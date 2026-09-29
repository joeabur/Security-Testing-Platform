"""Standalone secret scanning over a checkout (Addendum v2.1 §4.4).

The addendum promotes secret detection from "a detector used inside LLM02
and evidence redaction" to a scan surface of its own. It does **not** call
for a second detector stack, and building one would be actively harmful:
two implementations mean two redaction policies, and that is precisely how
the §13 "never persist a secret" invariant gets broken. So this engine
wraps `core/redaction/secrets.py` — the same patterns, digests and masking
the AI engine already uses — and adds the file-walking and the exposure
context around it.

Nothing detected here is stored in the clear. A finding carries
`sha256(secret)`, a masked preview and a line offset, which is enough to
identify what to rotate and not enough to use it.
"""

import hashlib
from pathlib import Path

from app.core.appsec.contract import EngineMeta, Pillar, code_evidence
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.redaction.secrets import SecretMatch, find_secrets

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 500

# Extensions whose contents are compiled, compressed or otherwise not text;
# scanning them produces entropy false positives and nothing else.
_SKIPPED_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".whl",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".pyc",
        ".woff",
        ".woff2",
        ".ttf",
    }
)

# Paths where a credential-shaped string is usually a fixture rather than a
# live secret. These are reported at lower severity rather than suppressed —
# a real key committed to a test file is still a real key.
_LIKELY_FIXTURE_PARTS = ("test", "tests", "fixture", "fixtures", "example", "examples", "sample")


class SecretScanEngine:
    meta = EngineMeta(
        id="appsec.secrets.repository",
        version="1.0.0",
        name="Secret detection (repository)",
        pillar=Pillar.SECRETS,
        tool="native (shared detector stack)",
        description="Scans in-scope files for committed credentials.",
    )

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(workspace.files)

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        findings: list[ScanResult] = []

        for path in workspace.files:
            if len(findings) >= MAX_FINDINGS:
                break
            if path.suffix.lower() in _SKIPPED_SUFFIXES:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            relative = str(path.relative_to(workspace.root))
            for match in find_secrets(text):
                findings.append(self._finding(match, relative, text))
                if len(findings) >= MAX_FINDINGS:
                    break
        return findings

    def _finding(self, match: SecretMatch, relative: str, text: str) -> ScanResult:
        line = text.count("\n", 0, match.offset) + 1
        fixture = any(part in _LIKELY_FIXTURE_PARTS for part in Path(relative).parts)

        return ScanResult(
            id=f"KERVY-SECRET-{match.kind.upper()}",
            title=f"Committed credential in {relative}",
            category=Category.INFRASTRUCTURE,
            # A credential in a test fixture is still a credential, so this
            # lowers the severity rather than dropping the finding.
            severity=Severity.MEDIUM if fixture else Severity.CRITICAL,
            confidence=Confidence.MEDIUM
            if match.kind == "high_entropy_string"
            else Confidence.HIGH,
            endpoint=f"{relative}:{line}",
            description=(
                f"A value matching the shape of a {match.kind.replace('_', ' ')} is "
                f"committed at {relative}:{line}."
                + (
                    " The path looks like test or example material, which lowers the "
                    "severity but does not clear it: a real credential committed to a "
                    "fixture is still exposed to everyone with repository access."
                    if fixture
                    else ""
                )
                + "\n\nThe value itself is not stored by this tool. What is recorded is "
                "a SHA-256 digest, a masked preview and the offset — enough to identify "
                "what to rotate, and not enough to use it."
            ),
            evidence=(
                f"file: {relative}\nline: {line}\nkind: {match.kind}\n"
                f"preview: {match.masked_preview}\ndigest: {match.sha256}\n"
                f"offset: {match.offset}, length: {match.length}"
            ),
            impact=(
                "Anyone with read access to this repository — including anyone who has "
                "cloned it historically — has this credential. Git history keeps it "
                "after the file is edited, so deleting the line is not remediation."
            ),
            remediation=(
                "Rotate the credential first; it must be treated as compromised. Then "
                "remove it from history, and replace it with a reference resolved at "
                "run time from a secret manager or the environment."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
            frameworks=("CWE-798", "CWE-540", "OWASP-ASVS:V2.10"),
            reproduction=(
                f"Open {relative} at line {line}.",
                f"Observe a value whose digest is {match.sha256}.",
            ),
            # Digest + path, never the value or the line number: the same
            # committed secret stays one finding as the file moves around it.
            fingerprint="sha256:"
            + hashlib.sha256(f"{match.sha256}|{relative}".encode()).hexdigest(),
            # The matched span goes through the same redaction as every other
            # bundle, so what is stored is the digest and the masked preview —
            # the one place where storing evidence verbatim would republish
            # the very thing the finding is about.
            evidence_bundle=code_evidence(
                self.meta,
                rule_id=match.kind,
                relative_path=relative,
                line=line,
                snippet=match.masked_preview,
                message=f"{match.kind} detected ({match.sha256})",
            ),
        )
