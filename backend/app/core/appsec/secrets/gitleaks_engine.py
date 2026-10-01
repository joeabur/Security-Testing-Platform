"""Gitleaks adapter — committed secrets, including in history
(docs/BUILD_SPEC.md §23, §26 Phase 11).

Why a second secrets engine alongside `SecretScanEngine`? They answer different
questions, and the difference matters:

* the built-in engine reads the **working tree**, which is what an operator
  can fix today;
* gitleaks reads the **git history**, which is where a credential removed in a
  later commit still sits — and a secret that was ever pushed has to be
  treated as compromised whether or not HEAD still contains it.

Reporting both is not duplication. A finding only gitleaks sees is the one an
operator most needs, because it is invisible to every other check.

**Never the value.** Gitleaks prints the matched secret in its JSON report.
This adapter keeps the rule id, the file, the line and the commit, and hashes
the match — the same discipline the built-in engine follows, for the same
reason: a findings table that stores credentials is a credential store nobody
secured.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from app.core.appsec.contract import (
    EngineMeta,
    Pillar,
    code_evidence,
    relative_to_workspace,
    tool_unavailable,
)
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

GITLEAKS_TIMEOUT_SECONDS = 420

# Rules whose matches are structurally weaker evidence: a generic high-entropy
# hit is often a test fixture or a checksum. Reported, and reported lower,
# because suppressing them would hide the one that is real.
_GENERIC_RULES = frozenset({"generic-api-key", "high-entropy-base64", "generic-credential"})


class GitleaksEngine:
    meta = EngineMeta(
        id="appsec.secrets.gitleaks",
        version="1.0.0",
        name="Gitleaks (committed secrets, including history)",
        pillar=Pillar.SECRETS,
        tool="gitleaks",
        description=(
            "Scans the git history for committed credentials. Complements the "
            "working-tree scan: a secret removed in a later commit is still in the "
            "history, and a secret that was ever pushed is compromised."
        ),
    )

    def applies_to(self, workspace: Workspace) -> bool:
        # Only where there is history to read. Against a plain directory
        # gitleaks would add nothing the working-tree engine does not already
        # cover, and spending a subprocess to learn that is waste.
        return (workspace.root / ".git").exists()

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        report = workspace.root / ".kervy-gitleaks.json"
        try:
            result = await run_tool(
                ToolInvocation(
                    command=(
                        "gitleaks",
                        "detect",
                        "--source",
                        ".",
                        "--report-format",
                        "json",
                        "--report-path",
                        report.name,
                        "--redact",  # keep the value out of the report at the source
                        "--no-banner",
                        "--exit-code",
                        "0",  # findings are this engine's output, not a failure
                    ),
                    cwd=workspace.root,
                    network=NetworkUse.OFFLINE,
                    timeout_seconds=GITLEAKS_TIMEOUT_SECONDS,
                )
            )
            if not result.ran:
                return [tool_unavailable(self.meta, result.reason)]
            if result.failed:
                return [
                    tool_unavailable(
                        self.meta,
                        f"gitleaks exited {result.exit_code}: {result.stderr[:400]}",
                    )
                ]

            try:
                raw = report.read_text(encoding="utf-8") if report.exists() else "[]"
            except OSError as exc:
                return [tool_unavailable(self.meta, f"could not read the report: {exc}")]

            try:
                payload = json.loads(raw or "[]")
            except ValueError as exc:
                return [tool_unavailable(self.meta, f"gitleaks output was not JSON: {exc}")]

            return self.parse(payload, workspace)
        finally:
            # The report sits inside the checkout and contains, at minimum, the
            # locations of every credential found. It goes even though the
            # checkout is discarded later, because "later" is not a guarantee.
            report.unlink(missing_ok=True)

    def parse(self, payload: Any, workspace: Workspace) -> list[ScanResult]:
        if not isinstance(payload, list):
            return []
        findings: list[ScanResult] = []
        for item in payload:
            if isinstance(item, dict):
                normalized = self._normalize(item, workspace)
                if normalized is not None:
                    findings.append(normalized)
        return findings

    def _normalize(self, item: dict[str, Any], workspace: Workspace) -> ScanResult | None:
        rule_id = str(item.get("RuleID") or "").strip()
        # No rule id, no finding: it could not be fingerprinted stably or traced
        # to an upstream rule, and inventing one would be worse.
        if not rule_id:
            return None

        relative = relative_to_workspace(str(item.get("File") or ""), workspace)
        if relative is None:
            return None

        line = _int_or_none(item.get("StartLine"))
        commit = str(item.get("Commit") or "").strip()
        author = str(item.get("Author") or "").strip()
        date = str(item.get("Date") or "").strip()
        generic = rule_id in _GENERIC_RULES

        # `--redact` already replaced the value, but this adapter does not rely
        # on a flag staying set in a future gitleaks release. Whatever arrived
        # is hashed, and only the digest is kept.
        digest = _digest(str(item.get("Secret") or item.get("Match") or ""))
        in_history = bool(commit) and commit != _WORKING_TREE

        return ScanResult(
            id=f"KERVY-SECRET-GL-{rule_id.upper()[:40]}",
            title=f"Committed credential: {item.get('Description') or rule_id}"[:300],
            category=Category.INFRASTRUCTURE,
            severity=Severity.MEDIUM if generic else Severity.CRITICAL,
            confidence=Confidence.MEDIUM if generic else Confidence.HIGH,
            endpoint=f"{relative}:{line}" if line else relative,
            description=(
                f"gitleaks rule {rule_id} matched at {relative}"
                + (f":{line}" if line else "")
                + (
                    f" in commit {commit[:12]}"
                    + (f" by {author}" if author else "")
                    + (f" on {date}" if date else "")
                    + ". The value is in the repository's history, so removing it from "
                    "the current files does not remove it."
                    if in_history
                    else ". The value is present in the working tree."
                )
                + (
                    "\n\nThis rule matches on shape rather than on a known issuer, so "
                    "it fires on test fixtures and checksums as well as on real "
                    "credentials. Reported at a lower severity rather than suppressed."
                    if generic
                    else ""
                )
            ),
            evidence=(
                f"rule={rule_id} file={relative}"
                + (f" line={line}" if line else "")
                + (f" commit={commit}" if commit else "")
                + f" sha256={digest}"
            ),
            impact=(
                "A credential in a git history is available to everyone who can clone "
                "the repository, and to anyone who ever could. Rotation is the only "
                "remedy; deleting the line is not."
            ),
            remediation=(
                "Rotate the credential first — assume it is compromised. Then remove it "
                "from the history (git filter-repo or a fresh repository) and move the "
                "value into a secret manager referenced by environment variable."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
            frameworks=("CWE-798", "CWE-540", "OWASP-ASVS:V13.3.1"),
            reproduction=(
                "Run: gitleaks detect --source . --redact",
                f"Observe rule {rule_id} at {relative}"
                + (f":{line}" if line else "")
                + (f" in commit {commit[:12]}" if in_history else ""),
            ),
            # Digest + rule + path, never the value or the line number: the same
            # committed secret stays one finding as the file moves around it.
            fingerprint="sha256:"
            + hashlib.sha256(f"{rule_id}|{relative}|{digest}".encode()).hexdigest(),
            evidence_bundle=code_evidence(
                self.meta,
                rule_id=rule_id,
                relative_path=relative,
                line=line,
                # The digest, not the match. `code_evidence` redacts too, but
                # the value must not be handed to it in the first place.
                snippet=f"[REDACTED] sha256={digest}",
                message=f"{rule_id} matched" + (f" in commit {commit[:12]}" if in_history else ""),
            ),
        )


# Gitleaks reports an empty commit for a finding in the working tree rather
# than in a commit.
_WORKING_TREE = ""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def report_path(workspace: Workspace) -> Path:
    """Exposed for the tests, which assert the report never survives a run."""
    return workspace.root / ".kervy-gitleaks.json"
