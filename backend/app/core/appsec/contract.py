"""The AppSec engine contract (docs/BUILD_SPEC.md §26 Phase 14).

An engine reads files from a resolved `Workspace` and emits the same
`ScanResult` wire shape every other engine on this platform emits. It does
not invent identifiers, does not reach the network except as declared, and
reports plainly when its tool is absent rather than returning nothing and
letting silence read as a clean result.
"""

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import unquote, urlsplit

from app.core.appsec.workspace import Workspace
from app.core.evidence.bundle import EvidenceBundle, build_bundle
from app.core.probes.models import Category, Confidence, ScanResult, Severity


class Pillar(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    # Added in Phase 15. A DAST engine tests a running application rather than
    # a checkout, so it does not take a `Workspace` — but it produces the same
    # `ScanResult` shape and the same "not tested" marker, which is the part
    # that matters for one report and one normalization path.
    DAST = "dast"


@dataclass(frozen=True)
class EngineMeta:
    id: str
    version: str
    name: str
    pillar: Pillar
    tool: str
    description: str


@runtime_checkable
class AppSecEngine(Protocol):
    meta: EngineMeta

    def applies_to(self, workspace: Workspace) -> bool: ...

    async def run(self, workspace: Workspace) -> list[ScanResult]: ...


# Whitespace and quoting change constantly and mean nothing to a
# fingerprint; what identifies a piece of code is its token shape.
_NORMALIZE = re.compile(r"\s+")


def code_span_signature(snippet: str) -> str:
    """A stable signature for a span of code.

    Deliberately not the line number. §4.1 of the addendum is explicit about
    why: line numbers drift on unrelated edits, so fingerprinting on them
    would split one long-lived issue into a new finding on every commit that
    touched the file above it, and the §11 fingerprint-stability guarantee
    would be worthless.
    """
    normalized = _NORMALIZE.sub(" ", snippet.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def finding_fingerprint(*, rule_id: str, relative_path: str, snippet: str) -> str:
    """rule id + normalized path + code-span signature (Addendum §4.1)."""
    material = f"{rule_id}|{relative_path}|{code_span_signature(snippet)}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def relative_to_workspace(raw: str, workspace: Workspace) -> str | None:
    """A workspace-relative path, or `None` if it is not in the workspace.

    Every engine needs this and the naive version is wrong in a way that
    matters. `uri.lstrip("./")` — which the semgrep engine used until a lab
    audit caught it — strips *characters*, not a prefix: it turns
    `./src/app.py` into `src/app.py` as intended, but it also turns
    `/home/runner/checkout-a1b2/src/app.py` into
    `home/runner/checkout-a1b2/src/app.py`. That is worse than cosmetic. The
    path is part of the §11 fingerprint, and a checkout directory is unique
    per run, so every finding would get a new identity on every scan: no
    dedup, no history, no "is this still there?". It also puts the worker's
    filesystem layout into a customer-facing report.

    Anything that resolves outside the workspace is dropped rather than
    reported with a trimmed path, on the same principle as the rest of the
    scope engine: a result about a file the operator did not put in scope is
    not a result this platform reports.
    """
    text = raw.strip()
    if not text:
        return None
    if text.startswith("file://"):
        text = unquote(urlsplit(text).path)
    candidate = Path(text)
    try:
        resolved = candidate if candidate.is_absolute() else (workspace.root / candidate)
        return str(resolved.resolve().relative_to(workspace.root))
    except (ValueError, OSError):
        return None


def code_evidence(
    meta: EngineMeta,
    *,
    rule_id: str,
    relative_path: str,
    line: int | None,
    snippet: str,
    message: str,
) -> EvidenceBundle:
    """The sealed bundle behind a static finding (docs/BUILD_SPEC.md §13).

    A static finding's "exchange" is a tool reading a file, so the bundle
    records that shape: the tool and rule that ran as the request, the code
    span it matched as the response. That is what makes a retest comparable —
    "the same rule at the same path now matches nothing" is a claim someone
    can check, where a prose line of evidence is not.

    The snippet goes through `build_bundle` like everything else, which
    matters most for the secrets engine: the span that matched a credential
    is stored as a digest and a masked preview, never as the value.
    """
    location = f"{relative_path}:{line}" if line else relative_path
    return build_bundle(
        probe_id=meta.id,
        probe_version=meta.version,
        # Not an HTTP request, and it does not pretend to be: `SCAN` plus a
        # file URL says what actually happened, where a fabricated GET and a
        # 200 would invite a reader to think a server answered.
        method="SCAN",
        url=f"file:///{relative_path}" + (f"#L{line}" if line else ""),
        request_body=f"{meta.tool} rule {rule_id} against {location}",
        status_code=None,
        response_body=snippet,
        adapter={"tool": meta.tool, "pillar": meta.pillar.value, "rule_id": rule_id},
        detector_verdict=f"{meta.tool} {rule_id}: {message}"[:1000],
    )


def tool_unavailable(meta: EngineMeta, reason: str) -> ScanResult:
    """The result an engine emits when its tool could not run.

    §15 requires graceful degradation, and §14 requires a report to state
    what it did not cover. Those combine to this: a missing scanner produces
    a visible gap, never an empty result set that reads as "nothing found".
    """
    return ScanResult(
        id="KERVY-APPSEC-000",
        title=f"Not tested: {meta.name}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=meta.pillar.value,
        description=(
            f"The {meta.pillar.value.upper()} engine did not run, so this assessment "
            f"says nothing about what {meta.tool} would have found."
        ),
        evidence=reason,
        impact="Unknown — the scan did not run, which is not the same as it passing.",
        remediation=(
            f"Install {meta.tool} on the worker and re-run, or record this pillar as "
            "out of scope for the engagement."
        ),
        probe_id=meta.id,
        probe_version=meta.version,
    )


def severity_from(label: str, default: Severity = Severity.MEDIUM) -> Severity:
    """Map a tool's own severity word onto ours, conservatively.

    An unrecognised label becomes the default rather than the lowest
    severity: a finding whose severity we could not read is not evidence
    that it is unimportant.
    """
    normalized = label.strip().upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "ERROR": Severity.HIGH,
        "HIGH": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "MODERATE": Severity.MEDIUM,
        "NOTE": Severity.LOW,
        "LOW": Severity.LOW,
        "INFO": Severity.INFORMATIONAL,
        "INFORMATIONAL": Severity.INFORMATIONAL,
        "UNKNOWN": default,
    }.get(normalized, default)
