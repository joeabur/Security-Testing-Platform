"""Shared helpers for the API probes.

Everything here funnels through `GatedTransport`, so a probe never has a way
to reach the network that the scope engine has not approved.
"""

from urllib.parse import quote, urljoin

from app.core.discovery.openapi import DiscoveredOperation
from app.core.evidence.bundle import EvidenceBundle
from app.core.evidence.observation import bundle_from_observation
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, Observation, ScopeBlockedError

# A path parameter has to be filled with *something* to make a request at
# all. This is a syntactically ordinary value that is not a plausible real
# object id, so a probe cannot accidentally act on another tenant's record
# just by walking the surface.
PLACEHOLDER_PATH_VALUE = "kervy-probe"

MAX_EVIDENCE_CHARS = 600


def surface_label(operation: DiscoveredOperation) -> str:
    return f"{operation.method} {operation.path}"


def fill_path(path: str, value: str = PLACEHOLDER_PATH_VALUE) -> str:
    """Substitute every `{param}` placeholder with one URL-encoded value."""
    out: list[str] = []
    depth = 0
    for char in path:
        if char == "{":
            depth += 1
            if depth == 1:
                out.append(quote(value, safe=""))
        elif char == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(char)
    return "".join(out)


def operation_url(base_url: str, operation: DiscoveredOperation, value: str | None = None) -> str:
    filled = fill_path(operation.path, value or PLACEHOLDER_PATH_VALUE)
    return urljoin(base_url if base_url.endswith("/") else base_url + "/", filled.lstrip("/"))


async def try_send(
    ctx: RunContext,
    transport: GatedTransport,
    *,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> Observation | None:
    """Send one request, returning `None` when it could not be made.

    A scope refusal and a dead socket both come back as `None` on purpose: in
    neither case did the probe observe the target's behaviour, and reporting
    "no finding" from a request that never happened would be a false
    negative dressed up as a pass. Callers that could not test anything say
    so with `untested()`.
    """
    try:
        return await transport.send(ctx, method=method, url=url, headers=headers, content=content)
    except ScopeBlockedError:
        return None
    except Exception:  # noqa: BLE001 - an unreachable target is not a probe crash
        return None


def body_text(observation: Observation) -> str:
    return observation.body.decode("utf-8", errors="replace")


def clip(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "… (truncated)"


def evidence_of(
    observation: Observation,
    *,
    probe_id: str,
    probe_version: str,
    verdict: str,
    request_headers: dict[str, str] | None = None,
    request_body: str = "",
    include_body: bool = False,
) -> EvidenceBundle:
    """The sealed bundle for an exchange a probe reported on.

    Thin by design: the conversion lives in `app.core.evidence.observation`
    so the DAST engine gets the same one, and the redaction lives in
    `build_bundle` so nothing here can weaken it.
    """
    return bundle_from_observation(
        observation,
        probe_id=probe_id,
        probe_version=probe_version,
        verdict=verdict,
        request_headers=request_headers,
        request_body=request_body,
        include_body=include_body,
    )


def untested(
    *, probe_id: str, probe_version: str, endpoint: str, reason: str, what: str
) -> ScanResult:
    """An explicit "this was not tested" result.

    docs/BUILD_SPEC.md §14 requires a report to state what it did not cover
    rather than letting silence imply a clean result.
    """
    return ScanResult(
        id="KERVY-API-000",
        title=f"Not tested: {what}",
        category=Category.API_SECURITY,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=endpoint,
        description=(
            f"{what} could not be tested against this target, so this run says "
            "nothing about it either way."
        ),
        evidence=reason,
        impact="Unknown — the check did not run, which is not the same as it passing.",
        remediation=(
            "Re-run with this surface in scope, or confirm by hand that the "
            "behaviour is covered elsewhere."
        ),
        probe_id=probe_id,
        probe_version=probe_version,
    )
