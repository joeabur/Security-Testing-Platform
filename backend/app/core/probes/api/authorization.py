"""Authorization — OWASP API1:2023 (BOLA) and API5:2023 (function level).

§10 calls this the highest-value area, and it is also the one where a
careless tool does real harm. Three constraints keep it safe:

* **Only authorized synthetic accounts.** Every request carries a credential
  the operator deliberately configured for testing. The probe never
  enumerates identifiers hoping to land on a stranger's record.
* **Only real object ids the operator declared.** A BOLA test asks about an
  object that is known to exist and known to belong to the test account that
  declared it.
* **The decision, then stop.** A 2xx answer is the entire finding. The probe
  does not read the object, keep the body, or act on it further, because
  what is being established is whether access was granted — not what was
  behind it.

Every test is paired with a control: the owning account is asked for its own
object first. Without that, a 404 to the other account would be reported as
"correctly denied" when the object may simply not exist, and a 200 to
everyone would be reported as BOLA when the endpoint returns the same thing
to everyone anyway.
"""

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.api._support import (
    clip,
    evidence_of,
    operation_url,
    surface_label,
    try_send,
    untested,
)
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport

_PRIVILEGED_PATH_SEGMENTS = frozenset({"admin", "administration", "internal", "manage", "root"})
_SAFE_METHODS = frozenset({"GET", "HEAD"})


def _is_privileged_surface(operation: DiscoveredOperation) -> bool:
    segments = {segment.strip().lower() for segment in operation.path.split("/") if segment}
    if segments & _PRIVILEGED_PATH_SEGMENTS:
        return True
    haystack = f"{operation.operation_id or ''} {operation.summary or ''}".lower()
    return "admin" in haystack


def _single_path_parameter_operations(
    target: ProbeTarget,
) -> list[DiscoveredOperation]:
    return [
        operation
        for operation in target.operations
        if operation.method in _SAFE_METHODS and operation.path.count("{") == 1
    ]


class BrokenObjectLevelAuthorizationProbe:
    id = "api.authz.bola"
    version = "1.0.0"
    name = "Broken object level authorization"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(_single_path_parameter_operations(target))

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        plan = target.authorization
        usable = plan.usable()
        owners = [account for account in usable if account.owned_object_ids]

        if len(usable) < 2 or not owners:
            return [
                untested(
                    probe_id=self.id,
                    probe_version=self.version,
                    endpoint=target.base_url,
                    what="Broken object level authorization (BOLA)",
                    reason=(
                        "BOLA testing needs two authorized synthetic accounts, at least "
                        "one of them declaring an object id it owns, with both "
                        "credentials resolvable from the worker's environment. "
                        f"Resolved {len(usable)} account(s), {len(owners)} with object ids."
                    ),
                )
            ]

        owner = owners[0]
        other = next(account for account in usable if account.label != owner.label)
        object_id = owner.owned_object_ids[0]
        results: list[ScanResult] = []

        for operation in _single_path_parameter_operations(target):
            if ctx.halted:
                break
            url = operation_url(target.base_url, operation, value=object_id)

            control = await try_send(
                ctx,
                transport,
                method=operation.method,
                url=url,
                headers=plan.credentials.headers_for(owner),
            )
            # No control, no conclusion: if the owner cannot read its own
            # object here, this operation tells us nothing about authorization.
            if control is None or not 200 <= control.status_code < 300:
                continue

            attempt = await try_send(
                ctx,
                transport,
                method=operation.method,
                url=url,
                headers=plan.credentials.headers_for(other),
            )
            if attempt is None or not 200 <= attempt.status_code < 300:
                continue

            surface = surface_label(operation)
            results.append(
                ScanResult(
                    id="KERVY-API-050",
                    title="Object is readable by an account that does not own it",
                    category=Category.API_SECURITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    endpoint=surface,
                    description=(
                        f"{surface} returned success to test account "
                        f"'{other.label}' for an object owned by test account "
                        f"'{owner.label}'. The endpoint authenticates the caller but "
                        "does not check whether that caller is entitled to this "
                        "particular object."
                    ),
                    evidence=clip(
                        f"Control: {operation.method} {url} as '{owner.label}' (owner) "
                        f"-> HTTP {control.status_code}\n"
                        f"Test:    {operation.method} {url} as '{other.label}' (not owner) "
                        f"-> HTTP {attempt.status_code}\n"
                        "Response bodies were not read or retained beyond their size."
                    ),
                    impact=(
                        "Any authenticated user can read any object of this type by "
                        "changing the identifier in the URL. Where the identifiers are "
                        "sequential or guessable, that is the whole dataset."
                    ),
                    remediation=(
                        "Check ownership on every object load, in the query that fetches "
                        "it rather than in a separate branch afterwards, so an endpoint "
                        "added later cannot skip the check."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API1", "CWE-639", "CWE-285"),
                    reproduction=(
                        f"As test account '{owner.label}', send {operation.method} {url} "
                        f"and observe HTTP {control.status_code}.",
                        f"Repeat as test account '{other.label}', which does not own the "
                        f"object, and observe HTTP {attempt.status_code} instead of 403 "
                        "or 404.",
                    ),
                    # The unauthorized success is the finding. No body: that
                    # body is the other account's data, and the probe's whole
                    # point is that it should not have been readable.
                    evidence_bundle=evidence_of(
                        attempt,
                        probe_id=self.id,
                        probe_version=self.version,
                        request_headers=plan.credentials.headers_for(other),
                        verdict=(
                            f"HTTP {attempt.status_code} as non-owner '{other.label}'; "
                            f"owner control returned HTTP {control.status_code}"
                        ),
                    ),
                )
            )
        return results


class BrokenFunctionLevelAuthorizationProbe:
    id = "api.authz.function_level"
    version = "1.0.0"
    name = "Broken function level authorization"

    def applies_to(self, target: ProbeTarget) -> bool:
        return any(_is_privileged_surface(op) for op in target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        plan = target.authorization
        unprivileged = [account for account in plan.usable() if not account.is_privileged]
        privileged = [account for account in plan.usable() if account.is_privileged]

        if not unprivileged:
            return [
                untested(
                    probe_id=self.id,
                    probe_version=self.version,
                    endpoint=target.base_url,
                    what="Broken function level authorization",
                    reason=(
                        "Testing vertical escalation needs an authorized synthetic "
                        "account marked as unprivileged, with its credential resolvable "
                        "from the worker's environment. None was available."
                    ),
                )
            ]

        account = unprivileged[0]
        results: list[ScanResult] = []

        for operation in target.operations:
            if ctx.halted:
                break
            if operation.method not in _SAFE_METHODS or not _is_privileged_surface(operation):
                continue

            url = operation_url(target.base_url, operation)
            attempt = await try_send(
                ctx,
                transport,
                method=operation.method,
                url=url,
                headers=plan.credentials.headers_for(account),
            )
            if attempt is None or not 200 <= attempt.status_code < 300:
                continue

            # A privileged control raises confidence from "this looks like an
            # administrative route by its name" to "this route works for an
            # admin and also for someone who is not one".
            control_note = "no privileged account was configured to confirm the contrast"
            confidence = Confidence.MEDIUM
            if privileged:
                control = await try_send(
                    ctx,
                    transport,
                    method=operation.method,
                    url=url,
                    headers=plan.credentials.headers_for(privileged[0]),
                )
                if control is not None and 200 <= control.status_code < 300:
                    confidence = Confidence.HIGH
                    control_note = (
                        f"privileged account '{privileged[0].label}' -> HTTP {control.status_code}"
                    )

            surface = surface_label(operation)
            results.append(
                ScanResult(
                    id="KERVY-API-051",
                    title="Administrative endpoint is reachable by an unprivileged account",
                    category=Category.API_SECURITY,
                    severity=Severity.HIGH,
                    confidence=confidence,
                    endpoint=surface,
                    description=(
                        f"{surface} returned success to test account '{account.label}', "
                        "which is configured as unprivileged. The route is "
                        "administrative by its path or description, so answering a "
                        "non-administrative caller is vertical privilege escalation."
                    ),
                    evidence=clip(
                        f"{operation.method} {url} as unprivileged '{account.label}' "
                        f"-> HTTP {attempt.status_code}\n{control_note}"
                    ),
                    impact=(
                        "Administrative functionality is available to ordinary users, "
                        "which usually means the whole tenant's data or configuration is "
                        "too."
                    ),
                    remediation=(
                        "Enforce the required role in middleware that covers the whole "
                        "administrative route group and denies by default, rather than "
                        "per handler."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API5", "CWE-285", "CWE-862"),
                    reproduction=(
                        f"As unprivileged test account '{account.label}', send "
                        f"{operation.method} {url}.",
                        f"Observe HTTP {attempt.status_code} rather than 403.",
                    ),
                    # As above: the decision is the evidence, not the
                    # administrative data behind it.
                    evidence_bundle=evidence_of(
                        attempt,
                        probe_id=self.id,
                        probe_version=self.version,
                        request_headers=plan.credentials.headers_for(account),
                        verdict=(
                            f"HTTP {attempt.status_code} as unprivileged "
                            f"'{account.label}'; {control_note}"
                        ),
                    ),
                )
            )
        return results
