"""Mass assignment — OWASP API3:2023 (docs/BUILD_SPEC.md §10).

Under safe mode — the default, and what every run ships with today — §10
says this is analysis-only against the specification, and that is exactly
what this probe does: it never sends a privileged field to see whether the
target accepts it.

That restraint is the point. Confirming mass assignment by *performing* it
means writing `is_admin: true` to a real record, and a tool that does that
to prove a point has caused the incident it was hired to find. The
specification already says whether the field is bindable, so the weakness is
reportable without touching anything — at design-review confidence, clearly
labelled, never dressed up as a confirmed exploit.
"""

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.api._support import surface_label, untested
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport

# Fields whose value is an authorization decision, a tenancy boundary, or
# money. If a client can set one of these, it is setting something the
# server was supposed to decide.
_PRIVILEGED_FIELDS = frozenset(
    {
        "account_type",
        "admin",
        "balance",
        "credit",
        "credits",
        "email_verified",
        "is_active",
        "is_admin",
        "is_staff",
        "is_superuser",
        "is_verified",
        "org_id",
        "organization_id",
        "owner_id",
        "permissions",
        "plan",
        "price",
        "role",
        "roles",
        "scope",
        "scopes",
        "tenant_id",
        "user_id",
        "verified",
    }
)

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _normalize(name: str) -> str:
    return name.strip().lower().replace("-", "_")


class MassAssignmentProbe:
    id = "api.mass_assignment.privileged_fields"
    version = "1.0.0"
    name = "Mass assignment of privileged fields"

    def applies_to(self, target: ProbeTarget) -> bool:
        return any(
            operation.method in _WRITE_METHODS and operation.body_fields
            for operation in target.operations
        )

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []

        for operation in target.operations:
            if operation.method not in _WRITE_METHODS or not operation.body_fields:
                continue
            results.extend(self._analyze(operation))

        if not target.safe_mode:
            # Being explicit beats silently behaving as though safe mode were
            # still on: the operator turned it off and deserves to know the
            # live confirmation step is not implemented rather than assume
            # these results were exercised against the target.
            results.append(
                untested(
                    probe_id=self.id,
                    probe_version=self.version,
                    endpoint=target.base_url,
                    what="Live confirmation of mass assignment",
                    reason=(
                        "Safe mode is off, but this probe still reports from the "
                        "specification only. Confirming acceptance requires writing a "
                        "privileged field to a real record, which is not implemented."
                    ),
                )
            )
        return results

    def _analyze(self, operation: DiscoveredOperation) -> list[ScanResult]:
        surface = surface_label(operation)
        results: list[ScanResult] = []

        bindable = sorted(
            field.name
            for field in operation.body_fields
            if _normalize(field.name) in _PRIVILEGED_FIELDS and not field.read_only
        )
        if bindable:
            results.append(
                ScanResult(
                    id="KERVY-API-030",
                    title="Request body binds privileged fields",
                    category=Category.API_SECURITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint=surface,
                    description=(
                        f"{surface} declares the writable field(s) "
                        f"{', '.join(bindable)} in its request body. These decide "
                        "privilege, tenancy or value, so a client that can set them is "
                        "making a decision the server should be making. This is read "
                        "from the specification — safe mode does not send a privileged "
                        "field to confirm it, because confirming it means performing it."
                    ),
                    evidence=(
                        f"Specification request body for {surface} declares writable "
                        f"field(s): {', '.join(bindable)}"
                    ),
                    impact=(
                        "If the handler binds the body straight onto its model, a caller "
                        "can grant itself a role, move a record between tenants, or set "
                        "its own balance."
                    ),
                    remediation=(
                        "Bind an explicit input schema listing only client-settable "
                        "fields, and set privilege, tenancy and value fields server-side "
                        "from the authenticated principal. Reject unknown fields rather "
                        "than ignoring them."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API3", "OWASP-API-2023:API6", "CWE-915"),
                    reproduction=(
                        f"Open the specification entry for {surface}.",
                        f"Observe that {', '.join(bindable)} are accepted in the request "
                        "body and are not marked readOnly.",
                        "Review the handler to see whether the body is bound wholesale "
                        "onto the persisted model.",
                    ),
                )
            )

        read_only_in_write = sorted(
            field.name for field in operation.body_fields if field.read_only
        )
        if read_only_in_write:
            results.append(
                ScanResult(
                    id="KERVY-API-031",
                    title="Write operation reuses a read schema",
                    category=Category.API_SECURITY,
                    severity=Severity.LOW,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint=surface,
                    description=(
                        f"{surface} accepts a body containing readOnly field(s) "
                        f"{', '.join(read_only_in_write)}, which means the same schema "
                        "is used for reading and writing. Whether those fields are "
                        "actually rejected then depends on the framework's validation "
                        "rather than on the design."
                    ),
                    evidence=(
                        f"Specification request body for {surface} includes readOnly "
                        f"field(s): {', '.join(read_only_in_write)}"
                    ),
                    impact=(
                        "A shared schema is how a field that was never meant to be "
                        "settable becomes settable after a refactor, with nothing in the "
                        "contract to catch it."
                    ),
                    remediation=(
                        "Split request and response schemas so a write body cannot name "
                        "a server-owned field at all."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API3", "CWE-915"),
                    reproduction=(
                        f"Open the specification entry for {surface}.",
                        f"Observe readOnly field(s) {', '.join(read_only_in_write)} "
                        "declared on the request body.",
                    ),
                )
            )
        return results
