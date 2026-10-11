"""The API security engine's probe set (docs/BUILD_SPEC.md §10, §26 Phase 5).

Registration is explicit and in one place so that "what does a run actually
do?" is answerable by reading a single list, and so a probe cannot end up
in a run just by existing in the package.
"""

from app.core.probes.api.authentication import (
    JwtSignatureBypassProbe,
    KeyMaterialInUrlProbe,
    TransportSecurityProbe,
    UnauthenticatedAccessProbe,
)
from app.core.probes.api.authorization import (
    BrokenFunctionLevelAuthorizationProbe,
    BrokenObjectLevelAuthorizationProbe,
)
from app.core.probes.api.graphql import (
    GraphQLErrorVerbosityProbe,
    GraphQLIntrospectionProbe,
    GraphQLQueryCostProbe,
)
from app.core.probes.api.input_validation import InputValidationProbe
from app.core.probes.api.mass_assignment import MassAssignmentProbe
from app.core.probes.api.misconfiguration import (
    CorsPolicyProbe,
    DebugEndpointProbe,
    SecurityHeadersProbe,
    VerboseErrorProbe,
)
from app.core.probes.api.resource_consumption import (
    PaginationLimitProbe,
    RateLimitPresenceProbe,
)
from app.core.probes.protocol import Probe, ProbeRegistry


def api_probes() -> list[Probe]:
    return [
        UnauthenticatedAccessProbe(),
        TransportSecurityProbe(),
        KeyMaterialInUrlProbe(),
        JwtSignatureBypassProbe(),
        BrokenObjectLevelAuthorizationProbe(),
        BrokenFunctionLevelAuthorizationProbe(),
        MassAssignmentProbe(),
        InputValidationProbe(),
        SecurityHeadersProbe(),
        CorsPolicyProbe(),
        VerboseErrorProbe(),
        DebugEndpointProbe(),
        RateLimitPresenceProbe(),
        PaginationLimitProbe(),
        GraphQLIntrospectionProbe(),
        GraphQLQueryCostProbe(),
        GraphQLErrorVerbosityProbe(),
    ]


def build_api_registry() -> ProbeRegistry:
    registry = ProbeRegistry()
    for probe in api_probes():
        registry.register(probe)
    return registry
