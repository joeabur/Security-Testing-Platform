"""Phase 5 acceptance: the API security engine finds every seeded flaw in
the lab and reports nothing against the hardened control
(docs/BUILD_SPEC.md §26, Phase 5).

Requests here go through the real `ScopeEngine` and the real
`GatedTransport`; only DNS and the socket are replaced. A probe that
somehow tried to reach outside the configured scope would be blocked in
these tests exactly as it would in production.
"""

import pytest
import respx

from app.core.discovery.openapi import parse_surface
from app.core.probes.api.registry import build_api_registry
from app.core.probes.credentials import (
    AuthorizationTestPlan,
    CredentialSet,
    SyntheticAccount,
)
from app.core.probes.models import ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from tests.lab.handlers import (
    ORDER_OWNED_BY_A,
    TOKEN_A,
    TOKEN_ADMIN,
    TOKEN_B,
    hardened_app,
    vulnerable_app,
)
from tests.lab.specs import hardened_spec, vulnerable_spec
from tests.security.conftest import FakeDnsResolver, make_budgets, make_context, make_roe

VULNERABLE_URL = "http://vulnerable.lab.test"
HARDENED_URL = "https://hardened.lab.test"

ACCOUNT_A = SyntheticAccount(
    label="account_a",
    credential_env_var="KERVY_LAB_TOKEN_A",
    owned_object_ids=(ORDER_OWNED_BY_A,),
)
ACCOUNT_B = SyntheticAccount(label="account_b", credential_env_var="KERVY_LAB_TOKEN_B")
ACCOUNT_ADMIN = SyntheticAccount(
    label="admin", credential_env_var="KERVY_LAB_TOKEN_ADMIN", is_privileged=True
)


def _plan() -> AuthorizationTestPlan:
    accounts = (ACCOUNT_A, ACCOUNT_B, ACCOUNT_ADMIN)
    return AuthorizationTestPlan(
        accounts=accounts,
        credentials=CredentialSet.from_environment(
            accounts,
            {
                "KERVY_LAB_TOKEN_A": TOKEN_A,
                "KERVY_LAB_TOKEN_B": TOKEN_B,
                "KERVY_LAB_TOKEN_ADMIN": TOKEN_ADMIN,
            },
        ),
    )


def _context(host: str) -> RunContext:
    return make_context(
        roe=make_roe(
            allowed_domains=(host,),
            allowed_methods=("GET", "POST"),
            # Generous enough that no probe is cut short mid-suite; the point
            # of these tests is coverage, not budget behaviour.
            budgets=make_budgets(max_requests=400),
        )
    )


def _transport(host: str) -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({host: ["203.0.113.10"]})
    )


async def _scan(*, base_url: str, spec: dict, app, safe_mode: bool = True) -> list[ScanResult]:
    host = base_url.split("//", 1)[1]
    surface = parse_surface(spec)
    target = ProbeTarget(
        base_url=base_url,
        operations=surface.operations,
        safe_mode=safe_mode,
        authorization=_plan(),
    )
    ctx = _context(host)
    results: list[ScanResult] = []

    with respx.mock(assert_all_called=False) as router:
        router.route(host=host).mock(side_effect=app)
        for probe in build_api_registry().applicable(target):
            results.extend(await probe.run(target, ctx, _transport(host)))
    return results


@pytest.fixture(scope="module")
async def vulnerable_results() -> list[ScanResult]:
    return await _scan(base_url=VULNERABLE_URL, spec=vulnerable_spec(), app=vulnerable_app)


@pytest.fixture(scope="module")
async def hardened_results() -> list[ScanResult]:
    return await _scan(base_url=HARDENED_URL, spec=hardened_spec(), app=hardened_app)


def _codes(results: list[ScanResult]) -> set[str]:
    return {result.id for result in results}


# Every flaw deliberately seeded into tests/lab/, with the result code the
# engine must report for it. A miss here is a false negative in the engine,
# which is the failure mode that matters most for a security tool.
SEEDED_FLAWS = {
    "KERVY-API-001": "authenticated endpoint answers without credentials",
    "KERVY-API-002": "API served over plaintext HTTP",
    "KERVY-API-003": "api_key accepted in the URL",
    "KERVY-API-010": "security response headers missing",
    "KERVY-API-011": "CORS reflects any origin with credentials",
    "KERVY-API-012": "verbose error exposes a traceback",
    "KERVY-API-013": "/.env reachable",
    "KERVY-API-020": "no rate limit advertised",
    "KERVY-API-021": "oversized page size accepted",
    "KERVY-API-030": "privileged fields bindable in the request body",
    "KERVY-API-031": "write operation reuses a read schema",
    "KERVY-API-040": "invalid input causes a server error",
    "KERVY-API-050": "object readable by an account that does not own it",
    "KERVY-API-051": "admin endpoint reachable by an unprivileged account",
    "KERVY-API-060": "GraphQL introspection enabled",
    "KERVY-API-061": "GraphQL query cost unlimited",
    "KERVY-API-062": "GraphQL errors expose internals",
}


@pytest.mark.parametrize("code", sorted(SEEDED_FLAWS))
async def test_every_seeded_flaw_is_found(code: str, vulnerable_results: list[ScanResult]) -> None:
    assert code in _codes(vulnerable_results), f"missed seeded flaw {code}: {SEEDED_FLAWS[code]}"


async def test_hardened_control_app_produces_no_findings(
    hardened_results: list[ScanResult],
) -> None:
    """Zero findings against a correctly built API.

    Informational results are excluded because that is exactly where the
    honest "this was not tested" markers live — they are not findings, and
    suppressing them to make this assertion pass would defeat their purpose.
    """
    reportable = [
        result for result in hardened_results if result.severity is not Severity.INFORMATIONAL
    ]
    assert reportable == [], [
        f"{result.id} {result.title} ({result.endpoint})" for result in reportable
    ]


async def test_no_probe_crashed_against_either_app(
    vulnerable_results: list[ScanResult], hardened_results: list[ScanResult]
) -> None:
    """KERVY-API-099 is the marker a probe leaves when it raised. Its absence
    is what makes the two assertions above mean something: a crashed probe
    would otherwise look identical to a probe that found nothing."""
    for results in (vulnerable_results, hardened_results):
        crashed = [result for result in results if result.id == "KERVY-API-099"]
        assert crashed == [], [result.evidence for result in crashed]


async def test_findings_carry_reproduction_steps_and_framework_mappings(
    vulnerable_results: list[ScanResult],
) -> None:
    """§27: every finding needs reproduction steps and a mapping."""
    for result in vulnerable_results:
        if result.severity is Severity.INFORMATIONAL:
            continue
        assert result.reproduction, f"{result.id} has no reproduction steps"
        assert result.frameworks, f"{result.id} has no framework mapping"
        assert result.remediation.strip(), f"{result.id} has no remediation"
        assert result.probe_id and result.probe_version


async def test_bola_finding_is_critical_and_names_both_accounts(
    vulnerable_results: list[ScanResult],
) -> None:
    bola = next(result for result in vulnerable_results if result.id == "KERVY-API-050")
    assert bola.severity is Severity.CRITICAL
    assert "account_a" in bola.evidence and "account_b" in bola.evidence


async def test_no_credential_value_ever_reaches_a_result(
    vulnerable_results: list[ScanResult], hardened_results: list[ScanResult]
) -> None:
    """The secrets the authorization probes use must not turn up in any
    field a report is built from (docs/BUILD_SPEC.md §2, §13)."""
    for result in vulnerable_results + hardened_results:
        blob = " ".join(
            [
                result.description,
                result.evidence,
                result.impact,
                result.remediation,
                result.title,
                *result.reproduction,
            ]
        )
        for secret in (TOKEN_A, TOKEN_B, TOKEN_ADMIN):
            assert secret not in blob, f"{result.id} leaked a credential"


# --- evidence (the Observation -> bundle pipeline the transport promised) --

# Findings that come from reading the specification rather than from an
# exchange. They carry no bundle by design, and naming them here means a new
# probe cannot quietly join the list.
_ANALYSIS_ONLY = {
    "KERVY-API-002",  # plaintext HTTP: read from the base URL, no request sent
    "KERVY-API-003",  # credentials declared as URL parameters
    "KERVY-API-030",  # mass assignment, analysis mode
    "KERVY-API-031",
}


async def test_every_finding_from_a_real_request_carries_its_exchange(
    vulnerable_results: list[ScanResult],
) -> None:
    for result in vulnerable_results:
        if result.severity is Severity.INFORMATIONAL or result.id in _ANALYSIS_ONLY:
            continue
        assert result.evidence_bundle is not None, result.id
        assert result.evidence_bundle.response["status_code"] is not None, result.id


async def test_specification_analysis_findings_do_not_claim_an_exchange(
    vulnerable_results: list[ScanResult],
) -> None:
    """A bundle asserts "this was observed". A finding read out of the spec
    was not observed, and an empty bundle for it would be a false claim in
    the evidence manifest."""
    analysis = [r for r in vulnerable_results if r.id in _ANALYSIS_ONLY]
    assert analysis
    assert all(r.evidence_bundle is None for r in analysis)


async def test_an_authorization_findings_evidence_withholds_the_other_partys_data(
    vulnerable_results: list[ScanResult],
) -> None:
    """BOLA proves account B reached account A's object. Storing that object
    would make the evidence bundle a copy of the records the probe only
    established were reachable — §10's "the decision, then stop"."""
    bola = next(r for r in vulnerable_results if r.id == "KERVY-API-050")
    assert bola.evidence_bundle is not None
    body = bola.evidence_bundle.response["body"]
    assert body.startswith("[NOT RETAINED]")
    # And the credential that made the request is masked, not recorded.
    assert TOKEN_B not in bola.evidence_bundle.canonical_bytes().decode()


async def test_a_verbose_error_findings_evidence_keeps_the_body(
    vulnerable_results: list[ScanResult],
) -> None:
    """The mirror image: here the body *is* the finding, so withholding it
    would leave the finding unsupported."""
    verbose = next(r for r in vulnerable_results if r.id == "KERVY-API-012")
    assert verbose.evidence_bundle is not None
    assert not verbose.evidence_bundle.response["body"].startswith("[NOT RETAINED]")
