"""Unit tests for the probe contract, credentials and registry."""

import pytest
import respx
from httpx import Response

from app.core.discovery.openapi import DiscoveredOperation, parse_surface
from app.core.orchestrator.probe_check import ProbeCheck
from app.core.probes.api.mass_assignment import MassAssignmentProbe
from app.core.probes.api.registry import build_api_registry
from app.core.probes.credentials import (
    CredentialSet,
    CredentialUnavailableError,
    SyntheticAccount,
)
from app.core.probes.models import Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeRegistry, ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from tests.security.conftest import FakeDnsResolver, make_context, make_roe

ACCOUNT = SyntheticAccount(label="a", credential_env_var="KERVY_TEST_TOKEN")


def test_credentials_are_resolved_from_the_environment_not_stored() -> None:
    credentials = CredentialSet.from_environment((ACCOUNT,), {"KERVY_TEST_TOKEN": "s3cret"})

    assert credentials.has(ACCOUNT)
    assert credentials.headers_for(ACCOUNT) == {"Authorization": "Bearer s3cret"}
    # The account description itself never holds the secret, which is what
    # makes it safe to persist.
    assert "s3cret" not in repr(ACCOUNT)
    assert "s3cret" not in repr(credentials)


def test_an_unset_variable_makes_an_account_unusable_rather_than_failing() -> None:
    credentials = CredentialSet.from_environment((ACCOUNT,), {})

    assert credentials.has(ACCOUNT) is False
    with pytest.raises(CredentialUnavailableError):
        credentials.headers_for(ACCOUNT)


def test_registry_refuses_duplicate_probe_ids() -> None:
    registry = ProbeRegistry()
    registry.register(MassAssignmentProbe())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(MassAssignmentProbe())


def test_every_registered_probe_has_a_distinct_id_and_a_version() -> None:
    registry = build_api_registry()
    probes = registry.all()

    assert len({probe.id for probe in probes}) == len(probes)
    for probe in probes:
        assert probe.version, f"{probe.id} has no version"
        assert probe.name, f"{probe.id} has no name"


def test_probes_decline_cheaply_when_they_do_not_apply() -> None:
    """A target with no surface must not cause a single request."""
    empty = ProbeTarget(base_url="https://ai.example.test")
    applicable = {probe.id for probe in build_api_registry().applicable(empty)}

    # Transport security and debug-path discovery are the only two that can
    # say anything without a declared surface.
    assert applicable == {"api.auth.transport_security", "api.misconfig.debug_endpoints"}


def test_mass_assignment_stays_analysis_only_and_sends_nothing() -> None:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"is_admin": {"type": "boolean"}},
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "ok"}},
                }
            }
        },
    }
    surface = parse_surface(spec)
    target = ProbeTarget(base_url="https://ai.example.test", operations=surface.operations)
    return_value = None

    async def _run() -> list[ScanResult]:
        transport = GatedTransport(
            engine=ScopeEngine(),
            dns_resolver=FakeDnsResolver({"ai.example.test": ["203.0.113.5"]}),
        )
        return await MassAssignmentProbe().run(target, make_context(), transport)

    import asyncio

    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://ai.example.test/users").mock(return_value=Response(201))
        return_value = asyncio.run(_run())
        # The whole point: the weakness is reported without performing it.
        assert route.call_count == 0

    assert [result.id for result in return_value] == ["KERVY-API-030"]
    assert return_value[0].confidence is Confidence.DESIGN_REVIEW


class _ExplodingProbe:
    id = "test.explode"
    version = "9.9.9"
    name = "Exploding probe"

    def applies_to(self, target: ProbeTarget) -> bool:
        return True

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        raise RuntimeError("probe boom")


async def test_a_crashing_probe_is_a_visible_gap_not_a_silent_pass() -> None:
    registry = ProbeRegistry()
    registry.register(_ExplodingProbe())
    check = ProbeCheck(registry, ProbeTarget(base_url="https://ai.example.test"))

    results = await check.run(make_context(), GatedTransport())

    assert results[0].ok is False
    assert "probe boom" in results[0].detail
    # A gap is recorded as a result of its own, so a reader cannot mistake a
    # crashed probe for a clean one.
    assert [result.id for result in check.scan_results] == ["KERVY-API-099"]
    assert check.scan_results[0].severity is Severity.INFORMATIONAL


async def test_probe_check_stops_when_the_run_halts() -> None:
    registry = build_api_registry()
    target = ProbeTarget(
        base_url="https://ai.example.test",
        operations=(DiscoveredOperation(method="GET", path="/a", requires_auth=True),),
    )
    ctx = make_context(roe=make_roe())
    ctx.kill_switch.trip()

    results = await ProbeCheck(registry, target).run(ctx, GatedTransport())

    assert results == []


_BOUNDED_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "t", "version": "1"},
    "paths": {
        "/items": {
            "post": {
                "security": [],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "maxLength": 5},
                                    "quantity": {"type": "integer", "maximum": 10},
                                    "discount": {"type": "integer", "minimum": 0},
                                    "status": {"type": "string", "enum": ["new", "done"]},
                                    "count": {"type": "integer"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def _bounded_target(safe_mode: bool) -> ProbeTarget:
    return ProbeTarget(
        base_url="https://ai.example.test",
        operations=parse_surface(_BOUNDED_SPEC).operations,
        safe_mode=safe_mode,
    )


def _lab_transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(),
        dns_resolver=FakeDnsResolver({"ai.example.test": ["203.0.113.5"]}),
    )


async def test_input_validation_generates_cases_from_the_declared_schema() -> None:
    """Each case exists because the contract declared a bound to violate —
    a maxLength, a maximum, a minimum, an enum, a type. An API with no
    declared constraints yields no cases, which is the difference between
    this and replaying a generic payload list."""
    from app.core.probes.api.input_validation import InputValidationProbe

    sent: list[bytes] = []

    def _record(request: object) -> Response:
        sent.append(getattr(request, "content", b""))
        return Response(400)

    with respx.mock(assert_all_called=False) as router:
        router.post("https://ai.example.test/items").mock(side_effect=_record)
        results = await InputValidationProbe().run(
            _bounded_target(safe_mode=False), make_context(), _lab_transport()
        )

    bodies = [body.decode() for body in sent]
    # The malformed-JSON case plus schema-derived cases, capped per operation.
    assert any("kervy" in body and not body.endswith("}") for body in bodies)
    assert any('"name": "aaaaaa"' in body for body in bodies)
    # Every case was correctly rejected, so nothing is reported.
    assert results == []


async def test_input_validation_reports_a_server_error_as_a_finding() -> None:
    from app.core.probes.api.input_validation import InputValidationProbe

    with respx.mock(assert_all_called=False) as router:
        router.post("https://ai.example.test/items").mock(
            return_value=Response(500, text="Traceback (most recent call last):")
        )
        results = await InputValidationProbe().run(
            _bounded_target(safe_mode=False), make_context(), _lab_transport()
        )

    assert results
    assert {result.id for result in results} == {"KERVY-API-040"}
    assert all(result.severity is Severity.MEDIUM for result in results)


async def test_input_validation_reports_accepted_invalid_input() -> None:
    from app.core.probes.api.input_validation import InputValidationProbe

    with respx.mock(assert_all_called=False) as router:
        router.post("https://ai.example.test/items").mock(return_value=Response(200))
        results = await InputValidationProbe().run(
            _bounded_target(safe_mode=False), make_context(), _lab_transport()
        )

    assert {result.id for result in results} == {"KERVY-API-041"}


async def test_safe_mode_does_not_send_write_requests() -> None:
    """Safe mode is the default, and a write that the API wrongly accepts
    would have changed state to tell us so."""
    from app.core.probes.api.input_validation import InputValidationProbe

    with respx.mock(assert_all_called=False) as router:
        route = router.post("https://ai.example.test/items").mock(return_value=Response(200))
        results = await InputValidationProbe().run(
            _bounded_target(safe_mode=True), make_context(), _lab_transport()
        )

    assert route.call_count == 0
    assert results == []
