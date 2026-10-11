"""`JwtSignatureBypassProbe` (`api.auth.jwt_signature_bypass`, `KERVY-API-004`).

OWASP API2:2023 / CWE-347: does the target accept a JWT whose signature was
never checked? The probe forges three variants from a real token's own
*unverified* header and payload — it never has, and never needs, the
signing secret.
"""

from __future__ import annotations

import jwt
import respx
from httpx import Response

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.api.authentication import JwtSignatureBypassProbe
from app.core.probes.credentials import AuthorizationTestPlan, CredentialSet, SyntheticAccount
from app.core.probes.models import Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from tests.security.conftest import FakeDnsResolver, make_context

SECRET = "lab-signing-secret-at-least-32-bytes-long"  # pragma: allowlist secret
REAL_TOKEN = jwt.encode({"sub": "alice", "role": "user"}, SECRET, algorithm="HS256")
ACCOUNT = SyntheticAccount(label="account_a", credential_env_var="KERVY_TEST_JWT_TOKEN")

GET_PROFILE = DiscoveredOperation(method="GET", path="/profile", requires_auth=True)
POST_ORDERS = DiscoveredOperation(method="POST", path="/orders", requires_auth=True)


def _plan(token: str = REAL_TOKEN) -> AuthorizationTestPlan:
    return AuthorizationTestPlan(
        accounts=(ACCOUNT,),
        credentials=CredentialSet.from_environment((ACCOUNT,), {"KERVY_TEST_JWT_TOKEN": token}),
    )


def _target(
    *,
    token: str = REAL_TOKEN,
    operations: tuple[DiscoveredOperation, ...] = (GET_PROFILE,),
    safe_mode: bool = True,
) -> ProbeTarget:
    return ProbeTarget(
        base_url="https://ai.example.test",
        operations=operations,
        safe_mode=safe_mode,
        authorization=_plan(token),
    )


def _transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(),
        dns_resolver=FakeDnsResolver({"ai.example.test": ["203.0.113.5"]}),
    )


async def test_declines_with_no_usable_account() -> None:
    target = ProbeTarget(base_url="https://ai.example.test", operations=(GET_PROFILE,))

    results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-000"]
    assert "no authorized synthetic account" in results[0].evidence.lower()


async def test_declines_when_the_credential_is_not_jwt_shaped() -> None:
    target = _target(token="an-opaque-api-key-not-a-jwt")

    results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-000"]
    assert "not shaped like a JWT" in results[0].evidence


async def test_declines_when_the_token_cannot_be_decoded() -> None:
    # Three dot-separated segments (matches the shape check) but the first
    # two are not valid base64 JSON, so decoding itself fails.
    target = _target(token="not-base64.still-not-base64.signature")

    results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-000"]
    assert "could not be decoded" in results[0].evidence


async def test_declines_when_there_is_no_control_to_compare_against() -> None:
    """The real token itself is rejected — there is nothing to prove a
    forged one matched."""
    target = _target()

    with respx.mock(assert_all_called=False) as router:
        router.get("https://ai.example.test/profile").mock(return_value=Response(401))
        results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-000"]
    assert "no control" in results[0].evidence


async def test_reports_nothing_when_every_forged_variant_is_rejected() -> None:
    """A control succeeds, and the server correctly rejects every forgery —
    no finding, same as a hardened app should look."""
    target = _target()

    def _respond(request: object) -> Response:
        auth = request.headers.get("authorization", "")  # type: ignore[attr-defined]
        return Response(200) if auth == f"Bearer {REAL_TOKEN}" else Response(401)

    with respx.mock(assert_all_called=False) as router:
        router.get("https://ai.example.test/profile").mock(side_effect=_respond)
        results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert results == []


async def test_reports_a_bypass_when_a_forged_alg_none_token_is_accepted() -> None:
    target = _target()

    def _respond(request: object) -> Response:
        auth = request.headers.get("authorization", "")  # type: ignore[attr-defined]
        if auth == f"Bearer {REAL_TOKEN}":
            return Response(200)
        # Anything else with the right shape is "accepted" too — the
        # vulnerability under test.
        return Response(200) if auth.startswith("Bearer ") else Response(401)

    with respx.mock(assert_all_called=False) as router:
        router.get("https://ai.example.test/profile").mock(side_effect=_respond)
        results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-004"]
    finding = results[0]
    assert finding.severity is Severity.CRITICAL
    assert "OWASP-API-2023:API2" in finding.frameworks
    assert "CWE-347" in finding.frameworks
    assert finding.evidence_bundle is not None
    # The real signing secret never appears anywhere in the finding — the
    # probe never has it and never needs it.
    blob = " ".join(
        [
            finding.description,
            finding.evidence,
            finding.impact,
            finding.remediation,
            *finding.reproduction,
        ]
    )
    assert SECRET not in blob

    # One confirmed bypass is enough: only the first qualifying operation
    # was exercised, not every one.
    assert len([r for r in results if r.id == "KERVY-API-004"]) == 1


async def test_stops_after_the_first_confirmed_bypass() -> None:
    target = _target(
        operations=(
            GET_PROFILE,
            DiscoveredOperation(method="GET", path="/settings", requires_auth=True),
        )
    )
    calls: list[str] = []

    def _respond(request: object) -> Response:
        calls.append(str(request.url))  # type: ignore[attr-defined]
        return Response(200)

    with respx.mock(assert_all_called=False) as router:
        router.get("https://ai.example.test/profile").mock(side_effect=_respond)
        router.get("https://ai.example.test/settings").mock(side_effect=_respond)
        results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-004"]
    # /profile's control, then one forged variant that already succeeds —
    # /settings is never reached.
    assert all("/settings" not in call for call in calls)


async def test_safe_mode_skips_a_write_operation_and_reports_no_control() -> None:
    target = _target(operations=(POST_ORDERS,), safe_mode=True)

    with respx.mock(assert_all_called=False) as router:
        results = await JwtSignatureBypassProbe().run(target, make_context(), _transport())

    assert [result.id for result in results] == ["KERVY-API-000"]
    assert router.calls == []
