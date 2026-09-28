"""The assistant API: drafts, acceptance, and what it refuses.

Uses the deterministic fake provider throughout — no test run spends tokens
or depends on a provider being reachable (Implementation Specification §20).
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import respx
from httpx import AsyncClient, Response

from app.api.v1.routers.assistant import get_ai_service
from app.core.assistant.autonomy import AutonomyMode
from app.core.assistant.fake import FakeProvider
from app.core.assistant.service import AIService
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.workers.tasks import execute_assessment_run
from tests.lab.ai_handlers import vulnerable_chat
from tests.security.conftest import FakeDnsResolver

LAB_HOST = "vulnerable-ai.lab.test"
LAB_URL = f"https://{LAB_HOST}"


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture(autouse=True)
def _assistant(client: AsyncClient, provider: FakeProvider) -> None:
    """Inject a deterministic provider into the app under test."""
    from app.main import create_app  # noqa: F401  (app already built by `client`)

    client._transport.app.dependency_overrides[get_ai_service] = lambda: AIService(  # type: ignore[attr-defined]
        provider, mode=AutonomyMode.RECOMMEND
    )


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "stub-task-id"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


def _worker_transport():
    from app.core.scope.engine import ScopeEngine
    from app.core.scope.transport import GatedTransport

    return GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({LAB_HOST: ["203.0.113.20"]})
    )


async def _run_with_findings(
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"aiowner{suffix}@example.test",
            "full_name": "AI Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"AI Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Lab assistant",
                "environment": "test",
                "kind": "llm_app",
                "base_url": LAB_URL,
            },
            headers=headers,
        )
    ).json()["id"]

    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    now = datetime.now(UTC)
    await client.put(
        f"{base}/rules-of-engagement",
        json={
            "allowed_domains": [LAB_HOST],
            "excluded_domains": [],
            "allowed_ip_ranges": [],
            "allowed_paths": [],
            "excluded_paths": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_headers": [],
            "budgets": {
                "max_requests": 400,
                "max_concurrency": 2,
                "requests_per_second": 50.0,
                "max_tokens_sent": 100000,
                "max_tokens_received": 100000,
                "max_estimated_cost_usd": 5.0,
                "max_wall_clock_minutes": 30,
            },
            "safe_mode": True,
        },
        headers=headers,
    )
    await client.post(
        f"{base}/authorization",
        json={
            "authorized_by_name": "AI Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "AI-1",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=6)).isoformat(),
        },
        headers=headers,
    )
    await client.put(
        f"{base}/adapter",
        json={"adapter_kind": "chat_http", "adapter_config": {"endpoint": "/api/chat"}},
        headers=headers,
    )

    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]
    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=vulnerable_chat)
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    result_id = next(r["id"] for r in results if r["result_code"] == "AEGIS-AI-001")
    return org_id, run_id, result_id, headers


async def test_status_reports_whether_the_assistant_is_available(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _, _, headers = await _run_with_findings(client, strong_password, "a")

    status = (
        await client.get(f"/api/v1/organizations/{org_id}/assistant/status", headers=headers)
    ).json()

    assert status["configured"] is True
    assert status["autonomy_mode"] == "RECOMMEND"


async def test_a_draft_is_stored_with_its_provenance_and_is_not_accepted(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, run_id, result_id, headers = await _run_with_findings(client, strong_password, "b")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "remediation", "scan_result_id": result_id},
        headers=headers,
    )

    assert response.status_code == 201
    draft = response.json()
    assert draft["content"]
    assert draft["model"] == "fake-model-1"
    assert draft["prompt_template_id"] == "assistant.draft_remediation"
    assert draft["prompt_template_version"]
    # The defining property: it is a draft until a human says otherwise.
    assert draft["accepted_at"] is None


async def test_the_finding_itself_is_untouched_by_drafting(
    client: AsyncClient, strong_password: str
) -> None:
    """The AI writes beside the record, never over it."""
    org_id, run_id, result_id, headers = await _run_with_findings(client, strong_password, "c")
    before = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()

    await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "severity_rationale", "scan_result_id": result_id},
        headers=headers,
    )

    after = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    assert after == before


async def test_accepting_a_draft_records_who_and_when(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, run_id, result_id, headers = await _run_with_findings(client, strong_password, "d")
    draft_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
            json={"field": "explanation", "scan_result_id": result_id},
            headers=headers,
        )
    ).json()["id"]

    accepted = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/drafts/{draft_id}/accept", headers=headers
    )

    assert accepted.status_code == 200
    assert accepted.json()["accepted_at"] is not None


async def test_accepting_requires_more_privilege_than_requesting(
    client: AsyncClient, strong_password: str
) -> None:
    """Reading a suggestion is cheap; putting it into the record is not."""
    org_id, run_id, result_id, owner_headers = await _run_with_findings(
        client, strong_password, "e"
    )
    _analyst_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    analyst = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "aianalyst@example.test",
            "full_name": "Analyst",
            "password": strong_password,
        },
        headers={HEADER_NAME: _analyst_anon_token},
    )
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": analyst.json()["user"]["email"], "role": "analyst"},
        headers=owner_headers,
    )
    analyst_headers = {"Authorization": f"Bearer {analyst.json()['access_token']}"}

    created = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "remediation", "scan_result_id": result_id},
        headers=analyst_headers,
    )
    assert created.status_code == 201

    refused = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/drafts/{created.json()['id']}/accept",
        headers=analyst_headers,
    )
    assert refused.status_code == 403


async def test_a_run_summary_uses_counts_the_platform_computed(
    client: AsyncClient, strong_password: str, provider: FakeProvider
) -> None:
    """§14 requires the methodology and scope figures to come from data. A
    model asked to count would sometimes get it wrong, and a wrong number in
    an executive summary discredits the report."""
    org_id, run_id, _, headers = await _run_with_findings(client, strong_password, "f")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "run_summary"},
        headers=headers,
    )

    assert response.status_code == 201
    _, prompt = provider.calls[-1]
    assert "Findings by severity:" in prompt
    assert "Explicitly not tested:" in prompt


async def test_a_finding_level_draft_needs_a_finding(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, run_id, _, headers = await _run_with_findings(client, strong_password, "g")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "remediation"},
        headers=headers,
    )

    assert response.status_code == 422
    assert "scan_result_id" in response.json()["error"]["message"]


async def test_drafts_are_not_visible_across_organizations(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, run_id, result_id, headers = await _run_with_findings(client, strong_password, "h")
    await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "remediation", "scan_result_id": result_id},
        headers=headers,
    )
    _outsider_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    outsider = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "aioutsider@example.test",
            "full_name": "Outsider",
            "password": strong_password,
        },
        headers={HEADER_NAME: _outsider_anon_token},
    )

    response = await client.get(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        headers={"Authorization": f"Bearer {outsider.json()['access_token']}"},
    )

    assert response.status_code == 404


async def test_a_capability_above_the_configured_mode_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, run_id, result_id, headers = await _run_with_findings(client, strong_password, "i")
    client._transport.app.dependency_overrides[get_ai_service] = lambda: AIService(  # type: ignore[attr-defined]
        FakeProvider(), mode=AutonomyMode.OFF
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "remediation", "scan_result_id": result_id},
        headers=headers,
    )

    assert response.status_code == 403
    assert "switched off" in response.json()["error"]["message"]


async def test_a_provider_failure_is_a_service_error_not_a_crash(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, run_id, result_id, headers = await _run_with_findings(client, strong_password, "j")

    def _explode(prompt: str, system: str | None) -> str:
        raise RuntimeError("provider down")

    client._transport.app.dependency_overrides[get_ai_service] = lambda: AIService(  # type: ignore[attr-defined]
        FakeProvider(responder=_explode), mode=AutonomyMode.RECOMMEND
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/assistant/runs/{run_id}/drafts",
        json={"field": "remediation", "scan_result_id": result_id},
        headers=headers,
    )

    assert response.status_code == 503
    assert "AI provider unavailable" in response.json()["error"]["message"]


async def test_the_openai_compatible_provider_reaches_only_its_endpoint() -> None:
    """The provider call goes through the same gated transport as everything
    else, under a scope allowing the provider host alone."""
    from app.core.assistant.openai_compatible import OpenAICompatibleProvider
    from app.core.assistant.provider import ProviderConfig, ProviderError
    from app.core.scope.engine import ScopeEngine
    from app.core.scope.transport import GatedTransport

    config = ProviderConfig(
        provider="openai_compatible",
        endpoint="https://api.example.test/v1/chat/completions",
        model="test-model",
    )
    transport = GatedTransport(
        engine=ScopeEngine(),
        dns_resolver=FakeDnsResolver({"api.example.test": ["203.0.113.50"]}),
    )
    provider = OpenAICompatibleProvider(config, transport)

    with respx.mock(assert_all_called=False) as router:
        router.post(config.endpoint).mock(
            return_value=Response(
                200,
                json={
                    "model": "test-model",
                    "choices": [{"message": {"content": "drafted text"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                },
            )
        )
        completion = await provider.generate("explain this", system="you are a helper")

    assert completion.text == "drafted text"
    assert completion.tokens_sent == 10
    # Cost is only ever reported when the provider reports it.
    assert completion.cost_usd is None

    # A provider whose host resolves to a blocked address is refused by the
    # same engine that guards a target.
    blocked = OpenAICompatibleProvider(
        config,
        GatedTransport(
            engine=ScopeEngine(),
            dns_resolver=FakeDnsResolver({"api.example.test": ["169.254.169.254"]}),
        ),
    )
    with pytest.raises(ProviderError, match="refused by the scope engine"):
        await blocked.generate("explain this")
