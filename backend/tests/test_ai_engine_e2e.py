"""The AI engine reached through the real stack: configure an adapter over
the REST API, run the assessment in the worker, read the results back."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import respx
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.workers.tasks import execute_assessment_run
from tests.lab.ai_handlers import LAB_SECRET, vulnerable_chat
from tests.security.conftest import FakeDnsResolver

LAB_HOST = "vulnerable-ai.lab.test"
LAB_URL = f"https://{LAB_HOST}"


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "stub-task-id"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


def _worker_transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({LAB_HOST: ["203.0.113.20"]})
    )


async def _setup(
    client: AsyncClient, password: str, *, with_adapter: bool
) -> tuple[str, str, dict]:
    _register_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    register = await client.post(
        "/api/v1/auth/register",
        json={"email": "aiowner@example.test", "full_name": "AI Owner", "password": password},
        headers={HEADER_NAME: _register_anon_token},
    )
    headers = {"Authorization": f"Bearer {register.json()['access_token']}"}
    org_id = (
        await client.post("/api/v1/organizations", json={"name": "AI Org"}, headers=headers)
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Lab Assistant",
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
                "max_requests": 800,
                "max_concurrency": 3,
                "requests_per_second": 50.0,
                "max_tokens_sent": 200000,
                "max_tokens_received": 200000,
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
            "reference": "AI-LAB-1",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=6)).isoformat(),
        },
        headers=headers,
    )
    if with_adapter:
        response = await client.put(
            f"{base}/adapter",
            json={
                "adapter_kind": "chat_http",
                "adapter_config": {"endpoint": "/api/chat"},
                "declared_tools": [
                    {"name": "search_products"},
                    {
                        "name": "issue_refund",
                        "writes": True,
                        "irreversible": True,
                        "external": True,
                    },
                ],
            },
            headers=headers,
        )
        assert response.status_code == 200, response.text

    return org_id, target_id, headers


async def _run(client: AsyncClient, org_id: str, target_id: str, headers: dict) -> str:
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=vulnerable_chat)
        status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    assert status.value == "completed"
    return run_id


async def test_a_run_against_the_ai_lab_stores_measured_findings(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, with_adapter=True)
    run_id = await _run(client, org_id, target_id, headers)

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    codes = {result["result_code"] for result in results}

    assert {"AEGIS-AI-001", "AEGIS-AI-010", "AEGIS-AI-011", "AEGIS-AI-031"} <= codes

    injection = next(r for r in results if r["result_code"] == "AEGIS-AI-001")
    assert "OWASP-LLM-2026:LLM01" in injection["frameworks"]
    assert "Attack success rate:" in injection["evidence"]
    assert "Decision rule:" in injection["evidence"]

    # No credential the lab disclosed may be stored anywhere in the results.
    assert LAB_SECRET not in json.dumps(results)
    assert "labpassword" not in json.dumps(results)


async def test_a_target_without_an_adapter_runs_the_api_engine_only(
    client: AsyncClient, strong_password: str
) -> None:
    """No chat adapter means no conversational surface. The AI engine
    declines rather than guessing an endpoint and a wire format, because a
    guess would send adversarial prompts somewhere nobody authorized in
    that shape."""
    org_id, target_id, headers = await _setup(client, strong_password, with_adapter=False)
    run_id = await _run(client, org_id, target_id, headers)

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()

    assert not [r for r in results if r["probe_id"].startswith("ai.")]


async def test_an_invalid_adapter_configuration_is_refused_at_configuration_time(
    client: AsyncClient, strong_password: str
) -> None:
    """A bad response path is a 422 now rather than a failed run later."""
    org_id, target_id, headers = await _setup(client, strong_password, with_adapter=False)

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/adapter",
        json={
            "adapter_kind": "chat_http",
            "adapter_config": {"request_template": {"text": "no placeholder here"}},
        },
        headers=headers,
    )

    assert response.status_code == 422
    assert "placeholder" in response.json()["error"]["message"]
