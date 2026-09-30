"""The native agent's HTTP surface (`app/api/v1/routers/agent.py`, Agent
Phases 5-6): tool discovery, a synchronous READ_ONLY investigation, a
SENSITIVE investigation that pauses for approval and resumes, cancel, the
direct single-tool call surface `backend/mcp_server/` uses, and the
notification fan-out a terminal investigation triggers.

`build_provider` is monkeypatched to a `FakeProvider` (Implementation
Specification §20) so these tests never call a live AI provider; the
provider's `responder` distinguishes the planning call from the final
summary call by which prompt template's system string it was given.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.planner import PLAN_PROMPT
from app.core.assistant.fake import FakeProvider
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.agent import Agent, AgentProvider, AgentProviderKind
from app.models.integration import NotificationChannel, NotificationDelivery


@pytest.fixture
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """`start_scan` queues a real run through `app.core.runs.service.queue_run`
    — stub its Celery dispatch the same way `test_runs_api.py` does, so
    these tests never need a broker."""
    queued: list[str] = []

    class _AsyncResult:
        id = "stub-task-id"

    def _send_task(name: str, args: list[str] | None = None, **kwargs: object) -> _AsyncResult:
        queued.append(args[0] if args else name)
        return _AsyncResult()

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", _send_task)
    return queued


def _roe_payload() -> dict:
    return {
        "allowed_domains": ["agent-api.example.test"],
        "excluded_domains": [],
        "allowed_ip_ranges": [],
        "allowed_paths": ["/*"],
        "excluded_paths": [],
        "allowed_methods": ["GET", "POST"],
        "forbidden_headers": [],
        "budgets": {
            "max_requests": 500,
            "max_concurrency": 3,
            "requests_per_second": 10.0,
            "max_tokens_sent": 100000,
            "max_tokens_received": 200000,
            "max_estimated_cost_usd": 5.0,
            "max_wall_clock_minutes": 30,
        },
        "safe_mode": True,
    }


def _authorization_payload() -> dict:
    now = datetime.now(UTC)
    return {
        "authorized_by_name": "Alice Owner",
        "authorized_by_role": "CISO",
        "authorized_by_email": "ciso@example.test",
        "reference": "TICKET-9999",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=6)).isoformat(),
    }


async def _org_and_target(
    client: AsyncClient, password: str, suffix: str, *, authorized: bool = False
) -> tuple[uuid.UUID, uuid.UUID, dict[str, str]]:
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"agentapi{suffix}@example.test",
            "full_name": "Agent API Owner",
            "password": password,
        },
        headers={HEADER_NAME: anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = uuid.UUID(
        (
            await client.post(
                "/api/v1/organizations", json={"name": f"Agent API Org {suffix}"}, headers=headers
            )
        ).json()["id"]
    )
    target_id = uuid.UUID(
        (
            await client.post(
                f"/api/v1/organizations/{org_id}/targets",
                json={
                    "name": "agent-api-target",
                    "environment": "staging",
                    "kind": "llm_app",
                    "base_url": "https://agent-api.example.test",
                },
                headers=headers,
            )
        ).json()["id"]
    )
    if authorized:
        base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
        roe = await client.put(f"{base}/rules-of-engagement", json=_roe_payload(), headers=headers)
        assert roe.status_code == 200, roe.text
        grant = await client.post(
            f"{base}/authorization", json=_authorization_payload(), headers=headers
        )
        assert grant.status_code == 201, grant.text
    return org_id, target_id, headers


async def _enable_agent(db_session: AsyncSession, organization_id: uuid.UUID) -> None:
    provider_row = AgentProvider(
        organization_id=organization_id,
        name="test-provider",
        kind=AgentProviderKind.ANTHROPIC,
        endpoint="https://api.anthropic.test/v1/messages",
        model="test-model",
        is_default=True,
        enabled=True,
    )
    db_session.add(provider_row)
    await db_session.flush()
    db_session.add(
        Agent(organization_id=organization_id, enabled=True, default_provider_id=provider_row.id)
    )
    await db_session.commit()


def _fake_provider(monkeypatch: pytest.MonkeyPatch, responder: object) -> FakeProvider:
    from app.api.v1.routers import agent as agent_router

    provider = FakeProvider(responder=responder)
    monkeypatch.setattr(agent_router, "build_provider", lambda row: provider)
    return provider


def _plan_responder(steps: list[dict]) -> object:
    def _respond(prompt: str, system: str | None) -> str:
        if system == PLAN_PROMPT.system:
            return json.dumps({"steps": steps})
        return "Summary: done."

    return _respond


async def test_list_tools_returns_the_registry(client: AsyncClient, strong_password: str) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "a")

    response = await client.get(f"/api/v1/organizations/{org_id}/agent/tools", headers=headers)

    assert response.status_code == 200
    names = {entry["name"] for entry in response.json()}
    assert "search_assets" in names
    assert "start_scan" in names


async def test_investigate_refuses_without_a_configured_agent(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "b")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "list my targets"},
        headers=headers,
    )

    assert response.status_code == 409


async def test_investigate_runs_a_read_only_plan_synchronously(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, target_id, headers = await _org_and_target(client, strong_password, "c")
    await _enable_agent(db_session, org_id)
    _fake_provider(
        monkeypatch,
        _plan_responder([{"tool_name": "get_asset", "params": {"target_id": str(target_id)}}]),
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "look up the target"},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "completed"
    assert body["outcomes"][0]["tool_name"] == "get_asset"
    assert body["outcomes"][0]["status"] == "ok"
    assert body["summary"]


async def test_investigate_pauses_for_a_sensitive_tool_and_approve_resumes_it(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    _stub_broker: list[str],
) -> None:
    org_id, target_id, headers = await _org_and_target(
        client, strong_password, "d", authorized=True
    )
    await _enable_agent(db_session, org_id)
    _fake_provider(
        monkeypatch,
        _plan_responder(
            [
                {
                    "tool_name": "start_scan",
                    "params": {
                        "target_id": str(target_id),
                        "authorization_confirmed": True,
                    },
                }
            ]
        ),
    )

    paused = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "scan the target"},
        headers=headers,
    )

    assert paused.status_code == 202, paused.text
    paused_body = paused.json()
    assert paused_body["status"] == "awaiting_approval"
    assert paused_body["pending_approval"]["tool_name"] == "start_scan"
    investigation_id = paused_body["investigation_id"]

    status_response = await client.get(
        f"/api/v1/organizations/{org_id}/agent/investigate/{investigation_id}/status",
        headers=headers,
    )
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "awaiting_approval"

    approved = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate/{investigation_id}/approve",
        json={},
        headers=headers,
    )

    assert approved.status_code == 200, approved.text
    approved_body = approved.json()
    assert approved_body["status"] == "completed"
    assert approved_body["outcomes"][0]["tool_name"] == "start_scan"
    assert approved_body["outcomes"][0]["status"] == "ok"

    # The paused session is gone once resolved.
    gone = await client.get(
        f"/api/v1/organizations/{org_id}/agent/investigate/{investigation_id}/status",
        headers=headers,
    )
    assert gone.status_code == 404


async def test_cancel_discards_a_paused_investigation(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, target_id, headers = await _org_and_target(
        client, strong_password, "e", authorized=True
    )
    await _enable_agent(db_session, org_id)
    _fake_provider(
        monkeypatch,
        _plan_responder(
            [
                {
                    "tool_name": "start_scan",
                    "params": {
                        "target_id": str(target_id),
                        "authorization_confirmed": True,
                    },
                }
            ]
        ),
    )

    paused = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "scan the target"},
        headers=headers,
    )
    investigation_id = paused.json()["investigation_id"]

    cancelled = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate/{investigation_id}/cancel",
        headers=headers,
    )
    assert cancelled.status_code == 204

    gone = await client.get(
        f"/api/v1/organizations/{org_id}/agent/investigate/{investigation_id}/status",
        headers=headers,
    )
    assert gone.status_code == 404


async def test_status_404s_for_an_unknown_investigation(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "f")

    response = await client.get(
        f"/api/v1/organizations/{org_id}/agent/investigate/{uuid.uuid4()}/status",
        headers=headers,
    )

    assert response.status_code == 404


async def test_status_does_not_leak_another_organizations_paused_investigation(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, target_id, headers = await _org_and_target(
        client, strong_password, "g", authorized=True
    )
    other_org_id, _other_target_id, other_headers = await _org_and_target(
        client, strong_password, "h"
    )
    await _enable_agent(db_session, org_id)
    _fake_provider(
        monkeypatch,
        _plan_responder(
            [
                {
                    "tool_name": "start_scan",
                    "params": {
                        "target_id": str(target_id),
                        "authorization_confirmed": True,
                    },
                }
            ]
        ),
    )

    paused = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "scan the target"},
        headers=headers,
    )
    investigation_id = paused.json()["investigation_id"]

    cross_org = await client.get(
        f"/api/v1/organizations/{other_org_id}/agent/investigate/{investigation_id}/status",
        headers=other_headers,
    )
    assert cross_org.status_code == 404


# --- direct tool calls (backend/mcp_server/'s surface) ----------------------


async def test_list_tools_includes_each_tools_input_schema(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "i")

    response = await client.get(f"/api/v1/organizations/{org_id}/agent/tools", headers=headers)

    entries = {entry["name"]: entry for entry in response.json()}
    assert entries["get_asset"]["input_schema"]["properties"]["target_id"]


async def test_call_tool_invokes_a_read_only_tool_directly(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _org_and_target(client, strong_password, "j")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/tools/get_asset/call",
        json={"params": {"target_id": str(target_id)}},
        headers=headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["result"]["target"]["id"] == str(target_id)


async def test_call_tool_refuses_a_sensitive_tool_directly(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _org_and_target(
        client, strong_password, "k", authorized=True
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/tools/start_scan/call",
        json={"params": {"target_id": str(target_id), "authorization_confirmed": True}},
        headers=headers,
    )

    assert response.status_code == 409


async def test_call_tool_404_for_an_unknown_tool_name(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "l")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/tools/does_not_exist/call",
        json={"params": {}},
        headers=headers,
    )

    assert response.status_code == 404


async def test_call_tool_404_when_the_tool_itself_cannot_find_its_target(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "m")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/tools/get_asset/call",
        json={"params": {"target_id": str(uuid.uuid4())}},
        headers=headers,
    )

    assert response.status_code == 404


async def test_call_tool_422_for_invalid_params(client: AsyncClient, strong_password: str) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "n")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/tools/get_asset/call",
        json={"params": {}},
        headers=headers,
    )

    assert response.status_code == 422


# --- notification fan-out ---------------------------------------------------


async def test_a_completed_investigation_notifies_a_subscribed_channel(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    _stub_broker: list[str],
) -> None:
    org_id, target_id, headers = await _org_and_target(client, strong_password, "o")
    await _enable_agent(db_session, org_id)
    db_session.add(
        NotificationChannel(
            organization_id=org_id,
            name="ops-webhook",
            kind="generic_webhook",
            events=["agent_investigation.completed"],
            enabled=True,
        )
    )
    await db_session.commit()
    _fake_provider(
        monkeypatch,
        _plan_responder([{"tool_name": "get_asset", "params": {"target_id": str(target_id)}}]),
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "look up the target"},
        headers=headers,
    )
    assert response.status_code == 200, response.text

    deliveries = (
        (
            await db_session.execute(
                select(NotificationDelivery).where(NotificationDelivery.organization_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(deliveries) == 1
    assert deliveries[0].event_type == "agent_investigation.completed"
    assert "kervy.deliver_notifications" in _stub_broker


# --- per-organization tool configuration (enable/disable, role override) ---


async def test_put_tool_config_round_trips_through_get(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "q")

    put_response = await client.put(
        f"/api/v1/organizations/{org_id}/agent/tools/get_workflow_status/config",
        json={"enabled": True, "minimum_role_override": "owner"},
        headers=headers,
    )
    assert put_response.status_code == 200, put_response.text
    assert put_response.json() == {
        "tool_name": "get_workflow_status",
        "enabled": True,
        "minimum_role": "analyst",
        "minimum_role_override": "owner",
        "effective_minimum_role": "owner",
    }

    get_response = await client.get(
        f"/api/v1/organizations/{org_id}/agent/tools/get_workflow_status/config",
        headers=headers,
    )
    assert get_response.status_code == 200
    assert get_response.json() == put_response.json()


async def test_put_tool_config_rejects_an_override_below_the_tools_code_default(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "r")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/agent/tools/get_workflow_status/config",
        json={"enabled": True, "minimum_role_override": "viewer"},
        headers=headers,
    )

    assert response.status_code == 422
    assert "cannot be set below its code default" in response.text


async def test_put_tool_config_404s_for_an_unknown_tool(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "s")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/agent/tools/does_not_exist/config",
        json={"enabled": True},
        headers=headers,
    )

    assert response.status_code == 404


async def test_disabling_a_tool_refuses_even_the_owner_on_a_direct_call(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _org_and_target(client, strong_password, "t")

    disable = await client.put(
        f"/api/v1/organizations/{org_id}/agent/tools/get_asset/config",
        json={"enabled": False},
        headers=headers,
    )
    assert disable.status_code == 200, disable.text
    assert disable.json()["enabled"] is False

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/tools/get_asset/call",
        json={"params": {"target_id": str(target_id)}},
        headers=headers,
    )

    assert response.status_code == 403


async def test_the_tool_catalog_reflects_a_configured_override_and_disablement(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _target_id, headers = await _org_and_target(client, strong_password, "u")

    await client.put(
        f"/api/v1/organizations/{org_id}/agent/tools/get_workflow_status/config",
        json={"enabled": True, "minimum_role_override": "owner"},
        headers=headers,
    )
    await client.put(
        f"/api/v1/organizations/{org_id}/agent/tools/get_asset/config",
        json={"enabled": False},
        headers=headers,
    )

    catalog = await client.get(f"/api/v1/organizations/{org_id}/agent/tools", headers=headers)
    entries = {entry["name"]: entry for entry in catalog.json()}

    assert entries["get_workflow_status"]["effective_minimum_role"] == "owner"
    assert entries["get_workflow_status"]["minimum_role"] == "analyst"
    assert entries["get_asset"]["enabled"] is False


async def test_a_paused_investigation_does_not_notify_yet(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, target_id, headers = await _org_and_target(
        client, strong_password, "p", authorized=True
    )
    await _enable_agent(db_session, org_id)
    db_session.add(
        NotificationChannel(
            organization_id=org_id,
            name="ops-webhook",
            kind="generic_webhook",
            events=["agent_investigation.completed", "agent_investigation.failed"],
            enabled=True,
        )
    )
    await db_session.commit()
    _fake_provider(
        monkeypatch,
        _plan_responder(
            [
                {
                    "tool_name": "start_scan",
                    "params": {
                        "target_id": str(target_id),
                        "authorization_confirmed": True,
                    },
                }
            ]
        ),
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "scan the target"},
        headers=headers,
    )
    assert response.status_code == 202, response.text

    deliveries = (
        (
            await db_session.execute(
                select(NotificationDelivery).where(NotificationDelivery.organization_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    assert deliveries == []
