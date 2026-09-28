"""The native agent's HTTP surface (`app/api/v1/routers/agent.py`,
Agent Phase 5): tool discovery, a synchronous READ_ONLY investigation, a
SENSITIVE investigation that pauses for approval and resumes, and cancel.

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
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.planner import PLAN_PROMPT
from app.core.assistant.fake import FakeProvider
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.agent import Agent, AgentProvider, AgentProviderKind


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
