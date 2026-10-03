"""Assessment run API and worker tests (docs/BUILD_SPEC.md §15, §16).

The Celery broker is stubbed out so these tests exercise the API contract
without a worker process; the worker's own behaviour is tested by calling
`execute_assessment_run` directly, which is the same coroutine the task
wraps.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import respx
from httpx import AsyncClient, Response
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.models.audit import AuditEvent
from app.models.authorization import Authorization
from app.models.rules_of_engagement import RulesOfEngagementRecord
from app.workers import tasks as worker_tasks
from app.workers.cancellation import (
    clear_cancellation,
    is_cancellation_requested,
    request_cancellation,
)
from app.workers.tasks import execute_assessment_run
from tests.security.conftest import FakeDnsResolver

BASE_URL = "https://ai.example.test"

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Demo AI App", "version": "1.0"},
    "paths": {
        "/api/chat": {"post": {"operationId": "chat", "responses": {"200": {"description": "ok"}}}},
        "/api/search": {
            "get": {"operationId": "search", "responses": {"200": {"description": "ok"}}}
        },
    },
}


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record what would have been queued instead of talking to a broker."""
    queued: list[str] = []

    class _AsyncResult:
        id = "stub-task-id"

    def _send_task(name: str, args: list[str] | None = None, **kwargs: object) -> _AsyncResult:
        queued.append(args[0] if args else name)
        return _AsyncResult()

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", _send_task)
    return queued


def _worker_transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(),
        dns_resolver=FakeDnsResolver({"ai.example.test": ["203.0.113.5"]}),
    )


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    _response_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0].title(), "password": password},
        headers={HEADER_NAME: _response_anon_token},
    )
    assert response.status_code == 201
    return response.json()


def _roe_payload(**overrides: object) -> dict:
    payload: dict = {
        "allowed_domains": ["ai.example.test"],
        "excluded_domains": [],
        "allowed_ip_ranges": [],
        "allowed_paths": ["/api/*"],
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
    payload.update(overrides)
    return payload


def _authorization_payload(**overrides: object) -> dict:
    now = datetime.now(UTC)
    payload: dict = {
        "authorized_by_name": "Alice Owner",
        "authorized_by_role": "CISO",
        "authorized_by_email": "ciso@example.test",
        "reference": "TICKET-1234",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=6)).isoformat(),
    }
    payload.update(overrides)
    return payload


async def _ready_target(
    client: AsyncClient,
    password: str,
    suffix: str,
    *,
    authorize: bool = True,
    roe: dict | None = None,
    authorization: dict | None = None,
    with_surface: bool = True,
) -> tuple[str, str, str]:
    """An org with a target that is authorized, scoped, and has a surface."""
    owner = await _register(client, f"runowner{suffix}@example.test", password)
    header = f"Bearer {owner['access_token']}"
    headers = {"Authorization": header}

    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Run Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Demo AI App",
                "environment": "staging",
                "kind": "llm_app",
                "base_url": BASE_URL,
            },
            headers=headers,
        )
    ).json()["id"]

    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    response = await client.put(
        f"{base}/rules-of-engagement", json=roe or _roe_payload(), headers=headers
    )
    assert response.status_code == 200
    if authorize:
        response = await client.post(
            f"{base}/authorization",
            json=authorization or _authorization_payload(),
            headers=headers,
        )
        assert response.status_code == 201
    if with_surface:
        import json as _json

        response = await client.put(
            f"{base}/openapi",
            files={"file": ("openapi.json", _json.dumps(SPEC).encode("utf-8"), "application/json")},
            headers=headers,
        )
        assert response.status_code == 200

    return org_id, target_id, header


async def test_create_run_queues_it_and_records_the_operator(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "a")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": True},
        headers={"Authorization": header},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "queued"
    assert body["safe_mode"] is True
    assert _stub_broker == [body["id"]]

    events = await client.get(
        f"/api/v1/organizations/{org_id}/runs/{body['id']}/events",
        headers={"Authorization": header},
    )
    assert [event["kind"] for event in events.json()] == ["queued"]


async def test_run_cannot_start_without_confirming_authorization(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "b")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": False},
        headers={"Authorization": header},
    )

    assert response.status_code == 422
    assert _stub_broker == []


async def test_run_against_an_unauthorized_target_is_refused_before_queueing(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    """Confirming authorization in the request body is not authorization —
    the target itself must carry a valid grant (§2.1, fail closed)."""
    org_id, target_id, header = await _ready_target(client, strong_password, "c", authorize=False)

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": True},
        headers={"Authorization": header},
    )

    assert response.status_code == 409
    assert _stub_broker == []


async def test_viewer_cannot_start_a_run(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    org_id, target_id, owner_header = await _ready_target(client, strong_password, "d")
    viewer = await _register(client, "runviewer@example.test", strong_password)
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": viewer["user"]["email"], "role": "viewer"},
        headers={"Authorization": owner_header},
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": True},
        headers={"Authorization": f"Bearer {viewer['access_token']}"},
    )

    assert response.status_code == 403
    assert _stub_broker == []


async def test_runs_are_invisible_across_organizations(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "e")
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers={"Authorization": header},
        )
    ).json()["id"]

    outsider_org_id, _, outsider_header = await _ready_target(client, strong_password, "f")

    # A non-member gets 404 rather than 403: the run's existence is itself
    # tenant data (§5).
    denied = await client.get(
        f"/api/v1/organizations/{org_id}/runs/{run_id}",
        headers={"Authorization": outsider_header},
    )
    assert denied.status_code == 404

    # Nor can the run be reached by quoting it under the outsider's own org.
    mismatched = await client.get(
        f"/api/v1/organizations/{outsider_org_id}/runs/{run_id}",
        headers={"Authorization": outsider_header},
    )
    assert mismatched.status_code == 404


async def test_cancelling_a_queued_run_stops_it_before_it_starts(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "g")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    try:
        response = await client.post(
            f"/api/v1/organizations/{org_id}/runs/{run_id}/cancel", headers=headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "cancelled"
        # The signal is also published for a worker that already picked it up.
        assert is_cancellation_requested(run_id) is True

        # A worker that reaches it afterwards must not resurrect it.
        assert (
            await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
            is not None
        )
        after = await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
        assert after.json()["status"] == "cancelled"
    finally:
        clear_cancellation(run_id)


async def test_worker_executes_a_queued_run_end_to_end(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "h")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/api/search").mock(return_value=Response(200))
        status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    assert status.value == "completed"

    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    # Two checks now: reachability, then the API security probes.
    assert run["checks_completed"] == run["checks_total"] == 2
    assert run["requests_blocked"] == 0
    assert run["started_at"] is not None and run["finished_at"] is not None
    # The authorization and RoE in force are pinned to the run so a later
    # change to either cannot rewrite what this run was permitted to do.
    assert run["authorization_digest"].startswith("sha256:")
    assert run["roe_digest"].startswith("sha256:")

    events = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/events", headers=headers)
    ).json()
    kinds = [event["kind"] for event in events]
    assert kinds[:2] == ["queued", "started"]
    assert kinds[-1] == "completed"
    assert kinds.count("check_started") == kinds.count("check_completed") == 2
    assert [event["seq"] for event in events] == sorted(event["seq"] for event in events)

    # The run's own lifecycle is in the append-only audit log too, not only
    # the operational RunEvent feed just checked above.
    audited = (
        await db_session.execute(
            select(AuditEvent.action, AuditEvent.result).where(
                AuditEvent.resource_type == "assessment_run",
                AuditEvent.resource_id == run_id,
            )
        )
    ).all()
    assert ("run.start", "allow") in audited
    assert ("run.completed", "allow") in audited


async def test_cancellation_flag_stops_a_run_already_in_a_worker(
    client: AsyncClient, strong_password: str
) -> None:
    """The Redis signal is what reaches a worker mid-run; the run must end
    cancelled without sending anything further."""
    org_id, target_id, header = await _ready_target(client, strong_password, "i")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    request_cancellation(run_id)
    try:
        with respx.mock(assert_all_called=False) as router:
            chat = router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
            search = router.get(f"{BASE_URL}/api/search").mock(return_value=Response(200))
            status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
            assert chat.call_count == 0
            assert search.call_count == 0
    finally:
        clear_cancellation(run_id)

    assert status.value == "cancelled"
    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    assert run["status"] == "cancelled"
    assert run["halted_reason"] == "kill switch tripped"


async def test_expired_authorization_ends_the_run_as_expired_not_failed(
    client: AsyncClient, strong_password: str
) -> None:
    """A grant that lapses between queueing and execution must stop the run,
    and the run must say *why* rather than reporting a generic failure."""
    now = datetime.now(UTC)
    org_id, target_id, header = await _ready_target(
        client,
        strong_password,
        "j",
        authorization=_authorization_payload(
            valid_from=(now - timedelta(days=2)).isoformat(),
            valid_until=(now - timedelta(minutes=1)).isoformat(),
        ),
    )
    headers = {"Authorization": header}

    created = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": True},
        headers=headers,
    )
    # Already lapsed at creation time, so it never even reaches the queue.
    assert created.status_code == 409
    assert "not currently valid" in created.json()["error"]["message"]


async def test_authorization_that_lapses_before_the_worker_starts_ends_expired(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The grant is re-checked at execution time, not trusted from queueing:
    a run queued under a valid grant that lapses first must end `expired`,
    with the reason recorded, rather than running or failing opaquely."""
    org_id, target_id, header = await _ready_target(client, strong_password, "n")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    now = datetime.now(UTC)
    await db_session.execute(
        update(Authorization)
        .where(Authorization.target_id == uuid.UUID(target_id))
        .values(valid_from=now - timedelta(days=2), valid_until=now - timedelta(minutes=1))
    )
    await db_session.commit()

    with respx.mock(assert_all_called=False) as router:
        chat = router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
        assert chat.call_count == 0

    assert status.value == "expired"
    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    assert run["status"] == "expired"
    assert run["halted_reason"] == "authorization is not currently valid"


async def test_budget_exhaustion_produces_a_partial_but_valid_run(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(
        client,
        strong_password,
        "k",
        roe=_roe_payload(
            budgets={
                "max_requests": 1,
                "max_concurrency": 1,
                "requests_per_second": 10.0,
                "max_tokens_sent": 100000,
                "max_tokens_received": 200000,
                "max_estimated_cost_usd": 5.0,
                "max_wall_clock_minutes": 30,
            }
        ),
    )
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/api/search").mock(return_value=Response(200))
        status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    assert status.value == "completed"
    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    assert run["halted_reason"] == "requests budget exceeded"
    assert run["requests_blocked"] == 1


async def test_worker_refuses_to_restart_a_finished_run(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "l")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/api/search").mock(return_value=Response(200))
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

        # A redelivered task must not re-send a single request.
        chat = router.post(f"{BASE_URL}/api/chat")
        before = chat.call_count
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
        assert chat.call_count == before

    events = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/events", headers=headers)
    ).json()
    assert len([e for e in events if e["kind"] == "completed"]) == 1


async def test_unknown_run_id_is_a_failed_status_not_a_crash() -> None:
    assert (await worker_tasks.execute_assessment_run(uuid.uuid4())).value == "failed"


async def test_stream_replays_persisted_events_and_ends_on_terminal_status(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "m")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/api/search").mock(return_value=Response(200))
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    async with client.stream(
        "GET", f"/api/v1/organizations/{org_id}/runs/{run_id}/stream", headers=headers
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        frames = [line async for line in response.aiter_lines()]

    body = "\n".join(frames)
    # Every frame corresponds to a row a worker actually wrote (§16: progress
    # is never faked), and the stream closes once the run is terminal.
    assert "event: queued" in body
    assert "event: check_completed" in body
    assert body.rstrip().endswith('data: {"status": "completed"}')


async def test_run_without_rules_of_engagement_is_refused(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    """No RoE means no defined scope, and an undefined scope is not a
    permissive one — even with a valid authorization on the target."""
    owner = await _register(client, "runnoroe@example.test", strong_password)
    headers = {"Authorization": f"Bearer {owner['access_token']}"}
    org_id = (
        await client.post("/api/v1/organizations", json={"name": "No RoE Org"}, headers=headers)
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Unscoped",
                "environment": "staging",
                "kind": "llm_app",
                "base_url": BASE_URL,
            },
            headers=headers,
        )
    ).json()["id"]

    granted = await client.post(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/authorization",
        json=_authorization_payload(),
        headers=headers,
    )
    assert granted.status_code == 201

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": True},
        headers=headers,
    )

    assert response.status_code == 409
    assert "Rules of Engagement" in response.json()["error"]["message"]
    assert _stub_broker == []


async def test_listing_returns_only_this_organizations_runs_newest_first(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "o")
    headers = {"Authorization": header}
    created = [
        (
            await client.post(
                f"/api/v1/organizations/{org_id}/runs",
                json={"target_id": target_id, "authorization_confirmed": True},
                headers=headers,
            )
        ).json()["id"]
        for _ in range(2)
    ]
    other_org_id, other_target_id, other_header = await _ready_target(client, strong_password, "p")
    await client.post(
        f"/api/v1/organizations/{other_org_id}/runs",
        json={"target_id": other_target_id, "authorization_confirmed": True},
        headers={"Authorization": other_header},
    )

    listed = await client.get(f"/api/v1/organizations/{org_id}/runs", headers=headers)

    assert listed.status_code == 200
    assert {run["id"] for run in listed.json()} == set(created)


async def test_cancelling_a_finished_run_leaves_it_untouched(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _ready_target(client, strong_password, "q")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        router.get(f"{BASE_URL}/api/search").mock(return_value=Response(200))
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs/{run_id}/cancel", headers=headers
    )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    # No cancellation is published for a run that is already over, and no
    # spurious cancelled event is appended to its log.
    assert is_cancellation_requested(run_id) is False
    events = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/events", headers=headers)
    ).json()
    assert not [event for event in events if event["kind"] == "cancelled"]


async def test_a_broker_that_cannot_accept_the_run_fails_it_visibly(
    client: AsyncClient, strong_password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that could not be queued must not sit in `queued` forever
    waiting for a worker that will never see it."""
    org_id, target_id, header = await _ready_target(client, strong_password, "r")

    from app.core.runs import service as runs_service

    def _explode(name: str, args: list[str] | None = None, **kwargs: object) -> None:
        raise ConnectionError("broker unreachable")

    monkeypatch.setattr(runs_service.celery_app, "send_task", _explode)

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": target_id, "authorization_confirmed": True},
        headers={"Authorization": header},
    )

    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "failed"
    assert "broker unreachable" in body["error_message"]


async def test_scope_removed_after_queueing_fails_the_run_in_the_worker(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """If a target's scope is torn down between queueing and execution, the
    worker must refuse the run outright rather than fall back to any default."""
    org_id, target_id, header = await _ready_target(client, strong_password, "s")
    headers = {"Authorization": header}
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    await db_session.execute(
        delete(RulesOfEngagementRecord).where(
            RulesOfEngagementRecord.target_id == uuid.UUID(target_id)
        )
    )
    await db_session.commit()

    with respx.mock(assert_all_called=False) as router:
        chat = router.post(f"{BASE_URL}/api/chat").mock(return_value=Response(200))
        status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
        assert chat.call_count == 0

    assert status.value == "failed"
    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    assert run["status"] == "failed"
    assert "Rules of Engagement" in run["error_message"]
    events = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/events", headers=headers)
    ).json()
    assert events[-1]["kind"] == "failed"
