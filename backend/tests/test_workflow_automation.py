"""Pentest module Phase 8 (automation): Celery Beat scheduling, the inbound
webhook, and the approval gate for unattended triggers.

`tests/test_workflow.py` and `tests/test_workflows_api.py` already cover the
five-stage engine and the manual trigger path unchanged by this phase. This
file concentrates on what is new:

* an unattended trigger (Celery Beat, the webhook) whose plan would queue a
  scan-touching action pauses — a manual trigger never does;
* approving a paused run queues the scan through the exact same
  `queue_run()` `POST /runs` uses, attributed to the human who approved it;
* the inbound webhook's HMAC signature, replay protection, and 404-not-403
  tenant isolation.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.integrations import signing
from app.core.probes.models import Category, Confidence, Severity
from app.core.runs import service as runs_service
from app.core.workflow.contract import WorkflowStatus
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.finding import Finding, FindingStatus, Stability
from app.models.workflow import Workflow
from app.workers import tasks as tasks_module

LAB_HOST = "wfauto.example.test"
LAB_URL = f"http://{LAB_HOST}"

_WEBHOOK_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # 32 zero bytes


@pytest.fixture(autouse=True)
def _webhook_encryption_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY", _WEBHOOK_KEY_B64)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """`approve()` queues a real scan through `queue_run`, which sends a
    Celery task to a broker this test suite does not run. Same stub
    `test_runs_api.py`/`test_agent_tools.py` use against the same
    `app.core.runs.service.celery_app`."""
    queued: list[str] = []

    class _AsyncResult:
        id = "stub-task-id"

    def _send_task(name: str, args: list[str] | None = None, **kwargs: object) -> _AsyncResult:
        queued.append((args or [""])[0])
        return _AsyncResult()

    monkeypatch.setattr(runs_service.celery_app, "send_task", _send_task)
    return queued


async def _setup(
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, dict[str, str]]:
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"wfauto{suffix}@example.test",
            "full_name": "WF Automation Owner",
            "password": password,
        },
        headers={HEADER_NAME: anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"WF Automation Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Automation target",
                "environment": "test",
                "kind": "api",
                "base_url": LAB_URL,
            },
            headers=headers,
        )
    ).json()["id"]
    return org_id, target_id, headers


async def _give_target_an_openapi_spec(
    client: AsyncClient, org_id: str, target_id: str, headers: dict[str, str]
) -> None:
    """Makes `API_SCAN` actually run in the plan (not skipped) — the
    minimal way to put a scan-touching action in `plan.will_run` without
    standing up a whole adapter/code-repo fixture."""
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Automation target", "version": "1.0"},
        "paths": {
            "/ping": {"get": {"operationId": "ping", "responses": {"200": {"description": "ok"}}}}
        },
    }
    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/openapi",
        files={"file": ("openapi.json", json.dumps(spec).encode("utf-8"), "application/json")},
        headers=headers,
    )
    assert response.status_code == 200, response.text


async def _create_scheduled_workflow(
    client: AsyncClient, org_id: str, target_id: str, headers: dict[str, str], *, name: str
) -> str:
    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows",
        json={
            "name": name,
            "target_id": target_id,
            "trigger_kind": "schedule",
            "schedule_interval_minutes": 60,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


# --- schedule configuration -------------------------------------------------


async def test_a_schedule_interval_below_the_minimum_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "a")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows",
        json={
            "name": "too fast",
            "target_id": target_id,
            "trigger_kind": "schedule",
            "schedule_interval_minutes": 5,
        },
        headers=headers,
    )
    assert response.status_code == 422, response.text


async def test_creating_a_scheduled_workflow_sets_next_run_at(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "b")
    before = datetime.now(UTC)
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="ticking"
    )

    fetched = await client.get(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}", headers=headers
    )
    next_run_at = datetime.fromisoformat(fetched.json()["next_run_at"])
    assert before + timedelta(minutes=59) < next_run_at < before + timedelta(minutes=61)


async def test_clearing_the_schedule_interval_clears_next_run_at(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "c")
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="stoppable"
    )

    updated = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}",
        json={"schedule_interval_minutes": None},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["schedule_interval_minutes"] is None
    assert updated.json()["next_run_at"] is None


# --- dispatching a due schedule ----------------------------------------------


async def test_dispatch_advances_next_run_at_and_enqueues_only_due_workflows(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "d")
    due_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="due"
    )
    not_due_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="not-due"
    )

    # The API always sets `next_run_at` in the future; force the "due" one
    # into the past directly, the way time passing actually would.
    due = await db_session.get(Workflow, uuid.UUID(due_id))
    assert due is not None
    due.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    dispatched: list[str] = []
    monkeypatch.setattr(
        tasks_module.run_scheduled_workflow,
        "delay",
        lambda workflow_id: dispatched.append(workflow_id),
    )

    count = await tasks_module.dispatch_scheduled_workflows_async()

    assert count == 1
    assert dispatched == [due_id]
    # `dispatch_scheduled_workflows_async` updated these rows through its
    # own, separate session — `db_session`'s identity map still holds the
    # values from before, so a fresh read needs an explicit expire.
    db_session.expire_all()
    refreshed = await db_session.get(Workflow, uuid.UUID(due_id))
    assert refreshed is not None
    assert refreshed.next_run_at is not None
    assert refreshed.next_run_at > datetime.now(UTC) + timedelta(minutes=50)
    unchanged = await db_session.get(Workflow, uuid.UUID(not_due_id))
    assert unchanged is not None
    assert unchanged.next_run_at > datetime.now(UTC) + timedelta(minutes=50)


async def test_a_disabled_workflow_is_never_dispatched(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "e")
    workflow_id = await _create_scheduled_workflow(client, org_id, target_id, headers, name="off")
    workflow = await db_session.get(Workflow, uuid.UUID(workflow_id))
    assert workflow is not None
    workflow.enabled = False
    workflow.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    monkeypatch.setattr(tasks_module.run_scheduled_workflow, "delay", lambda workflow_id: None)
    count = await tasks_module.dispatch_scheduled_workflows_async()

    assert count == 0


# --- firing one scheduled workflow: the approval gate -----------------------


async def test_a_scheduled_run_pauses_when_the_plan_would_queue_a_scan(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "f")
    await _give_target_an_openapi_spec(client, org_id, target_id, headers)
    workflow_id = await _create_scheduled_workflow(client, org_id, target_id, headers, name="scans")

    await tasks_module.run_scheduled_workflow_async(workflow_id)

    runs = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()
    assert len(runs) == 1
    assert runs[0]["status"] == WorkflowStatus.AWAITING_APPROVAL.value
    assert runs[0]["assessment_run_id"] is None
    assert runs[0]["gate_passed"] is None
    assert "api_scan" in {a["kind"] for a in runs[0]["plan"]["actions"] if not a["skipped"]}


async def test_a_scheduled_run_completes_when_the_plan_has_nothing_to_approve(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "g")
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="gate-only"
    )

    await tasks_module.run_scheduled_workflow_async(workflow_id)

    runs = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()
    assert len(runs) == 1
    assert runs[0]["status"] == "completed"
    assert runs[0]["gate_passed"] is True


async def test_a_disabled_scheduled_workflow_is_not_run(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "h")
    workflow_id = await _create_scheduled_workflow(client, org_id, target_id, headers, name="off2")
    workflow = await db_session.get(Workflow, uuid.UUID(workflow_id))
    assert workflow is not None
    workflow.enabled = False
    await db_session.commit()

    await tasks_module.run_scheduled_workflow_async(workflow_id)

    runs = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()
    assert runs == []


# --- approve / reject --------------------------------------------------------


async def test_approving_a_paused_run_queues_the_scan_and_attributes_it_to_the_approver(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "i")
    await _give_target_an_openapi_spec(client, org_id, target_id, headers)
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="approve-me"
    )
    await tasks_module.run_scheduled_workflow_async(workflow_id)
    run_id = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()[0]["id"]

    approved = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs/{run_id}/approve",
        json={},
        headers=headers,
    )
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["status"] == "running"
    assert body["assessment_run_id"] is not None
    assert body["approved_by_user_id"] is not None
    assert body["approved_at"] is not None
    assert _stub_broker  # the scan was actually queued through queue_run


async def test_approving_a_run_not_awaiting_approval_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "j")
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="already-done"
    )
    await tasks_module.run_scheduled_workflow_async(workflow_id)
    run_id = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()[0]["id"]

    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs/{run_id}/approve",
        json={},
        headers=headers,
    )
    assert response.status_code == 409


async def test_rejecting_a_paused_run_marks_it_refused_with_the_reason(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "k")
    await _give_target_an_openapi_spec(client, org_id, target_id, headers)
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="reject-me"
    )
    await tasks_module.run_scheduled_workflow_async(workflow_id)
    run_id = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()[0]["id"]

    rejected = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs/{run_id}/reject",
        json={"reason": "not authorized this week"},
        headers=headers,
    )
    assert rejected.status_code == 200, rejected.text
    body = rejected.json()
    assert body["status"] == "refused"
    assert body["detail"] == "not authorized this week"
    assert body["assessment_run_id"] is None


# --- gating a linked assessment run once it finishes ------------------------


def _finding_fields(target_id: uuid.UUID, organization_id: uuid.UUID) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "organization_id": organization_id,
        "target_id": target_id,
        "fingerprint": f"fp-{uuid.uuid4().hex}",
        "title": "A critical finding",
        "category": Category.API_SECURITY,
        "probe_id": "KERVY-API-999",
        "probe_version": "1.0.0",
        "surface": "GET /ping",
        "severity": Severity.CRITICAL,
        "severity_rationale": "unauthenticated critical exposure",
        "confidence": Confidence.HIGH,
        "stability": Stability.DETERMINISTIC,
        "risk_model": "kervy-ordinal-v1",
        "risk_score": 10,
        "description": "Critical exposure.",
        "impact": "Full compromise.",
        "remediation": "Fix it.",
        "first_seen": now,
        "last_seen": now,
        "status": FindingStatus.NEW,
    }


async def test_gate_workflow_run_if_linked_gates_over_the_findings_the_scan_produced(
    client: AsyncClient, strong_password: str, db_session: AsyncSession, _stub_broker: list[str]
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "l")
    await _give_target_an_openapi_spec(client, org_id, target_id, headers)
    workflow_id = await _create_scheduled_workflow(
        client, org_id, target_id, headers, name="gate-linked"
    )
    await tasks_module.run_scheduled_workflow_async(workflow_id)
    run_id = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()[0]["id"]

    approved = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs/{run_id}/approve",
        json={},
        headers=headers,
    )
    assessment_run_id = approved.json()["assessment_run_id"]

    # Simulate the queued scan finishing with one critical finding — the
    # same gate a manual trigger's synchronous call already uses.
    db_session.add(Finding(**_finding_fields(uuid.UUID(target_id), uuid.UUID(org_id))))
    assessment_run = await db_session.get(AssessmentRun, uuid.UUID(assessment_run_id))
    assert assessment_run is not None
    assessment_run.status = RunStatus.COMPLETED
    await db_session.commit()

    await tasks_module.gate_workflow_run_if_linked_async(assessment_run_id)

    runs = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()
    assert runs[0]["status"] == "completed"
    assert runs[0]["gate_passed"] is False
    assert runs[0]["gate_exit_code"] == 1


async def test_gate_workflow_run_if_linked_is_a_noop_for_an_unlinked_assessment_run() -> None:
    # No exception, nothing to gate — the overwhelming majority of
    # assessment runs have no linked workflow run at all.
    await tasks_module.gate_workflow_run_if_linked_async(str(uuid.uuid4()))


# --- the inbound webhook -----------------------------------------------------


async def _enable_webhook(
    client: AsyncClient, org_id: str, workflow_id: str, headers: dict[str, str]
) -> tuple[str, str]:
    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/webhook-secret",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["secret"], body["webhook_url"]


def _signed_headers(secret: str, body: bytes, *, timestamp: str | None = None) -> dict[str, str]:
    stamp, signature = signing.sign(secret, body, timestamp=timestamp)
    return {signing.SIGNATURE_HEADER: signature, signing.TIMESTAMP_HEADER: stamp}


async def _post_webhook(
    client: AsyncClient, workflow_id: str, body: bytes, headers: dict[str, str]
) -> object:
    """A real webhook sender never carries this platform's session cookie —
    `_setup`/`_enable_webhook` authenticate the *test's* setup calls with a
    Bearer token, but the same `client` object still holds the cookie its
    registration call set. Clearing it here is what actually reproduces an
    external caller, not a workaround for a CSRF false positive: with the
    cookie gone, `authenticated_by_cookie()` correctly reads this request as
    what it is — not cookie-authenticated at all."""
    client.cookies.clear()
    return await client.post(
        f"/api/v1/webhooks/workflows/{workflow_id}", content=body, headers=headers
    )


async def test_webhook_requires_signature_headers(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "m")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "wh", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]

    response = await _post_webhook(
        client, workflow_id, b'{"kind": "repository_change"}', {}
    )
    assert response.status_code == 401


async def test_webhook_rejects_an_unknown_or_disabled_workflow(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "n")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "not-enabled", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    body = json.dumps({"kind": "repository_change"}).encode("utf-8")

    # Never enabled at all — a made-up secret, since none exists yet.
    response = await _post_webhook(
        client, workflow_id, body, _signed_headers("no-such-secret", body)
    )
    assert response.status_code == 404

    unknown = await _post_webhook(
        client, str(uuid.uuid4()), body, _signed_headers("anything", body)
    )
    assert unknown.status_code == 404


async def test_webhook_accepts_a_correctly_signed_delivery(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "o")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "webhookable", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    secret, _url = await _enable_webhook(client, org_id, workflow_id, headers)
    body = json.dumps(
        {"kind": "repository_change", "ref": "refs/heads/main", "commit": "a" * 40}
    ).encode("utf-8")

    response = await _post_webhook(client, workflow_id, body, _signed_headers(secret, body))
    assert response.status_code == 202, response.text

    runs = (
        await client.get(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
        )
    ).json()
    assert len(runs) == 1
    assert runs[0]["trigger"]["kind"] == "repository_change"
    assert runs[0]["trigger"]["unattended"] is True
    assert runs[0]["trigger"]["actor"] == f"webhook:{workflow_id}"


async def test_webhook_rejects_a_bad_signature(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "p")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "bad-sig", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    _secret, _url = await _enable_webhook(client, org_id, workflow_id, headers)
    body = json.dumps({"kind": "repository_change"}).encode("utf-8")

    response = await _post_webhook(
        client, workflow_id, body, _signed_headers("wrong-secret", body)
    )
    assert response.status_code == 401


async def test_webhook_rejects_an_expired_timestamp(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "q")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "stale", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    secret, _url = await _enable_webhook(client, org_id, workflow_id, headers)
    body = json.dumps({"kind": "repository_change"}).encode("utf-8")
    old_timestamp = str(int(time.time()) - signing.DEFAULT_TOLERANCE_SECONDS - 60)

    response = await _post_webhook(
        client, workflow_id, body, _signed_headers(secret, body, timestamp=old_timestamp)
    )
    assert response.status_code == 401


async def test_webhook_rejects_a_replayed_delivery(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "r")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "replay", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    secret, _url = await _enable_webhook(client, org_id, workflow_id, headers)
    body = json.dumps({"kind": "repository_change"}).encode("utf-8")
    signed = _signed_headers(secret, body)

    first = await _post_webhook(client, workflow_id, body, signed)
    assert first.status_code == 202, first.text

    second = await _post_webhook(client, workflow_id, body, signed)
    assert second.status_code == 409


async def test_webhook_rejects_a_kind_it_may_not_carry(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "s")
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "wrong-kind", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    secret, _url = await _enable_webhook(client, org_id, workflow_id, headers)
    body = json.dumps({"kind": "schedule"}).encode("utf-8")

    response = await _post_webhook(client, workflow_id, body, _signed_headers(secret, body))
    assert response.status_code == 422


async def test_one_workflows_secret_does_not_verify_anothers_webhook(
    client: AsyncClient, strong_password: str
) -> None:
    """Tenant isolation for the webhook: a secret generated for workflow A
    must not authenticate a delivery to workflow B's URL, even within the
    same organization."""
    org_id, target_id, headers = await _setup(client, strong_password, "t")
    workflow_a = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "wh-a", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    workflow_b = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "wh-b", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]
    secret_a, _ = await _enable_webhook(client, org_id, workflow_a, headers)
    await _enable_webhook(client, org_id, workflow_b, headers)
    body = json.dumps({"kind": "repository_change"}).encode("utf-8")

    response = await _post_webhook(client, workflow_b, body, _signed_headers(secret_a, body))
    assert response.status_code == 401
