"""Findings through the real stack: promotion from a run, dedup across runs,
and lifecycle triage."""

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
from tests.lab.ai_handlers import vulnerable_chat
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
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"findowner{suffix}@example.test",
            "full_name": "Find Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Find Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Lab assistant",
                "environment": "production",
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
            "authorized_by_name": "Find Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "FIND-1",
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
    return org_id, target_id, headers


async def _run(client: AsyncClient, org_id: str, target_id: str, headers: dict[str, str]) -> str:
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
    return run_id


async def test_a_run_promotes_its_results_into_scored_findings(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "a")
    await _run(client, org_id, target_id, headers)

    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()

    assert findings
    for finding in findings:
        # The acceptance criterion: every finding has a rationale, and it
        # states the score the finding carries.
        assert finding["severity_rationale"]
        assert f"{finding['risk_score']}/10" in finding["severity_rationale"]
        assert finding["risk_model"] == "kervy-v1"
        assert finding["risk_inputs"]
        assert finding["fingerprint"].startswith("sha256:")
        assert finding["status"] == "new"
        assert finding["times_seen"] == 1
        # Never manufactured (§12).
        assert finding["cvss_v4"] is None
        assert finding["aivss"] is None


async def test_informational_results_do_not_become_findings(
    client: AsyncClient, strong_password: str
) -> None:
    """The informational rows are coverage notes and "not tested" markers.
    Promoting them would file "this was not tested" as a problem."""
    org_id, target_id, headers = await _setup(client, strong_password, "b")
    run_id = await _run(client, org_id, target_id, headers)

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()

    assert [r for r in results if r["severity"] == "INFORMATIONAL"]
    assert not [f for f in findings if f["severity"] == "INFORMATIONAL"]


async def test_a_second_run_updates_the_same_finding_rather_than_duplicating_it(
    client: AsyncClient, strong_password: str
) -> None:
    """The property the fingerprint exists for. Without it, "is this still
    there?" is unanswerable and remediation has nothing stable to attach to."""
    org_id, target_id, headers = await _setup(client, strong_password, "c")
    await _run(client, org_id, target_id, headers)
    first = (await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)).json()

    await _run(client, org_id, target_id, headers)
    second = (await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)).json()

    assert len(second) == len(first)
    assert {f["fingerprint"] for f in second} == {f["fingerprint"] for f in first}
    assert all(f["times_seen"] == 2 for f in second)


async def test_a_triage_decision_survives_a_re_run(
    client: AsyncClient, strong_password: str
) -> None:
    """Re-running a scan must not silently revert a human's judgement."""
    org_id, target_id, headers = await _setup(client, strong_password, "d")
    await _run(client, org_id, target_id, headers)
    finding = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()[0]

    await client.post(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/status",
        json={"status": "accepted_risk", "note": "compensating control in place"},
        headers=headers,
    )
    await _run(client, org_id, target_id, headers)

    after = (
        await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding['id']}", headers=headers
        )
    ).json()
    assert after["status"] == "accepted_risk"
    assert after["times_seen"] == 2


async def test_something_marked_remediated_that_is_still_there_reopens(
    client: AsyncClient, strong_password: str
) -> None:
    """The one exception to preserving a status. A stale "remediated" on a
    weakness that is still present is the most dangerous kind of record."""
    org_id, target_id, headers = await _setup(client, strong_password, "e")
    await _run(client, org_id, target_id, headers)
    finding = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()[0]
    base = f"/api/v1/organizations/{org_id}/findings/{finding['id']}/status"

    await client.post(base, json={"status": "in_remediation"}, headers=headers)
    await client.post(base, json={"status": "remediated"}, headers=headers)
    await _run(client, org_id, target_id, headers)

    after = (
        await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding['id']}", headers=headers
        )
    ).json()
    assert after["status"] == "confirmed"
    assert "still present" in after["status_note"]


async def test_a_finding_cannot_jump_straight_to_closed(
    client: AsyncClient, strong_password: str
) -> None:
    """Transitions are restricted so a closed finding is auditable: it had
    to pass through a state that recorded why."""
    org_id, target_id, headers = await _setup(client, strong_password, "f")
    await _run(client, org_id, target_id, headers)
    finding = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()[0]

    response = await client.post(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/status",
        json={"status": "closed"},
        headers=headers,
    )

    assert response.status_code == 409
    assert "cannot move a finding from new to closed" in response.json()["error"]["message"]


async def test_findings_can_be_filtered_and_are_ordered_by_risk(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "g")
    await _run(client, org_id, target_id, headers)

    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    scores = [f["risk_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)

    filtered = (
        await client.get(
            f"/api/v1/organizations/{org_id}/findings",
            params={"finding_status": "new"},
            headers=headers,
        )
    ).json()
    assert len(filtered) == len(findings)


async def test_findings_are_not_visible_across_organizations(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "h")
    await _run(client, org_id, target_id, headers)
    _outsider_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    outsider = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "findoutsider@example.test",
            "full_name": "Outsider",
            "password": strong_password,
        },
        headers={HEADER_NAME: _outsider_anon_token},
    )

    response = await client.get(
        f"/api/v1/organizations/{org_id}/findings",
        headers={"Authorization": f"Bearer {outsider.json()['access_token']}"},
    )

    assert response.status_code == 404


async def test_a_probabilistic_finding_carries_its_measurement(
    client: AsyncClient, strong_password: str
) -> None:
    """§7.1: the rate, the interval and the control travel with the finding,
    not only with the raw result."""
    org_id, target_id, headers = await _setup(client, strong_password, "i")
    await _run(client, org_id, target_id, headers)

    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    measured = [f for f in findings if f["attack_success_rate"]]

    assert measured, "the AI probes produce measured findings"
    for finding in measured:
        assert "ci95" in finding["attack_success_rate"]
        assert finding["control_success_rate"] is not None
        assert finding["stability"] in ("deterministic", "probabilistic", "single_shot")
