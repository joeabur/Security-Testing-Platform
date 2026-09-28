"""Remediation board and retest workflow (docs/BUILD_SPEC.md §26 Phase 9).

The acceptance criterion is that a finding can be assigned, moved through
remediation states, retested, and shown as reproduced or not reproduced with
evidence. These tests drive that whole path against the AI lab: the first run
finds real weaknesses, the retest runs against the same lab (still
vulnerable) and then against the hardened one (fixed), and the verdicts have
to come out the right way round.

The third verdict gets its own test. `not_tested` is what keeps a retest
honest when its probe never ran, and it is the one a careless implementation
would fold into "not reproduced" — reporting a fix nobody verified.
"""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
import respx
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.retest.service import baseline_of, mark_awaiting_retest, record_retest
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.models.assessment_run import AssessmentRun, RunKind, RunStatus
from app.models.finding import Finding, FindingStatus
from app.models.remediation import RemediationTask
from app.models.retest import RetestResult, RetestVerdict
from app.workers.tasks import execute_assessment_run
from tests.lab.ai_handlers import hardened_chat, vulnerable_chat
from tests.security.conftest import FakeDnsResolver

LAB_HOST = "retest-lab.test"
LAB_URL = f"https://{LAB_HOST}"


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "stub-task-id"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


def _worker_transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({LAB_HOST: ["203.0.113.40"]})
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
            "email": f"fixowner{suffix}@example.test",
            "full_name": "Fix Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Fix Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Retested assistant",
                "environment": "staging",
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
            "authorized_by_name": "Fix Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "FIX-1",
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


async def _retest(
    client: AsyncClient,
    org_id: str,
    target_id: str,
    headers: dict[str, str],
    finding_ids: list[str],
    *,
    handler,
) -> str:
    response = await client.post(
        f"/api/v1/organizations/{org_id}/retests",
        json={
            "target_id": target_id,
            "finding_ids": finding_ids,
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    run_id = response.json()["id"]
    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=handler)
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
    return run_id


async def _worst_finding(client: AsyncClient, org_id: str, headers: dict[str, str]) -> dict:
    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    assert findings
    return findings[0]


async def _injection_finding(client: AsyncClient, org_id: str, headers: dict[str, str]) -> dict:
    """A finding the hardened lab genuinely fixes.

    Chosen deliberately rather than taking the highest-risk row. Some findings
    are *supposed* to survive a hardened target: the excessive-agency ones are
    design review over declared tools, and the output-handling one reports
    deterministic reachability. A retest test that used those would be
    asserting the engine is wrong.
    """
    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    injection = [f for f in findings if f["probe_id"].startswith("ai.injection.direct")]
    assert injection, f"no direct-injection finding among {[f['probe_id'] for f in findings]}"
    return injection[0]


async def _declare_fixed(
    client: AsyncClient, org_id: str, finding_id: str, headers: dict[str, str]
) -> None:
    base = f"/api/v1/organizations/{org_id}/findings/{finding_id}/status"
    assert (
        await client.post(base, json={"status": "in_remediation"}, headers=headers)
    ).status_code == 200
    assert (
        await client.post(base, json={"status": "remediated"}, headers=headers)
    ).status_code == 200


# --- the remediation board ------------------------------------------------


async def test_a_finding_can_be_assigned_with_a_due_date(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "a")
    await _run(client, org_id, target_id, headers)
    finding = await _worst_finding(client, org_id, headers)

    due = (date.today() + timedelta(days=14)).isoformat()
    created = await client.put(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
        json={"due_date": due, "notes": "Separate instructions from data."},
        headers=headers,
    )
    assert created.status_code == 200
    assert created.json()["due_date"] == due
    # Summary defaults to the finding's own title rather than an empty string.
    assert created.json()["summary"] == finding["title"]

    board = (
        await client.get(f"/api/v1/organizations/{org_id}/remediation", headers=headers)
    ).json()
    assert len(board) == 1
    assert board[0]["finding_id"] == finding["id"]
    assert board[0]["severity"] == finding["severity"]
    assert board[0]["status"] == "new"


async def test_the_board_is_ordered_by_risk_not_by_filing_order(
    client: AsyncClient, strong_password: str
) -> None:
    """A board sorted by creation invites someone to work the top of the list
    instead of the top of the risk."""
    org_id, target_id, headers = await _setup(client, strong_password, "b")
    await _run(client, org_id, target_id, headers)
    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    assert len(findings) >= 2

    # File the lowest-risk one first.
    for finding in reversed(findings):
        await client.put(
            f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
            json={},
            headers=headers,
        )

    board = (
        await client.get(f"/api/v1/organizations/{org_id}/remediation", headers=headers)
    ).json()
    scores = [row["risk_score"] for row in board]
    assert scores == sorted(scores, reverse=True)


async def test_a_task_cannot_be_assigned_to_a_stranger(
    client: AsyncClient, strong_password: str
) -> None:
    """An assignee who cannot see the finding is useless on the board, and
    confirming that a user id exists is a small leak in itself."""
    org_id, target_id, headers = await _setup(client, strong_password, "c")
    await _run(client, org_id, target_id, headers)
    finding = await _worst_finding(client, org_id, headers)

    _outsider_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    outsider = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "stranger@example.test",
            "full_name": "Stranger",
            "password": strong_password,
        },
        headers={HEADER_NAME: _outsider_anon_token},
    )
    stranger_id = outsider.json()["user"]["id"]

    response = await client.put(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
        json={"assignee_user_id": stranger_id},
        headers=headers,
    )
    assert response.status_code == 422
    assert "not a member" in response.json()["error"]["message"]


async def test_a_viewer_can_read_the_board_but_not_change_it(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "d")
    await _run(client, org_id, target_id, headers)
    finding = await _worst_finding(client, org_id, headers)
    await client.put(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
        json={},
        headers=headers,
    )

    _viewer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    viewer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "boardviewer@example.test",
            "full_name": "Board Viewer",
            "password": strong_password,
        },
        headers={HEADER_NAME: _viewer_anon_token},
    )
    viewer_headers = {"Authorization": f"Bearer {viewer.json()['access_token']}"}
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "boardviewer@example.test", "role": "viewer"},
        headers=headers,
    )

    assert (
        await client.get(f"/api/v1/organizations/{org_id}/remediation", headers=viewer_headers)
    ).status_code == 200
    denied = await client.put(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
        json={"notes": "I should not be able to write this."},
        headers=viewer_headers,
    )
    assert denied.status_code == 403


# --- retest ---------------------------------------------------------------


async def test_a_weakness_that_is_still_there_is_reported_as_reproduced(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "e")
    await _run(client, org_id, target_id, headers)
    finding = await _injection_finding(client, org_id, headers)
    await client.put(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
        json={"notes": "claimed fixed"},
        headers=headers,
    )
    await _declare_fixed(client, org_id, finding["id"], headers)

    run_id = await _retest(
        client, org_id, target_id, headers, [finding["id"]], handler=vulnerable_chat
    )

    verdicts = (
        await client.get(
            f"/api/v1/organizations/{org_id}/runs/{run_id}/retest-results", headers=headers
        )
    ).json()
    assert len(verdicts) == 1
    assert verdicts[0]["verdict"] == "reproduced"
    assert verdicts[0]["before_evidence_ref"]
    assert verdicts[0]["after_evidence_ref"]

    after = (
        await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding['id']}", headers=headers
        )
    ).json()
    assert after["status"] == "confirmed"
    assert after["retest_result"] == "reproduced"


async def test_a_weakness_that_is_gone_is_reported_as_not_reproduced_and_closed(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The retest against the hardened lab. This is the direction an ordinary
    scan cannot express: absence of a finding is indistinguishable from a
    probe that never ran unless something recorded what it set out to check."""
    org_id, target_id, headers = await _setup(client, strong_password, "f")
    await _run(client, org_id, target_id, headers)
    finding = await _injection_finding(client, org_id, headers)
    await client.put(
        f"/api/v1/organizations/{org_id}/findings/{finding['id']}/remediation",
        json={"notes": "instructions separated from data"},
        headers=headers,
    )
    await _declare_fixed(client, org_id, finding["id"], headers)

    run_id = await _retest(
        client, org_id, target_id, headers, [finding["id"]], handler=hardened_chat
    )

    verdicts = (
        await client.get(
            f"/api/v1/organizations/{org_id}/runs/{run_id}/retest-results", headers=headers
        )
    ).json()
    assert [v["verdict"] for v in verdicts] == ["not_reproduced"]
    # The before digest survives; there is no after, because nothing was seen.
    assert verdicts[0]["before_evidence_ref"]
    assert verdicts[0]["after_evidence_ref"] is None

    after = (
        await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding['id']}", headers=headers
        )
    ).json()
    assert after["status"] == "closed"
    assert after["retest_result"] == "not_reproduced"

    task = (
        await db_session.execute(
            select(RemediationTask).where(RemediationTask.finding_id == uuid.UUID(finding["id"]))
        )
    ).scalar_one()
    assert task.closed_at is not None, "a verified fix should close its task"


async def test_a_retest_needs_its_own_authorization_confirmation(
    client: AsyncClient, strong_password: str
) -> None:
    """Having scanned something once is not standing permission to scan it
    again."""
    org_id, target_id, headers = await _setup(client, strong_password, "g")
    await _run(client, org_id, target_id, headers)
    finding = await _worst_finding(client, org_id, headers)

    response = await client.post(
        f"/api/v1/organizations/{org_id}/retests",
        json={"target_id": target_id, "finding_ids": [finding["id"]]},
        headers=headers,
    )
    assert response.status_code == 422
    assert "authorization_confirmed" in response.json()["error"]["message"]


async def test_a_retest_naming_an_unknown_finding_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    """Refused rather than silently narrowed: a retest that drops findings
    reports a clean result for work it never checked."""
    org_id, target_id, headers = await _setup(client, strong_password, "h")
    await _run(client, org_id, target_id, headers)
    finding = await _worst_finding(client, org_id, headers)

    response = await client.post(
        f"/api/v1/organizations/{org_id}/retests",
        json={
            "target_id": target_id,
            "finding_ids": [finding["id"], str(uuid.uuid4())],
            "authorization_confirmed": True,
        },
        headers=headers,
    )
    assert response.status_code == 404
    assert "unknown finding" in response.json()["error"]["message"]


async def test_an_analyst_cannot_start_a_retest(client: AsyncClient, strong_password: str) -> None:
    """A retest reaches the target, so it needs the same role a scan does."""
    org_id, target_id, headers = await _setup(client, strong_password, "i")
    await _run(client, org_id, target_id, headers)
    finding = await _worst_finding(client, org_id, headers)

    _analyst_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    analyst = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "retestanalyst@example.test",
            "full_name": "Retest Analyst",
            "password": strong_password,
        },
        headers={HEADER_NAME: _analyst_anon_token},
    )
    analyst_headers = {"Authorization": f"Bearer {analyst.json()['access_token']}"}
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "retestanalyst@example.test", "role": "analyst"},
        headers=headers,
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/retests",
        json={
            "target_id": target_id,
            "finding_ids": [finding["id"]],
            "authorization_confirmed": True,
        },
        headers=analyst_headers,
    )
    assert response.status_code == 403


async def test_the_retest_report_states_the_verdicts(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "j")
    await _run(client, org_id, target_id, headers)
    finding = await _injection_finding(client, org_id, headers)
    await _declare_fixed(client, org_id, finding["id"], headers)
    run_id = await _retest(
        client, org_id, target_id, headers, [finding["id"]], handler=hardened_chat
    )

    report = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/report", headers=headers)
    ).text
    assert "## Retest results" in report
    assert "not_reproduced" in report
    assert "**Not** evidence of a fix" in report  # the not_tested row is always shown


# --- the verdict that keeps the other two honest --------------------------


async def test_a_probe_that_did_not_run_is_not_tested_rather_than_fixed(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """Driven at the service, so the "probe never ran" case is exact.

    A retest whose probe was refused by scope, held back by safe mode, or
    simply not applicable to the target as configured produces no result for
    it. Reading that silence as a fix is the single worst thing this workflow
    could do.
    """
    org_id, target_id, headers = await _setup(client, strong_password, "k")
    await _run(client, org_id, target_id, headers)
    finding_id = (await _worst_finding(client, org_id, headers))["id"]

    finding = (
        await db_session.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    ).scalar_one()
    finding.status = FindingStatus.RETEST_REQUIRED
    finding.probe_id = "ai.probe.that.was.never.run"
    await db_session.commit()

    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
        kind=RunKind.RETEST,
        profile="full",
        safe_mode=True,
        retest_baseline=baseline_of([finding]),
    )
    db_session.add(run)
    await db_session.commit()

    verdicts = await record_retest(db_session, run=run)
    await db_session.commit()

    assert [v.verdict for v in verdicts] == [RetestVerdict.NOT_TESTED]
    assert "Not looking is not a fix" in verdicts[0].detail
    # And the status is untouched: nothing was learned, so nothing moves.
    assert finding.status is FindingStatus.RETEST_REQUIRED
    assert finding.retest_result == "not_tested"


async def test_a_halted_retest_reports_nothing_as_fixed(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "l")
    await _run(client, org_id, target_id, headers)
    finding_id = (await _worst_finding(client, org_id, headers))["id"]
    finding = (
        await db_session.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    ).scalar_one()
    finding.status = FindingStatus.RETEST_REQUIRED
    await db_session.commit()

    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
        kind=RunKind.RETEST,
        profile="full",
        safe_mode=True,
        halted_reason="request_budget_exhausted",
        retest_baseline=baseline_of([finding]),
    )
    db_session.add(run)
    await db_session.commit()

    verdicts = await record_retest(db_session, run=run)
    assert [v.verdict for v in verdicts] == [RetestVerdict.NOT_TESTED]
    assert "stopped early" in verdicts[0].detail
    assert finding.status is FindingStatus.RETEST_REQUIRED


def test_requesting_a_retest_moves_only_findings_claimed_fixed() -> None:
    """§11: `remediated` leads nowhere except a retest, and requesting one is
    where that transition belongs. Something still in remediation has not been
    claimed fixed by anyone, so the platform does not claim it for them."""
    remediated = Finding(status=FindingStatus.REMEDIATED)
    in_progress = Finding(status=FindingStatus.IN_REMEDIATION)
    confirmed = Finding(status=FindingStatus.CONFIRMED)

    moved = mark_awaiting_retest([remediated, in_progress, confirmed], None)

    assert moved == [remediated]
    assert remediated.status is FindingStatus.RETEST_REQUIRED
    assert in_progress.status is FindingStatus.IN_REMEDIATION
    assert confirmed.status is FindingStatus.CONFIRMED


async def test_the_baseline_is_a_snapshot_not_a_live_read(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The evidence digest from *before* only exists if it was written down:
    the retest overwrites it on the finding when the weakness reproduces."""
    org_id, target_id, headers = await _setup(client, strong_password, "m")
    await _run(client, org_id, target_id, headers)
    finding_id = (await _worst_finding(client, org_id, headers))["id"]
    finding = (
        await db_session.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    ).scalar_one()

    snapshot = baseline_of([finding])
    original_ref = finding.evidence_ref
    assert snapshot[0]["evidence_ref"] == original_ref

    finding.evidence_ref = "sha256:" + "9" * 64
    await db_session.commit()

    # The snapshot is unmoved by the later write.
    assert snapshot[0]["evidence_ref"] == original_ref


async def test_retest_results_are_not_visible_across_organizations(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "n")
    await _run(client, org_id, target_id, headers)
    finding = await _injection_finding(client, org_id, headers)
    await _declare_fixed(client, org_id, finding["id"], headers)
    run_id = await _retest(
        client, org_id, target_id, headers, [finding["id"]], handler=hardened_chat
    )
    _, _, outsider = await _setup(client, strong_password, "o")

    assert (
        await client.get(
            f"/api/v1/organizations/{org_id}/runs/{run_id}/retest-results", headers=outsider
        )
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/organizations/{org_id}/remediation", headers=outsider)
    ).status_code == 404


async def test_a_retest_run_is_a_run_with_the_same_safety_record(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """A retest reuses the run table precisely so it inherits the
    authorization record, the pinned digests and the audit trail rather than
    re-earning them."""
    org_id, target_id, headers = await _setup(client, strong_password, "p")
    first = await _run(client, org_id, target_id, headers)
    finding = await _injection_finding(client, org_id, headers)
    await _declare_fixed(client, org_id, finding["id"], headers)
    run_id = await _retest(
        client, org_id, target_id, headers, [finding["id"]], handler=hardened_chat
    )

    run = (
        await db_session.execute(select(AssessmentRun).where(AssessmentRun.id == uuid.UUID(run_id)))
    ).scalar_one()
    assert run.kind is RunKind.RETEST
    assert run.retest_of_run_id == uuid.UUID(first)
    assert run.authorization_digest and run.roe_digest
    assert run.authorization_confirmed_at is not None

    stored = (
        (
            await db_session.execute(
                select(RetestResult).where(RetestResult.run_id == uuid.UUID(run_id))
            )
        )
        .scalars()
        .all()
    )
    assert len(stored) == 1
