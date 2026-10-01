"""The security-operations dashboard summary (pentest module, Phase 10).

Same discipline as `tests/test_web.py`'s own "every number is a real query"
test: assert against what the endpoint actually returns, not against the
query functions in isolation, and cover the case that matters most for a
cross-org aggregate — a second organization's rows must never leak in.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.probes.models import Category, Confidence, Severity
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.finding import Finding, FindingStatus, Stability
from app.models.remediation import RemediationTask
from app.models.scan_result import ScanResultRecord
from app.models.workflow import Workflow, WorkflowRun

LAB_URL = "https://dashboard-api.lab.test"


async def _setup(
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, dict[str, str]]:
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    registered = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"dashapi{suffix}@example.test",
            "full_name": "Dash API Owner",
            "password": password,
        },
        headers={HEADER_NAME: anon_token},
    )
    assert registered.status_code == 201, registered.text
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}

    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Dash API Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Dashboard API lab",
                "environment": "test",
                "kind": "llm_app",
                "base_url": LAB_URL,
            },
            headers=headers,
        )
    ).json()["id"]
    return org_id, target_id, headers


def _finding(org_id: str, target_id: str, **overrides: object) -> Finding:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "organization_id": uuid.UUID(org_id),
        "target_id": uuid.UUID(target_id),
        "fingerprint": "sha256:" + uuid.uuid4().hex * 2,
        "title": "Prompt injection overrides the system instruction",
        "category": Category.AI_SECURITY,
        "probe_id": "ai.llm01.direct",
        "probe_version": "1.0.0",
        "surface": "/api/chat",
        "severity": Severity.CRITICAL,
        "severity_rationale": "Marker recovered in 9 of 10 trials.",
        "confidence": Confidence.HIGH,
        "stability": Stability.DETERMINISTIC,
        "risk_model": "kervy-v1",
        "risk_score": 8.7,
        "risk_inputs": {},
        "description": "d",
        "impact": "i",
        "remediation": "r",
        "reproduction": [],
        "mappings": {},
        "mapping_versions": {},
        "status": FindingStatus.NEW,
        "first_seen": now,
        "last_seen": now,
        "times_seen": 1,
    }
    values.update(overrides)
    return Finding(**values)


def _run(org_id: str, target_id: str, **overrides: object) -> AssessmentRun:
    values: dict[str, object] = {
        "organization_id": uuid.UUID(org_id),
        "target_id": uuid.UUID(target_id),
        "status": RunStatus.COMPLETED,
        "profile": "connectivity",
        "safe_mode": True,
        "checks_total": 1,
        "checks_completed": 1,
        "findings_reported": 0,
    }
    values.update(overrides)
    return AssessmentRun(**values)


def _scan_result(
    org_id: str, run_id: uuid.UUID, probe_id: str, **overrides: object
) -> ScanResultRecord:
    values: dict[str, object] = {
        "organization_id": uuid.UUID(org_id),
        "run_id": run_id,
        "result_code": "r-1",
        "title": "A real result",
        "category": Category.AI_SECURITY,
        "severity": Severity.LOW,
        "confidence": Confidence.HIGH,
        "endpoint": "/api/chat",
        "description": "d",
        "evidence": "e",
        "impact": "i",
        "remediation": "r",
        "probe_id": probe_id,
        "probe_version": "1.0.0",
        "frameworks": [],
        "reproduction": [],
    }
    values.update(overrides)
    return ScanResultRecord(**values)


async def test_empty_organization_has_a_zeroed_summary(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/summary", headers=headers
    )
    assert response.status_code == 200
    body = response.json()

    assert body["targets"] == 1
    assert body["open_findings"] == 0
    assert body["open_findings_by_severity"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    assert body["remediation"] == {"open": 0, "overdue": 0}
    assert body["pending_retests"] == 0
    assert body["recent_runs"] == []
    assert body["recent_workflow_runs"] == []
    assert body["top_findings"] == []
    # Every pillar named, none tested — the §27 "enumerate, do not assemble"
    # rule this reuses from `_pillar_coverage` still holds for the org-wide
    # rollup.
    assert len(body["pillar_coverage"]) == 13
    assert all(row["tested"] is False for row in body["pillar_coverage"])


async def test_summary_reflects_findings_runs_remediation_and_coverage(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    run = _run(org_id, target_id)
    db_session.add(run)
    await db_session.flush()

    # Two open findings (critical, high), one accepted-risk (excluded from
    # "open"), one retest_required (counted separately as a pending retest).
    open_critical = _finding(org_id, target_id, severity=Severity.CRITICAL, risk_score=9.0)
    open_high = _finding(org_id, target_id, severity=Severity.HIGH, risk_score=6.0)
    accepted = _finding(
        org_id,
        target_id,
        severity=Severity.LOW,
        risk_score=1.0,
        status=FindingStatus.ACCEPTED_RISK,
    )
    awaiting_retest = _finding(
        org_id,
        target_id,
        severity=Severity.MEDIUM,
        risk_score=4.0,
        status=FindingStatus.RETEST_REQUIRED,
    )
    db_session.add_all([open_critical, open_high, accepted, awaiting_retest])
    await db_session.flush()  # assigns .id (server-side default) before it's referenced below

    # A remediation task, overdue.
    db_session.add(
        RemediationTask(
            organization_id=uuid.UUID(org_id),
            finding_id=open_critical.id,
            summary="Fix the injection",
            due_date=date.today() - timedelta(days=3),
        )
    )

    # A workflow + one of its runs.
    workflow = Workflow(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        name="Staging gate",
        trigger_kind="manual",
        enabled=True,
    )
    db_session.add(workflow)
    await db_session.flush()
    db_session.add(
        WorkflowRun(
            organization_id=uuid.UUID(org_id),
            workflow_id=workflow.id,
            status="completed",
            gate_passed=False,
        )
    )

    # Scan results covering SAST and AI security, plus one "Not tested:"
    # marker that must not count as coverage.
    db_session.add_all(
        [
            _scan_result(org_id, run.id, "appsec.sast.bandit.b602"),
            _scan_result(org_id, run.id, "ai.llm01.direct"),
            _scan_result(org_id, run.id, "dast.zap.xss", title="Not tested: DAST"),
        ]
    )
    await db_session.commit()

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/summary", headers=headers
    )
    assert response.status_code == 200
    body = response.json()

    # Three, not two: `retest_required` is deliberately not in CLOSED_STATUSES
    # (Finding's own status machine — a remediation is a claim until a retest
    # checks it), so `awaiting_retest` still counts as open work.
    assert body["open_findings"] == 3
    assert body["open_findings_by_severity"]["critical"] == 1
    assert body["open_findings_by_severity"]["high"] == 1
    assert body["pending_retests"] == 1
    assert body["remediation"] == {"open": 1, "overdue": 1}

    assert len(body["recent_runs"]) == 1
    assert body["recent_runs"][0]["target_name"] == "Dashboard API lab"

    assert len(body["recent_workflow_runs"]) == 1
    assert body["recent_workflow_runs"][0]["workflow_name"] == "Staging gate"
    assert body["recent_workflow_runs"][0]["gate_passed"] is False

    top_ids = {row["id"] for row in body["top_findings"]}
    assert str(open_critical.id) in top_ids
    assert str(open_high.id) in top_ids
    assert str(accepted.id) not in top_ids  # closed statuses are not "open work"
    # Worst first: the risk model's own score decides order, not severity alone.
    assert body["top_findings"][0]["id"] == str(open_critical.id)

    coverage = {row["pillar"]: row["tested"] for row in body["pillar_coverage"]}
    assert coverage["SAST"] is True
    assert coverage["AI security"] is True
    assert coverage["DAST"] is False  # the "Not tested:" marker must not count
    assert coverage["Cloud"] is False


async def test_summary_does_not_leak_another_organizations_data(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    org_a, target_a, headers_a = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    org_b, target_b, _headers_b = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    db_session.add(_finding(org_b, target_b, severity=Severity.CRITICAL, risk_score=9.9))
    await db_session.commit()

    response = await client.get(
        f"/api/v1/organizations/{org_a}/dashboard/summary", headers=headers_a
    )
    assert response.status_code == 200
    body = response.json()
    assert body["open_findings"] == 0
    assert body["top_findings"] == []


async def test_summary_is_404_for_a_non_member(client: AsyncClient, strong_password: str) -> None:
    org_id, _, _ = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    _, _, outsider_headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/summary", headers=outsider_headers
    )
    assert response.status_code == 404


async def test_empty_organization_has_an_empty_trend(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/findings-trend", headers=headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["days"] == 30
    assert body["points"] == []


async def test_trend_buckets_by_day_and_severity_within_the_window(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    today = datetime.now(UTC)
    yesterday = today - timedelta(days=1)
    outside_window = today - timedelta(days=90)

    db_session.add_all(
        [
            _finding(
                org_id, target_id, severity=Severity.CRITICAL, first_seen=today, last_seen=today
            ),
            _finding(
                org_id, target_id, severity=Severity.HIGH, first_seen=today, last_seen=today
            ),
            _finding(
                org_id,
                target_id,
                severity=Severity.CRITICAL,
                first_seen=yesterday,
                last_seen=yesterday,
            ),
            # Outside the default 30-day window — must not appear.
            _finding(
                org_id,
                target_id,
                severity=Severity.CRITICAL,
                first_seen=outside_window,
                last_seen=outside_window,
            ),
        ]
    )
    await db_session.commit()

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/findings-trend", headers=headers
    )
    assert response.status_code == 200
    body = response.json()

    by_day: dict[str, dict[str, int]] = {}
    for point in body["points"]:
        by_day.setdefault(point["day"], {})[point["severity"]] = point["count"]

    assert by_day[today.date().isoformat()]["CRITICAL"] == 1
    assert by_day[today.date().isoformat()]["HIGH"] == 1
    assert by_day[yesterday.date().isoformat()]["CRITICAL"] == 1
    assert outside_window.date().isoformat() not in by_day


async def test_trend_days_query_param_is_clamped(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/findings-trend?days=9000", headers=headers
    )
    assert response.status_code == 422


async def test_trend_does_not_leak_another_organizations_data(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    org_a, _, headers_a = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    org_b, target_b, _headers_b = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    db_session.add(_finding(org_b, target_b, severity=Severity.CRITICAL))
    await db_session.commit()

    response = await client.get(
        f"/api/v1/organizations/{org_a}/dashboard/findings-trend", headers=headers_a
    )
    assert response.status_code == 200
    assert response.json()["points"] == []


async def test_trend_is_404_for_a_non_member(client: AsyncClient, strong_password: str) -> None:
    org_id, _, _ = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    _, _, outsider_headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(
        f"/api/v1/organizations/{org_id}/dashboard/findings-trend", headers=outsider_headers
    )
    assert response.status_code == 404
