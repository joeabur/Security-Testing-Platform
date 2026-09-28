"""The native agent's tools ("Agent Phase 2": the first seven READ_ONLY
tools; "Agent Phase 3": the STANDARD and SENSITIVE tools alongside it):
`search_assets`, `get_asset`, `search_findings`, `get_finding`,
`get_scan_status`, `get_scan_results`, `get_workflow_status`,
`create_report`, `create_workflow`, `run_workflow`, `start_scan`.

Each tool wraps the exact query (or, for the writing tools, the exact
service call) its matching REST endpoint already runs, so these tests build
real rows via the ORM (the same pattern `test_integrations_api.py` uses)
and assert the tool's answer matches what that endpoint would return —
including that another organization's rows never leak through, the same
tenant-isolation guarantee the REST layer has, and that the two SENSITIVE
tools refuse the same things `POST /runs` and `POST /workflows/{id}/runs`
refuse.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.context import AgentContext
from app.core.agent.tools.assets import GET_ASSET, SEARCH_ASSETS
from app.core.agent.tools.contract import ToolExecutionError, ToolNotFoundError
from app.core.agent.tools.findings import GET_FINDING, SEARCH_FINDINGS
from app.core.agent.tools.registry import agent_tools, tools_by_name
from app.core.agent.tools.reports import CREATE_REPORT
from app.core.agent.tools.runs import GET_SCAN_RESULTS, GET_SCAN_STATUS
from app.core.agent.tools.scans import START_SCAN
from app.core.agent.tools.workflows import CREATE_WORKFLOW, GET_WORKFLOW_STATUS, RUN_WORKFLOW
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.probes.models import Category, Confidence, Severity
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.finding import Finding, FindingStatus, Stability
from app.models.organization import Role
from app.models.scan_result import ScanResultRecord
from app.models.workflow import Workflow, WorkflowRun


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record what `start_scan` would have queued instead of talking to a
    real Celery broker — same stub `test_runs_api.py` uses, against the
    same `app.core.runs.service.celery_app` the tool now shares with
    `POST /runs`."""
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
        "allowed_domains": ["acme-api.example.test"],
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
        "reference": "TICKET-1234",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=6)).isoformat(),
    }


def _finding_fields() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "category": Category.API_SECURITY,
        "probe_id": "AEGIS-API-050",
        "probe_version": "1.0.0",
        "surface": "GET /orders/{id}",
        "severity": Severity.CRITICAL,
        "severity_rationale": "authenticated cross-tenant read",
        "confidence": Confidence.HIGH,
        "stability": Stability.DETERMINISTIC,
        "risk_model": "aegis-ordinal-v1",
        "risk_score": 9,
        "description": "Another tenant's order is readable.",
        "impact": "Cross-tenant data exposure.",
        "remediation": "Authorize the object, not just the caller.",
        "first_seen": now,
        "last_seen": now,
    }


def _scan_result_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "result_code": "AEGIS-API-050",
        "title": "BOLA on /orders/{id}",
        "category": Category.API_SECURITY,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "endpoint": "GET /orders/{id}",
        "description": "d",
        "evidence": "e",
        "impact": "i",
        "remediation": "r",
        "probe_id": "AEGIS-API-050",
        "probe_version": "1.0.0",
    }
    base.update(overrides)
    return base


async def _org_and_target(
    client: AsyncClient, password: str, suffix: str
) -> tuple[uuid.UUID, uuid.UUID, dict[str, str]]:
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"agenttools{suffix}@example.test",
            "full_name": "Agent Tools Owner",
            "password": password,
        },
        headers={HEADER_NAME: anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Agent Tools Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "acme-api",
                "environment": "staging",
                "kind": "llm_app",
                "base_url": "https://acme-api.example.test",
            },
            headers=headers,
        )
    ).json()["id"]
    return uuid.UUID(org_id), uuid.UUID(target_id), headers


async def _authorized_target(
    client: AsyncClient, password: str, suffix: str
) -> tuple[uuid.UUID, uuid.UUID, dict[str, str]]:
    """An org/target ready for `start_scan`: rules of engagement and a
    currently-valid authorization grant, the same prerequisites
    `POST /runs` enforces — built the same way `test_runs_api.py`'s
    `_ready_target` is."""
    org_id, target_id, headers = await _org_and_target(client, password, suffix)
    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    roe = await client.put(f"{base}/rules-of-engagement", json=_roe_payload(), headers=headers)
    assert roe.status_code == 200, roe.text
    grant = await client.post(
        f"{base}/authorization", json=_authorization_payload(), headers=headers
    )
    assert grant.status_code == 201, grant.text
    return org_id, target_id, headers


async def _owner_user_id(db: AsyncSession, organization_id: uuid.UUID) -> uuid.UUID:
    """The real, FK-satisfying user id behind `_org_and_target`'s owner
    membership — needed by any tool test that writes a row with a
    `created_by_user_id`/`authorization_confirmed_by_user_id` foreign key,
    where a bare random uuid would violate the constraint."""
    from sqlalchemy import select

    from app.models.organization import Membership

    result = await db.execute(
        select(Membership.user_id).where(Membership.organization_id == organization_id).limit(1)
    )
    return result.scalar_one()


def _context(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    role: Role = Role.VIEWER,
    user_id: uuid.UUID | None = None,
) -> AgentContext:
    return AgentContext(
        organization_id=organization_id,
        user_id=user_id if user_id is not None else uuid.uuid4(),
        effective_role=role,
        db=db,
        request_id="test-request",
    )


# --- registry --------------------------------------------------------------


def test_the_registry_lists_every_tool_exactly_once() -> None:
    tools = agent_tools()
    names = [tool.name for tool in tools]
    assert len(names) == len(set(names))
    assert set(names) == {
        "search_assets",
        "get_asset",
        "search_findings",
        "get_finding",
        "get_scan_status",
        "get_scan_results",
        "get_workflow_status",
        "create_report",
        "create_workflow",
        "run_workflow",
        "start_scan",
    }
    assert tools_by_name()["search_assets"] is SEARCH_ASSETS


def test_only_start_scan_and_run_workflow_are_sensitive() -> None:
    """The three-tier classification is a closed decision, not a per-tool
    guess — pinned here so a future tool's risk level is a deliberate edit
    to this test, not a silent default."""
    sensitive = {t.name for t in agent_tools() if t.risk_level.value == "sensitive"}
    assert sensitive == {"start_scan", "run_workflow"}


# --- assets ------------------------------------------------------------


async def test_search_assets_lists_only_this_organizations_targets(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "a")
    other_org_id, _other_target, _other_headers = await _org_and_target(
        client, strong_password, "b"
    )

    result = await SEARCH_ASSETS.invoke(_context(db_session, org_id), {})

    assert [str(t.id) for t in result.targets] == [str(target_id)]
    assert all(str(t.organization_id) == str(org_id) for t in result.targets)

    other_result = await SEARCH_ASSETS.invoke(_context(db_session, other_org_id), {})
    assert str(target_id) not in [str(t.id) for t in other_result.targets]


async def test_get_asset_returns_the_target(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "c")

    result = await GET_ASSET.invoke(_context(db_session, org_id), {"target_id": str(target_id)})

    assert result.target.id == target_id
    assert result.target.name == "acme-api"


async def test_get_asset_raises_not_found_for_an_unknown_id(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, _target_id, _headers = await _org_and_target(client, strong_password, "d")

    with pytest.raises(ToolNotFoundError):
        await GET_ASSET.invoke(_context(db_session, org_id), {"target_id": str(uuid.uuid4())})


async def test_get_asset_does_not_leak_another_organizations_target(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, _target_id, _headers = await _org_and_target(client, strong_password, "e")
    _other_org_id, other_target_id, _other_headers = await _org_and_target(
        client, strong_password, "f"
    )

    with pytest.raises(ToolNotFoundError):
        await GET_ASSET.invoke(_context(db_session, org_id), {"target_id": str(other_target_id)})


# --- findings ------------------------------------------------------------


async def test_search_findings_filters_by_severity_and_status(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "g")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.flush()

    critical = Finding(
        organization_id=org_id,
        fingerprint="fp-1",
        title="Critical one",
        status=FindingStatus.NEW,
        first_run_id=run.id,
        last_run_id=run.id,
        **_finding_fields(),
    )
    low = Finding(
        organization_id=org_id,
        fingerprint="fp-2",
        title="Low one",
        status=FindingStatus.NEW,
        first_run_id=run.id,
        last_run_id=run.id,
        **{**_finding_fields(), "severity": Severity.LOW, "risk_score": 2},
    )
    db_session.add_all([critical, low])
    await db_session.commit()

    result = await SEARCH_FINDINGS.invoke(
        _context(db_session, org_id), {"severity": Severity.CRITICAL.value}
    )

    assert [f.title for f in result.findings] == ["Critical one"]


async def test_get_finding_returns_one_finding(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "h")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.flush()
    finding = Finding(
        organization_id=org_id,
        fingerprint="fp-3",
        title="A finding",
        status=FindingStatus.NEW,
        first_run_id=run.id,
        last_run_id=run.id,
        **_finding_fields(),
    )
    db_session.add(finding)
    await db_session.commit()

    result = await GET_FINDING.invoke(_context(db_session, org_id), {"finding_id": str(finding.id)})

    assert result.finding.title == "A finding"


async def test_get_finding_raises_not_found_across_organizations(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "i")
    other_org_id, _other_target_id, _other_headers = await _org_and_target(
        client, strong_password, "j"
    )
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.flush()
    finding = Finding(
        organization_id=org_id,
        fingerprint="fp-4",
        title="Org-scoped finding",
        status=FindingStatus.NEW,
        first_run_id=run.id,
        last_run_id=run.id,
        **_finding_fields(),
    )
    db_session.add(finding)
    await db_session.commit()

    with pytest.raises(ToolNotFoundError):
        await GET_FINDING.invoke(
            _context(db_session, other_org_id), {"finding_id": str(finding.id)}
        )


# --- runs ------------------------------------------------------------------


async def test_get_scan_status_returns_the_run(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "k")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.commit()

    result = await GET_SCAN_STATUS.invoke(_context(db_session, org_id), {"run_id": str(run.id)})

    assert result.run.id == run.id
    assert result.run.status == RunStatus.COMPLETED


async def test_get_scan_results_respects_include_informational(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "l")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.flush()
    db_session.add_all(
        [
            ScanResultRecord(run_id=run.id, organization_id=org_id, **_scan_result_fields()),
            ScanResultRecord(
                run_id=run.id,
                organization_id=org_id,
                **_scan_result_fields(
                    result_code="AEGIS-APPSEC-000",
                    title="Not tested: Semgrep",
                    severity=Severity.INFORMATIONAL,
                ),
            ),
        ]
    )
    await db_session.commit()

    everything = await GET_SCAN_RESULTS.invoke(
        _context(db_session, org_id), {"run_id": str(run.id)}
    )
    assert len(everything.results) == 2

    reportable_only = await GET_SCAN_RESULTS.invoke(
        _context(db_session, org_id),
        {"run_id": str(run.id), "include_informational": False},
    )
    assert len(reportable_only.results) == 1
    assert reportable_only.results[0].severity is Severity.CRITICAL


async def test_get_scan_status_raises_not_found_for_an_unknown_run(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, _target_id, _headers = await _org_and_target(client, strong_password, "m")

    with pytest.raises(ToolNotFoundError):
        await GET_SCAN_STATUS.invoke(_context(db_session, org_id), {"run_id": str(uuid.uuid4())})


# --- workflows -----------------------------------------------------------


async def test_get_workflow_status_returns_the_workflow_and_recent_runs(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "n")
    workflow = Workflow(
        organization_id=org_id, target_id=target_id, name="weekly-scan", trigger_kind="manual"
    )
    db_session.add(workflow)
    await db_session.flush()
    run = WorkflowRun(
        organization_id=org_id,
        workflow_id=workflow.id,
        status="completed",
        gate_passed=True,
    )
    db_session.add(run)
    await db_session.commit()

    result = await GET_WORKFLOW_STATUS.invoke(
        _context(db_session, org_id), {"workflow_id": str(workflow.id)}
    )

    assert result.workflow.name == "weekly-scan"
    assert len(result.recent_runs) == 1
    assert result.recent_runs[0].gate_passed is True


async def test_get_workflow_status_raises_not_found_across_organizations(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "o")
    other_org_id, _other_target_id, _other_headers = await _org_and_target(
        client, strong_password, "p"
    )
    workflow = Workflow(
        organization_id=org_id, target_id=target_id, name="weekly-scan", trigger_kind="manual"
    )
    db_session.add(workflow)
    await db_session.commit()

    with pytest.raises(ToolNotFoundError):
        await GET_WORKFLOW_STATUS.invoke(
            _context(db_session, other_org_id), {"workflow_id": str(workflow.id)}
        )


async def test_create_workflow_defines_a_new_workflow(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "q")
    user_id = await _owner_user_id(db_session, org_id)

    result = await CREATE_WORKFLOW.invoke(
        _context(db_session, org_id, role=Role.ADMIN, user_id=user_id),
        {"name": "agent-proposed", "target_id": str(target_id)},
    )

    assert result.workflow.name == "agent-proposed"
    assert result.workflow.target_id == target_id
    assert result.workflow.enabled is True


async def test_create_workflow_refuses_a_duplicate_name(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "r")
    db_session.add(
        Workflow(organization_id=org_id, target_id=target_id, name="dup", trigger_kind="manual")
    )
    await db_session.commit()

    with pytest.raises(ToolExecutionError):
        await CREATE_WORKFLOW.invoke(
            _context(db_session, org_id, role=Role.ADMIN),
            {"name": "dup", "target_id": str(target_id)},
        )


async def test_create_workflow_raises_not_found_for_an_unknown_target(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, _target_id, _headers = await _org_and_target(client, strong_password, "s")

    with pytest.raises(ToolNotFoundError):
        await CREATE_WORKFLOW.invoke(
            _context(db_session, org_id, role=Role.ADMIN),
            {"name": "orphan", "target_id": str(uuid.uuid4())},
        )


async def test_run_workflow_triggers_it_and_the_gate_passes_with_no_findings(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "t")
    workflow = Workflow(
        organization_id=org_id, target_id=target_id, name="on-demand", trigger_kind="manual"
    )
    db_session.add(workflow)
    await db_session.commit()

    result = await RUN_WORKFLOW.invoke(
        _context(db_session, org_id, role=Role.SECURITY_ENGINEER),
        {"workflow_id": str(workflow.id)},
    )

    assert result.run.workflow_id == workflow.id
    assert result.run.gate_passed is True


async def test_run_workflow_refuses_a_disabled_workflow(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "u")
    workflow = Workflow(
        organization_id=org_id,
        target_id=target_id,
        name="off",
        trigger_kind="manual",
        enabled=False,
    )
    db_session.add(workflow)
    await db_session.commit()

    with pytest.raises(ToolExecutionError):
        await RUN_WORKFLOW.invoke(
            _context(db_session, org_id, role=Role.SECURITY_ENGINEER),
            {"workflow_id": str(workflow.id)},
        )


async def test_run_workflow_raises_not_found_across_organizations(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "v")
    other_org_id, _other_target_id, _other_headers = await _org_and_target(
        client, strong_password, "w"
    )
    workflow = Workflow(
        organization_id=org_id, target_id=target_id, name="wf", trigger_kind="manual"
    )
    db_session.add(workflow)
    await db_session.commit()

    with pytest.raises(ToolNotFoundError):
        await RUN_WORKFLOW.invoke(
            _context(db_session, other_org_id, role=Role.SECURITY_ENGINEER),
            {"workflow_id": str(workflow.id)},
        )


# --- reports ---------------------------------------------------------------


async def test_create_report_renders_markdown_for_a_completed_run(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "x")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.commit()

    result = await CREATE_REPORT.invoke(
        _context(db_session, org_id, role=Role.ANALYST), {"run_id": str(run.id)}
    )

    assert result.report_format == "markdown"
    assert isinstance(result.content, str) and result.content


async def test_create_report_as_json_produces_canonical_json(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "y")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.COMPLETED)
    db_session.add(run)
    await db_session.commit()

    result = await CREATE_REPORT.invoke(
        _context(db_session, org_id, role=Role.ANALYST),
        {"run_id": str(run.id), "report_format": "json"},
    )

    assert result.report_format == "json"
    parsed = json.loads(result.content)
    assert parsed["tool"]["name"] == "Aegis AI Security"


async def test_create_report_refuses_a_run_that_has_not_started(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "z")
    run = AssessmentRun(organization_id=org_id, target_id=target_id, status=RunStatus.DRAFT)
    db_session.add(run)
    await db_session.commit()

    with pytest.raises(ToolExecutionError):
        await CREATE_REPORT.invoke(
            _context(db_session, org_id, role=Role.ANALYST), {"run_id": str(run.id)}
        )


async def test_create_report_raises_not_found_for_an_unknown_run(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, _target_id, _headers = await _org_and_target(client, strong_password, "aa")

    with pytest.raises(ToolNotFoundError):
        await CREATE_REPORT.invoke(
            _context(db_session, org_id, role=Role.ANALYST), {"run_id": str(uuid.uuid4())}
        )


# --- scans -------------------------------------------------------------


async def test_start_scan_queues_a_run_for_an_authorized_target(
    client: AsyncClient, strong_password: str, db_session: AsyncSession, _stub_broker: list[str]
) -> None:
    org_id, target_id, _headers = await _authorized_target(client, strong_password, "ab")
    user_id = await _owner_user_id(db_session, org_id)

    result = await START_SCAN.invoke(
        _context(db_session, org_id, role=Role.SECURITY_ENGINEER, user_id=user_id),
        {"target_id": str(target_id), "authorization_confirmed": True},
    )

    assert result.run.status == RunStatus.QUEUED
    assert _stub_broker == [str(result.run.id)]


async def test_start_scan_refuses_without_confirming_authorization(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, _headers = await _authorized_target(client, strong_password, "ac")

    with pytest.raises(ToolExecutionError):
        await START_SCAN.invoke(
            _context(db_session, org_id, role=Role.SECURITY_ENGINEER),
            {"target_id": str(target_id), "authorization_confirmed": False},
        )


async def test_start_scan_refuses_an_unauthorized_target(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """No rules of engagement and no authorization grant at all — the same
    refusal `POST /runs` gives, via the same `build_run_context` call."""
    org_id, target_id, _headers = await _org_and_target(client, strong_password, "ad")

    with pytest.raises(ToolExecutionError):
        await START_SCAN.invoke(
            _context(db_session, org_id, role=Role.SECURITY_ENGINEER),
            {"target_id": str(target_id), "authorization_confirmed": True},
        )


async def test_start_scan_raises_not_found_for_an_unknown_target(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, _target_id, _headers = await _org_and_target(client, strong_password, "ae")

    with pytest.raises(ToolNotFoundError):
        await START_SCAN.invoke(
            _context(db_session, org_id, role=Role.SECURITY_ENGINEER),
            {"target_id": str(uuid.uuid4()), "authorization_confirmed": True},
        )
