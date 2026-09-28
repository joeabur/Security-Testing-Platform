"""The native agent's first READ_ONLY tools (pentest-module-adjacent
"Agent Phase 2"): `search_assets`, `get_asset`, `search_findings`,
`get_finding`, `get_scan_status`, `get_scan_results`, `get_workflow_status`.

Each tool wraps the exact query its matching REST endpoint already runs,
so these tests build real rows via the ORM (the same pattern
`test_integrations_api.py` uses) and assert the tool's answer matches what
that endpoint would return — including that another organization's rows
never leak through, the same tenant-isolation guarantee the REST layer has.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.context import AgentContext
from app.core.agent.tools.assets import GET_ASSET, SEARCH_ASSETS
from app.core.agent.tools.contract import ToolNotFoundError
from app.core.agent.tools.findings import GET_FINDING, SEARCH_FINDINGS
from app.core.agent.tools.registry import agent_tools, tools_by_name
from app.core.agent.tools.runs import GET_SCAN_RESULTS, GET_SCAN_STATUS
from app.core.agent.tools.workflows import GET_WORKFLOW_STATUS
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.probes.models import Category, Confidence, Severity
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.finding import Finding, FindingStatus, Stability
from app.models.organization import Role
from app.models.scan_result import ScanResultRecord
from app.models.workflow import Workflow, WorkflowRun


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


def _context(db: AsyncSession, organization_id: uuid.UUID) -> AgentContext:
    return AgentContext(
        organization_id=organization_id,
        user_id=uuid.uuid4(),
        effective_role=Role.VIEWER,
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
    }
    assert tools_by_name()["search_assets"] is SEARCH_ASSETS


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
