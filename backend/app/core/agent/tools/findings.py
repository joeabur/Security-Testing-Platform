"""`search_findings` / `get_finding` — read-only tools over `Finding`.

Each runs the exact query `GET /findings`/`GET /findings/{id}` already
runs. Findings are never mutated here — status transitions are a STANDARD/
SENSITIVE-tier tool for a later phase, not something a read tool does.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolNotFoundError
from app.core.probes.models import Severity
from app.models.finding import Finding, FindingStatus
from app.models.organization import Role
from app.schemas.finding import FindingRead


class SearchFindingsParams(BaseModel):
    severity: Severity | None = None
    finding_status: FindingStatus | None = None
    run_id: uuid.UUID | None = None


class SearchFindingsResult(BaseModel):
    findings: list[FindingRead] = Field(default_factory=list)


async def _search_findings(ctx: AgentContext, params: SearchFindingsParams) -> SearchFindingsResult:
    query = select(Finding).where(Finding.organization_id == ctx.organization_id)
    if params.severity is not None:
        query = query.where(Finding.severity == params.severity)
    if params.finding_status is not None:
        query = query.where(Finding.status == params.finding_status)
    if params.run_id is not None:
        query = query.where(Finding.last_run_id == params.run_id)

    rows = await ctx.db.execute(query.order_by(Finding.risk_score.desc(), Finding.last_seen.desc()))
    return SearchFindingsResult(
        findings=[FindingRead.model_validate(row) for row in rows.scalars().all()]
    )


SEARCH_FINDINGS = Tool(
    name="search_findings",
    description=(
        "List findings in this organization, optionally filtered by severity, "
        "status, or the run that last saw them."
    ),
    input_model=SearchFindingsParams,
    output_model=SearchFindingsResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_search_findings,
    rate_limit_rule="agent_tool_call",
)


class GetFindingParams(BaseModel):
    finding_id: uuid.UUID


class GetFindingResult(BaseModel):
    finding: FindingRead


async def _get_finding(ctx: AgentContext, params: GetFindingParams) -> GetFindingResult:
    finding = (
        await ctx.db.execute(
            select(Finding).where(
                Finding.id == params.finding_id, Finding.organization_id == ctx.organization_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise ToolNotFoundError(f"finding {params.finding_id} not found")
    return GetFindingResult(finding=FindingRead.model_validate(finding))


GET_FINDING = Tool(
    name="get_finding",
    description="Get one finding by id, including its risk score and evidence reference.",
    input_model=GetFindingParams,
    output_model=GetFindingResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_get_finding,
    rate_limit_rule="agent_tool_call",
)
