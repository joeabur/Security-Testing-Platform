"""`get_scan_status` / `get_scan_results` — read-only tools over
`AssessmentRun`/`ScanResultRecord`.

Each runs the exact query `GET /runs/{id}`/`GET /runs/{id}/results`
already runs. Starting a run is a SENSITIVE-tier tool for a later phase —
these two only ever read what already happened.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolNotFoundError
from app.core.probes.models import Severity
from app.models.assessment_run import AssessmentRun
from app.models.organization import Role
from app.models.scan_result import ScanResultRecord
from app.schemas.run import RunRead, ScanResultRead


async def _load_run(ctx: AgentContext, run_id: uuid.UUID) -> AssessmentRun:
    run = (
        await ctx.db.execute(
            select(AssessmentRun).where(
                AssessmentRun.id == run_id, AssessmentRun.organization_id == ctx.organization_id
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise ToolNotFoundError(f"run {run_id} not found")
    return run


class GetScanStatusParams(BaseModel):
    run_id: uuid.UUID


class GetScanStatusResult(BaseModel):
    run: RunRead


async def _get_scan_status(ctx: AgentContext, params: GetScanStatusParams) -> GetScanStatusResult:
    run = await _load_run(ctx, params.run_id)
    return GetScanStatusResult(run=RunRead.model_validate(run))


GET_SCAN_STATUS = Tool(
    name="get_scan_status",
    description="Get one assessment run's status, progress, and halted/error reason if any.",
    input_model=GetScanStatusParams,
    output_model=GetScanStatusResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_get_scan_status,
    rate_limit_rule="agent_tool_call",
)


class GetScanResultsParams(BaseModel):
    run_id: uuid.UUID
    # Defaults to true, matching GET /runs/{id}/results: the informational
    # rows are where "this was not tested" lives, and a caller who filters
    # them out should do so knowingly rather than by default.
    include_informational: bool = True


class GetScanResultsResult(BaseModel):
    results: list[ScanResultRead] = Field(default_factory=list)


async def _get_scan_results(
    ctx: AgentContext, params: GetScanResultsParams
) -> GetScanResultsResult:
    await _load_run(ctx, params.run_id)

    query = select(ScanResultRecord).where(ScanResultRecord.run_id == params.run_id)
    if not params.include_informational:
        query = query.where(ScanResultRecord.severity != Severity.INFORMATIONAL)

    rows = await ctx.db.execute(query.order_by(ScanResultRecord.seq))
    return GetScanResultsResult(
        results=[ScanResultRead.model_validate(row) for row in rows.scalars().all()]
    )


GET_SCAN_RESULTS = Tool(
    name="get_scan_results",
    description="Get the raw scan results (including not-tested markers) for one assessment run.",
    input_model=GetScanResultsParams,
    output_model=GetScanResultsResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_get_scan_results,
    rate_limit_rule="agent_tool_call",
)
