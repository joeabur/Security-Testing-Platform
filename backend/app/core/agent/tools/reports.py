"""`create_report` — renders one run's report on demand.

STANDARD tier: reading and rendering already-recorded results is passive
(nothing this tool does could not have been read a different way), but
producing a document meant to leave the organization is a step above a plain
read, matching the request's "Reports / passive discovery / approved
automation" tier.

There is nothing to persist here beyond what already exists: like
`GET /organizations/{id}/runs/{run_id}/report`, a report is rendered fresh
from the run's own recorded results every time — this tool calls the exact
same `build_report` the router does, so its output is only ever what a
human calling the API directly would also see, and there is no new report
table for the zero-persistence rule to need to exempt.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolExecutionError, ToolNotFoundError
from app.core.reporting.build import build_report, to_canonical_json
from app.core.reporting.render import render_markdown
from app.core.reporting.templates import Template
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.organization import Role
from app.models.target import Target

# A report from a run that never started would be a document full of zeroes
# that reads like a clean result — same refusal `GET .../report` makes.
_NOT_YET_RUN = frozenset({RunStatus.DRAFT, RunStatus.QUEUED})


class CreateReportParams(BaseModel):
    run_id: uuid.UUID
    report_format: Literal["markdown", "json"] = "markdown"
    template: Template = Template.TECHNICAL


class CreateReportResult(BaseModel):
    content: str
    report_format: Literal["markdown", "json"]
    template: Template


async def _create_report(ctx: AgentContext, params: CreateReportParams) -> CreateReportResult:
    run = (
        await ctx.db.execute(
            select(AssessmentRun).where(
                AssessmentRun.id == params.run_id,
                AssessmentRun.organization_id == ctx.organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise ToolNotFoundError(f"run {params.run_id} not found")
    if run.status in _NOT_YET_RUN:
        raise ToolExecutionError(f"run is {run.status.value}; there is nothing to report on yet")

    target = (
        await ctx.db.execute(
            select(Target)
            .where(Target.id == run.target_id)
            .options(
                selectinload(Target.authorization),
                selectinload(Target.rules_of_engagement),
                selectinload(Target.surface_endpoints),
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise ToolNotFoundError(f"target {run.target_id} not found")

    report = await build_report(ctx.db, run=run, target=target)
    content = (
        to_canonical_json(report)
        if params.report_format == "json"
        else render_markdown(report, params.template)
    )
    return CreateReportResult(
        content=content, report_format=params.report_format, template=params.template
    )


CREATE_REPORT = Tool(
    name="create_report",
    description="Render one assessment run's report as Markdown or canonical JSON.",
    input_model=CreateReportParams,
    output_model=CreateReportResult,
    risk_level=RiskLevel.STANDARD,
    minimum_role=Role.ANALYST,
    handler=_create_report,
    rate_limit_rule="agent_tool_call",
)
