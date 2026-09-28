"""`get_workflow_status` — a read-only tool over `Workflow`/`WorkflowRun`.

Runs the exact query `GET /workflows/{id}` and `GET /workflows/{id}/runs`
already run. Triggering a workflow is a SENSITIVE-tier tool for a later
phase — this one only ever reads what a workflow is configured to do and
what its past runs decided.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolNotFoundError
from app.models.organization import Role
from app.models.workflow import Workflow, WorkflowRun
from app.schemas.workflow import WorkflowRead, WorkflowRunRead

_MAX_RECENT_RUNS = 10


class GetWorkflowStatusParams(BaseModel):
    workflow_id: uuid.UUID


class GetWorkflowStatusResult(BaseModel):
    workflow: WorkflowRead
    recent_runs: list[WorkflowRunRead] = Field(default_factory=list)


async def _get_workflow_status(
    ctx: AgentContext, params: GetWorkflowStatusParams
) -> GetWorkflowStatusResult:
    workflow = (
        await ctx.db.execute(
            select(Workflow).where(
                Workflow.id == params.workflow_id, Workflow.organization_id == ctx.organization_id
            )
        )
    ).scalar_one_or_none()
    if workflow is None:
        raise ToolNotFoundError(f"workflow {params.workflow_id} not found")

    runs = await ctx.db.execute(
        select(WorkflowRun)
        .where(
            WorkflowRun.organization_id == ctx.organization_id,
            WorkflowRun.workflow_id == params.workflow_id,
        )
        .order_by(WorkflowRun.created_at.desc())
        .limit(_MAX_RECENT_RUNS)
    )
    return GetWorkflowStatusResult(
        workflow=WorkflowRead.model_validate(workflow),
        recent_runs=[WorkflowRunRead.model_validate(run) for run in runs.scalars().all()],
    )


GET_WORKFLOW_STATUS = Tool(
    name="get_workflow_status",
    description=(
        "Get one workflow's configuration and its most recent runs, including "
        "whether each run's gate passed."
    ),
    input_model=GetWorkflowStatusParams,
    output_model=GetWorkflowStatusResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.ANALYST,
    handler=_get_workflow_status,
    rate_limit_rule="agent_tool_call",
)
