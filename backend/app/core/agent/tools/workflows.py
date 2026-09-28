"""Tools over `Workflow`/`WorkflowRun`: read status, define one, trigger one.

`get_workflow_status` runs the exact query `GET /workflows/{id}` and
`GET /workflows/{id}/runs` already run — READ_ONLY.

`create_workflow` reuses `WorkflowCreate`, the same Pydantic model (and gate
validation) the router's request body uses, so a workflow the agent
proposes is validated identically to one a person submits through the API —
STANDARD, since defining what will gate a release is more than a read but
touches nothing yet.

`run_workflow` reuses `app.core.workflow.service.trigger_from`/`start`/
`finish`, the exact same functions `POST /workflows/{id}/runs` calls — the
plan's scan actions are queued through the same authorization check either
way. SENSITIVE: triggering a workflow can queue a real assessment run.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolExecutionError, ToolNotFoundError
from app.core.gate.model import GateConfigError
from app.core.workflow.service import finish, start, trigger_from
from app.models.organization import Role
from app.models.target import Target
from app.models.workflow import Workflow, WorkflowRun
from app.schemas.workflow import WorkflowCreate, WorkflowRead, WorkflowRunRead, WorkflowRunRequest

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


class CreateWorkflowResult(BaseModel):
    workflow: WorkflowRead


async def _create_workflow(ctx: AgentContext, params: WorkflowCreate) -> CreateWorkflowResult:
    target = (
        await ctx.db.execute(
            select(Target).where(
                Target.id == params.target_id, Target.organization_id == ctx.organization_id
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise ToolNotFoundError(f"target {params.target_id} not found")

    existing = (
        await ctx.db.execute(
            select(Workflow.id).where(
                Workflow.organization_id == ctx.organization_id, Workflow.name == params.name
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ToolExecutionError(f"a workflow named {params.name!r} already exists")

    workflow = Workflow(
        organization_id=ctx.organization_id,
        target_id=params.target_id,
        name=params.name,
        trigger_kind=params.trigger_kind.value,
        enabled=params.enabled,
        gate_config=params.gate_config,
        created_by_user_id=ctx.user_id,
    )
    ctx.db.add(workflow)
    await ctx.db.flush()
    await ctx.db.refresh(workflow)
    return CreateWorkflowResult(workflow=WorkflowRead.model_validate(workflow))


CREATE_WORKFLOW = Tool(
    name="create_workflow",
    description=("Define a new workflow for a target: what triggers it and what findings gate it."),
    input_model=WorkflowCreate,
    output_model=CreateWorkflowResult,
    risk_level=RiskLevel.STANDARD,
    minimum_role=Role.ADMIN,
    handler=_create_workflow,
    rate_limit_rule="agent_tool_call",
)


class RunWorkflowParams(WorkflowRunRequest):
    workflow_id: uuid.UUID


class RunWorkflowResult(BaseModel):
    run: WorkflowRunRead


async def _run_workflow(ctx: AgentContext, params: RunWorkflowParams) -> RunWorkflowResult:
    workflow = (
        await ctx.db.execute(
            select(Workflow).where(
                Workflow.id == params.workflow_id, Workflow.organization_id == ctx.organization_id
            )
        )
    ).scalar_one_or_none()
    if workflow is None:
        raise ToolNotFoundError(f"workflow {params.workflow_id} not found")
    if not workflow.enabled:
        raise ToolExecutionError("workflow is disabled")

    trigger = trigger_from(
        workflow,
        ref=params.ref,
        commit=params.commit,
        pull_number=params.pull_number,
        actor=str(ctx.user_id),
    )
    try:
        run, outcome = await start(ctx.db, workflow, trigger)
        await finish(ctx.db, run, workflow, outcome, actions_detail="triggered by the AI agent")
    except GateConfigError as exc:
        await ctx.db.rollback()
        raise ToolExecutionError(f"gate configuration is invalid: {exc}") from exc
    except ValueError as exc:
        await ctx.db.rollback()
        raise ToolExecutionError(str(exc)) from exc

    await ctx.db.flush()
    await ctx.db.refresh(run)
    return RunWorkflowResult(run=WorkflowRunRead.model_validate(run))


RUN_WORKFLOW = Tool(
    name="run_workflow",
    description="Trigger a workflow: run its plan, gate the findings, and record the result.",
    input_model=RunWorkflowParams,
    output_model=RunWorkflowResult,
    risk_level=RiskLevel.SENSITIVE,
    minimum_role=Role.SECURITY_ENGINEER,
    handler=_run_workflow,
    rate_limit_rule="agent_sensitive_tool_call",
)
