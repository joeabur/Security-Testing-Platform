"""`app/core/agent/runtime.py`: executing a `Plan` against `Investigation`
state — completion, an unknown tool, a role the caller lacks, an
unapproved SENSITIVE tool (pause, then resume), a tool's own refusal, and
the optional evidence-fenced summary.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.context import AgentContext
from app.core.agent.investigation import Investigation, InvestigationStatus
from app.core.agent.planner import Plan, PlanStep
from app.core.agent.runtime import StepStatus, run_plan
from app.core.agent.tools.contract import RiskLevel, Tool, ToolExecutionError
from app.core.assistant.fake import FakeProvider
from app.models.organization import Role


class _Params(BaseModel):
    pass


class _Result(BaseModel):
    value: str = "ok"


async def _ok_handler(ctx: AgentContext, params: _Params) -> _Result:
    return _Result()


async def _fail_handler(ctx: AgentContext, params: _Params) -> _Result:
    raise ToolExecutionError("boom")


OK_TOOL = Tool(
    name="ok_tool",
    description="always succeeds",
    input_model=_Params,
    output_model=_Result,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_ok_handler,
)

FAIL_TOOL = Tool(
    name="fail_tool",
    description="always refuses",
    input_model=_Params,
    output_model=_Result,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_fail_handler,
)

SENSITIVE_TOOL = Tool(
    name="sensitive_tool",
    description="needs approval",
    input_model=_Params,
    output_model=_Result,
    risk_level=RiskLevel.SENSITIVE,
    minimum_role=Role.SECURITY_ENGINEER,
    handler=_ok_handler,
)

ADMIN_TOOL = Tool(
    name="admin_tool",
    description="needs an admin",
    input_model=_Params,
    output_model=_Result,
    risk_level=RiskLevel.STANDARD,
    minimum_role=Role.ADMIN,
    handler=_ok_handler,
)

TOOLS = {t.name: t for t in (OK_TOOL, FAIL_TOOL, SENSITIVE_TOOL, ADMIN_TOOL)}


def _context(
    db: AsyncSession, *, role: Role = Role.VIEWER, provider: object | None = None
) -> AgentContext:
    return AgentContext(
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        effective_role=role,
        db=db,
        request_id="test-request",
        provider=provider,  # type: ignore[arg-type]
    )


def _investigation(ctx: AgentContext) -> Investigation:
    return Investigation.start(organization_id=ctx.organization_id, user_id=ctx.user_id)


async def test_run_plan_executes_every_step_and_completes(db_session: AsyncSession) -> None:
    ctx = _context(db_session)
    plan = Plan(steps=(PlanStep("ok_tool", {}), PlanStep("ok_tool", {})))

    result = await run_plan(ctx, plan, TOOLS, _investigation(ctx))

    assert result.investigation.status is InvestigationStatus.COMPLETED
    assert [o.status for o in result.outcomes] == [StepStatus.OK, StepStatus.OK]
    assert result.investigation.plan_step_index == 2


async def test_run_plan_stops_at_an_unknown_tool(db_session: AsyncSession) -> None:
    ctx = _context(db_session)
    plan = Plan(steps=(PlanStep("does_not_exist", {}),))

    result = await run_plan(ctx, plan, TOOLS, _investigation(ctx))

    assert result.investigation.status is InvestigationStatus.FAILED
    assert result.outcomes[0].status is StepStatus.TOOL_NOT_FOUND


async def test_run_plan_stops_at_a_role_the_caller_lacks(db_session: AsyncSession) -> None:
    ctx = _context(db_session, role=Role.VIEWER)
    plan = Plan(steps=(PlanStep("admin_tool", {}),))

    result = await run_plan(ctx, plan, TOOLS, _investigation(ctx))

    assert result.investigation.status is InvestigationStatus.FAILED
    assert result.outcomes[0].status is StepStatus.PERMISSION_DENIED


async def test_run_plan_pauses_at_an_unapproved_sensitive_tool_then_resumes(
    db_session: AsyncSession,
) -> None:
    ctx = _context(db_session, role=Role.SECURITY_ENGINEER)
    plan = Plan(
        steps=(PlanStep("ok_tool", {}), PlanStep("sensitive_tool", {}), PlanStep("ok_tool", {}))
    )
    investigation = _investigation(ctx)

    paused = await run_plan(ctx, plan, TOOLS, investigation)

    assert paused.investigation.status is InvestigationStatus.AWAITING_APPROVAL
    assert [o.status for o in paused.outcomes] == [StepStatus.OK, StepStatus.APPROVAL_REQUIRED]
    assert paused.investigation.plan_step_index == 1
    assert paused.investigation.pending_approval is not None
    assert paused.investigation.pending_approval.tool_name == "sensitive_tool"

    resumed = await run_plan(
        ctx, plan, TOOLS, paused.investigation, approved_tool_names=frozenset({"sensitive_tool"})
    )

    assert resumed.investigation.status is InvestigationStatus.COMPLETED
    assert [o.status for o in resumed.outcomes] == [StepStatus.OK, StepStatus.OK]
    assert resumed.investigation.pending_approval is None


async def test_run_plan_stops_at_a_tools_own_refusal(db_session: AsyncSession) -> None:
    ctx = _context(db_session)
    plan = Plan(steps=(PlanStep("fail_tool", {}),))

    result = await run_plan(ctx, plan, TOOLS, _investigation(ctx))

    assert result.investigation.status is InvestigationStatus.FAILED
    assert result.outcomes[0].status is StepStatus.EXECUTION_ERROR
    assert result.outcomes[0].error == "boom"


async def test_run_plan_produces_a_summary_when_requested(db_session: AsyncSession) -> None:
    provider = FakeProvider()
    ctx = _context(db_session, provider=provider)
    plan = Plan(steps=(PlanStep("ok_tool", {}),))

    result = await run_plan(ctx, plan, TOOLS, _investigation(ctx), summarize=True)

    assert result.summary is not None
    system, prompt = provider.calls[-1]
    assert "<<<KERVY-EVIDENCE-BEGIN>>>" in prompt
    assert "<<<KERVY-EVIDENCE-END>>>" in prompt


async def test_run_plan_does_not_summarize_without_a_provider(db_session: AsyncSession) -> None:
    ctx = _context(db_session, provider=None)
    plan = Plan(steps=(PlanStep("ok_tool", {}),))

    result = await run_plan(ctx, plan, TOOLS, _investigation(ctx), summarize=True)

    assert result.summary is None


async def test_run_plan_on_an_empty_plan_completes_immediately(db_session: AsyncSession) -> None:
    ctx = _context(db_session)

    result = await run_plan(ctx, Plan(steps=()), TOOLS, _investigation(ctx))

    assert result.investigation.status is InvestigationStatus.COMPLETED
    assert result.outcomes == []
