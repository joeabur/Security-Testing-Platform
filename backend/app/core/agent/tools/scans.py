"""`start_scan` — queues an assessment run against an authorized target.

SENSITIVE: the one tool in this phase that sends real requests at a target,
via the exact same authorization and scope checks `POST /runs` enforces.
Reuses `app.core.orchestrator.context_builder.build_run_context` for the
authorization/RoE validation and `app.core.runs.service.queue_run` to queue
it — the same two calls the router makes, in the same order, so an
AI-initiated scan can never start under weaker authorization than a human
clicking the same button would need.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolExecutionError, ToolNotFoundError
from app.core.orchestrator.context_builder import build_run_context
from app.core.runs.service import queue_run
from app.core.scope.errors import AuthorizationRequiredError, RoEValidationError
from app.models.organization import Role
from app.models.target import Target
from app.schemas.run import RunRead


class StartScanParams(BaseModel):
    target_id: uuid.UUID
    profile: str = Field(default="connectivity", max_length=50)
    safe_mode: bool = True
    # Same affirmation `RunCreate.authorization_confirmed` requires of a
    # human caller — an AI-composed request does not get to skip it.
    authorization_confirmed: bool = False


class StartScanResult(BaseModel):
    run: RunRead


async def _start_scan(ctx: AgentContext, params: StartScanParams) -> StartScanResult:
    target = (
        await ctx.db.execute(
            select(Target)
            .where(Target.id == params.target_id, Target.organization_id == ctx.organization_id)
            .options(
                selectinload(Target.authorization),
                selectinload(Target.rules_of_engagement),
                selectinload(Target.api_spec),
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise ToolNotFoundError(f"target {params.target_id} not found")

    if not params.authorization_confirmed:
        raise ToolExecutionError("authorization_confirmed must be true to start an assessment")

    try:
        context = build_run_context(target)
    except (AuthorizationRequiredError, RoEValidationError) as exc:
        raise ToolExecutionError(str(exc)) from exc

    now = datetime.now(UTC)
    if now < context.authorization.valid_from or now >= context.authorization.valid_until:
        raise ToolExecutionError("authorization for this target is not currently valid")

    run = await queue_run(
        ctx.db,
        organization_id=ctx.organization_id,
        target=target,
        user_id=ctx.user_id,
        profile=params.profile,
        safe_mode=params.safe_mode,
        confirmed_at=now,
    )
    return StartScanResult(run=RunRead.model_validate(run))


START_SCAN = Tool(
    name="start_scan",
    description="Queue an assessment run against an authorized target.",
    input_model=StartScanParams,
    output_model=StartScanResult,
    risk_level=RiskLevel.SENSITIVE,
    minimum_role=Role.SECURITY_ENGINEER,
    handler=_start_scan,
    timeout_seconds=30.0,
    rate_limit_rule="agent_sensitive_tool_call",
)
