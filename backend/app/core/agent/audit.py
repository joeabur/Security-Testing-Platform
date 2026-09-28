"""Recording what a tool call did — never what it said or returned.

Two append-only records per call: an `AuditEvent` (the platform-wide audit
trail every other subsystem already writes to,
`app/audit/service.py::record_event`) and, when the call ran a real tool
rather than only being authorized, an `AgentUsageMetadata` row (cost and
performance metrics). Both take a fixed set of scalar fields — never a
prompt, a tool's raw arguments, or its result — so there is exactly one
place in the agent subsystem that decides what "operational metadata" means,
and every caller goes through it rather than composing their own metadata
dict that could grow a content field by accident.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel
from app.models.agent import AgentUsageMetadata


async def record_tool_call(
    db: AsyncSession,
    ctx: AgentContext,
    *,
    tool_name: str,
    risk_level: RiskLevel,
    status: str,
    duration_ms: int,
    error_code: str | None = None,
) -> None:
    """Append one `AuditEvent` for a tool call's outcome.

    `status` is `"allow"` or `"deny"`, matching every other caller of
    `record_event` in this codebase — not a free-form success/failure string
    that would need its own vocabulary.
    """
    await record_event(
        db,
        action="agent.tool_call",
        resource_type="agent_tool",
        resource_id=tool_name,
        result=status,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        metadata={
            "tool_name": tool_name,
            "risk_level": risk_level.value,
            "duration_ms": duration_ms,
            "error_code": error_code,
            "request_id": ctx.request_id,
        },
    )


async def record_usage(
    db: AsyncSession,
    ctx: AgentContext,
    *,
    agent_id: uuid.UUID | None,
    tool_name: str,
    provider: str | None,
    model: str | None,
    tokens_sent: int = 0,
    tokens_received: int = 0,
    cost_usd: float = 0.0,
    duration_ms: int,
    status: str,
    error_code: str | None = None,
) -> AgentUsageMetadata:
    """Append one usage/cost/performance row.

    `agent_id`/`provider`/`model` are `None` for a tool call that never
    reached a provider (every tool call today — no tool in this phase makes
    an AI request of its own). Left in the shape now so `planner.py`
    (Phase 4) has somewhere to record a real provider call's token usage
    without a schema change.
    """
    usage = AgentUsageMetadata(
        organization_id=ctx.organization_id,
        agent_id=agent_id,
        tool_name=tool_name,
        provider=provider,
        model=model,
        tokens_sent=tokens_sent,
        tokens_received=tokens_received,
        cost_usd=cost_usd,
        duration_ms=duration_ms,
        status=status,
        error_code=error_code,
        request_id=ctx.request_id,
    )
    db.add(usage)
    await db.flush()
    return usage
