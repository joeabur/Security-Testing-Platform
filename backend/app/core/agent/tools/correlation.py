"""`correlate_findings`/`prioritise_findings` — AI-drafted analysis over a
set of findings, not just one.

Same reuse shape as `app.core.agent.tools.analysis`: the tool loads
`Finding` rows scoped to `ctx.organization_id`, projects each into a
`FindingView`, and calls the existing `AIService` method in-process. Both
capabilities are pre-declared at `AutonomyMode.RECOMMEND` in
`app.core.assistant.autonomy` — one tier above `explain_finding`'s ASSIST,
because looking across findings and proposing an order is a step closer to
a recommendation a human is expected to act on, not just an explanation of
what is already there. Read-only either way: neither method writes a
finding's real severity, status, or relationships.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel
from sqlalchemy import select

from app.core.agent.context import AgentContext
from app.core.agent.tools.analysis import _finding_view
from app.core.agent.tools.contract import RiskLevel, Tool, ToolExecutionError, ToolNotFoundError
from app.core.assistant.autonomy import AutonomyMode
from app.core.assistant.provider import ProviderError, ProviderNotConfiguredError
from app.core.assistant.service import AIService
from app.models.finding import Finding
from app.models.organization import Role

# A co-pilot reasoning over too many findings at once produces noise, not a
# correlation — matches `AIService`'s own `MAX_FINDINGS` cap.
MAX_FINDING_IDS = 25


class FindingSetParams(BaseModel):
    finding_ids: list[uuid.UUID]


class FindingSetResult(BaseModel):
    analysis: str
    model: str
    provider: str


async def _load_findings(ctx: AgentContext, finding_ids: list[uuid.UUID]) -> list[Finding]:
    if not finding_ids:
        raise ToolExecutionError("finding_ids must not be empty")
    ids = finding_ids[:MAX_FINDING_IDS]
    rows = (
        await ctx.db.execute(
            select(Finding).where(
                Finding.id.in_(ids), Finding.organization_id == ctx.organization_id
            )
        )
    ).scalars().all()
    found_ids = {row.id for row in rows}
    missing = [str(finding_id) for finding_id in ids if finding_id not in found_ids]
    if missing:
        raise ToolNotFoundError(f"finding(s) not found: {', '.join(missing)}")
    return list(rows)


async def _correlate_findings(ctx: AgentContext, params: FindingSetParams) -> FindingSetResult:
    findings = await _load_findings(ctx, params.finding_ids)

    if ctx.provider is None:
        raise ToolExecutionError("no AI provider is configured for this organization")

    service = AIService(ctx.provider, mode=AutonomyMode.RECOMMEND)
    try:
        draft = await service.correlate_findings([_finding_view(f) for f in findings])
    except (ProviderNotConfiguredError, ProviderError) as exc:
        raise ToolExecutionError(f"AI provider call failed: {exc}") from exc

    return FindingSetResult(analysis=draft.content, model=draft.model, provider=draft.provider)


async def _prioritise_findings(ctx: AgentContext, params: FindingSetParams) -> FindingSetResult:
    findings = await _load_findings(ctx, params.finding_ids)

    if ctx.provider is None:
        raise ToolExecutionError("no AI provider is configured for this organization")

    service = AIService(ctx.provider, mode=AutonomyMode.RECOMMEND)
    try:
        draft = await service.prioritise_findings([_finding_view(f) for f in findings])
    except (ProviderNotConfiguredError, ProviderError) as exc:
        raise ToolExecutionError(f"AI provider call failed: {exc}") from exc

    return FindingSetResult(analysis=draft.content, model=draft.model, provider=draft.provider)


CORRELATE_FINDINGS = Tool(
    name="correlate_findings",
    description=(
        "Look for relationships between a set of findings from the same assessment: "
        "a shared root cause, one finding enabling another, or a pattern across the "
        "same surface or component."
    ),
    input_model=FindingSetParams,
    output_model=FindingSetResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_correlate_findings,
    timeout_seconds=30.0,
    rate_limit_rule="agent_tool_call",
)

PRIORITISE_FINDINGS = Tool(
    name="prioritise_findings",
    description=(
        "Get an AI-proposed remediation order for a set of findings, with rationale. "
        "A recommendation only — no finding's stored severity or status changes."
    ),
    input_model=FindingSetParams,
    output_model=FindingSetResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_prioritise_findings,
    timeout_seconds=30.0,
    rate_limit_rule="agent_tool_call",
)
