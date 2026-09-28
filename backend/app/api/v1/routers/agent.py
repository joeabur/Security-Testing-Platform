"""The native AI agent's HTTP surface (Agent Phase 5).

Five endpoints, deliberately narrow:

* `GET .../agent/tools` — discovery: which tools exist, at what risk tier,
  behind what minimum role. No execution.
* `POST .../agent/investigate` — plan and run a natural-language request
  against the caller's own permitted tool set. Runs **synchronously**: a
  READ_ONLY/STANDARD plan returns its final result in this response: a
  plan that reaches an unapproved SENSITIVE step returns `202` with the
  pending approval instead of running it.
* `GET .../agent/investigate/{id}/status` — read a **paused** investigation
  back. There is nothing to read for one that already finished: per the
  zero-persistence rule, a completed investigation's result was returned
  once, in the original response, and was never written anywhere — the
  same reason a `POST /runs` response is the one place a run's queued
  status is announced before its row exists to poll.
* `POST .../agent/investigate/{id}/approve` — resume a paused investigation
  past its one pending SENSITIVE step.
* `POST .../agent/investigate/{id}/cancel` — discard a paused investigation
  without running its remaining steps.

Streaming (an SSE endpoint mirroring `runs.py`'s live progress stream) is a
stated future enhancement, not built here: today's `investigate` call
already returns synchronously, so there is no in-flight state an SSE
stream would have anything to report on until execution itself moves to a
background worker — see `docs/roadmap.md`.
"""

from __future__ import annotations

import contextlib
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from app.auth.dependencies import DbSession, effective_role, require_membership
from app.core.agent.audit import record_tool_call
from app.core.agent.context import AgentContext
from app.core.agent.investigation import Investigation, InvestigationStatus
from app.core.agent.planner import PlanningError, build_plan
from app.core.agent.provider.factory import build_provider
from app.core.agent.runtime import ExecutionResult, StepOutcome, StepStatus, run_plan
from app.core.agent.session_store import (
    InvestigationSessionStore,
    PausedInvestigation,
    SessionStoreUnavailable,
)
from app.core.agent.tools.contract import RiskLevel
from app.core.agent.tools.registry import agent_tools, tools_by_name
from app.core.assistant.provider import ProviderError
from app.models.agent import Agent, AgentProvider
from app.models.organization import Membership, Role
from app.schemas.agent import (
    ApproveRequest,
    InvestigateRequest,
    InvestigationRead,
    PendingApprovalRead,
    StepOutcomeRead,
    ToolCatalogEntry,
)

router = APIRouter(prefix="/organizations/{organization_id}/agent", tags=["agent"])

_READER = require_membership(Role.VIEWER)
_INVESTIGATOR = require_membership(Role.ANALYST)
_APPROVER = require_membership(Role.SECURITY_ENGINEER)


async def _resolved_provider(db: DbSession, organization_id: uuid.UUID) -> AgentProvider | None:
    agent = (
        await db.execute(select(Agent).where(Agent.organization_id == organization_id))
    ).scalar_one_or_none()
    if agent is None or not agent.enabled or agent.default_provider_id is None:
        return None
    provider_row = await db.get(AgentProvider, agent.default_provider_id)
    if provider_row is None or not provider_row.enabled:
        return None
    return provider_row


def _outcome_read(outcome: StepOutcome) -> StepOutcomeRead:
    return StepOutcomeRead(
        tool_name=outcome.tool_name,
        status=outcome.status.value,
        result=outcome.result.model_dump(mode="json") if outcome.result is not None else None,
        error=outcome.error,
        duration_ms=outcome.duration_ms,
    )


def _investigation_read(result: ExecutionResult) -> InvestigationRead:
    investigation = result.investigation
    pending = investigation.pending_approval
    return InvestigationRead(
        investigation_id=investigation.id,
        status=investigation.status.value,
        outcomes=[_outcome_read(o) for o in result.outcomes],
        summary=result.summary,
        pending_approval=(
            None
            if pending is None
            else PendingApprovalRead(
                tool_name=pending.tool_name,
                risk_level=pending.risk_level.value,
                description=pending.description,
            )
        ),
    )


async def _record_outcomes(db: DbSession, ctx: AgentContext, outcomes: list[StepOutcome]) -> None:
    catalog = tools_by_name()
    for outcome in outcomes:
        tool = catalog.get(outcome.tool_name)
        await record_tool_call(
            db,
            ctx,
            tool_name=outcome.tool_name,
            risk_level=tool.risk_level if tool is not None else RiskLevel.READ_ONLY,
            status="allow" if outcome.status is StepStatus.OK else "deny",
            duration_ms=outcome.duration_ms,
            error_code=outcome.error,
        )


@router.get("/tools", response_model=list[ToolCatalogEntry])
async def list_tools(
    organization_id: uuid.UUID,
    membership: Membership = Depends(_READER),  # noqa: B008
) -> list[ToolCatalogEntry]:
    return [
        ToolCatalogEntry(
            name=tool.name,
            description=tool.description,
            risk_level=tool.risk_level.value,
            minimum_role=tool.minimum_role.value,
        )
        for tool in agent_tools()
    ]


@router.post("/investigate", response_model=InvestigationRead)
async def investigate(
    organization_id: uuid.UUID,
    payload: InvestigateRequest,
    request: Request,
    response: Response,
    db: DbSession,
    membership: Membership = Depends(_INVESTIGATOR),  # noqa: B008
) -> InvestigationRead:
    provider_row = await _resolved_provider(db, organization_id)
    if provider_row is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="the native agent is not enabled, or has no default provider configured, "
            "for this organization",
        )
    provider = build_provider(provider_row)

    api_key = getattr(request.state, "api_key", None)
    effective = effective_role(membership, api_key)
    permitted_tools = [tool for tool in agent_tools() if effective.at_least(tool.minimum_role)]

    try:
        plan = await build_plan(provider, payload.request, permitted_tools)
    except PlanningError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"could not plan this request: {exc}"
        ) from exc
    except ProviderError as exc:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY, detail=f"AI provider call failed: {exc}"
        ) from exc

    ctx = AgentContext(
        organization_id=organization_id,
        user_id=membership.user_id,
        effective_role=effective,
        db=db,
        request_id=str(uuid.uuid4()),
        provider=provider,
    )
    investigation = Investigation.start(organization_id=organization_id, user_id=membership.user_id)
    result = await run_plan(ctx, plan, tools_by_name(), investigation, summarize=True)

    await _record_outcomes(db, ctx, result.outcomes)
    await db.commit()

    if result.investigation.status is InvestigationStatus.AWAITING_APPROVAL:
        store = InvestigationSessionStore()
        try:
            await store.save(result.investigation, plan)
        except SessionStoreUnavailable as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"could not save the paused investigation: {exc}",
            ) from exc
        response.status_code = status.HTTP_202_ACCEPTED

    return _investigation_read(result)


async def _load_paused(
    organization_id: uuid.UUID, investigation_id: uuid.UUID
) -> PausedInvestigation:
    store = InvestigationSessionStore()
    try:
        paused = await store.load(investigation_id, organization_id=organization_id)
    except SessionStoreUnavailable as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"could not read investigation state: {exc}. Treat this as not "
            "approvable rather than retrying an approval blind.",
        ) from exc
    if paused is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="no paused investigation with this id in this organization",
        )
    return paused


@router.get("/investigate/{investigation_id}/status", response_model=InvestigationRead)
async def get_investigation_status(
    organization_id: uuid.UUID,
    investigation_id: uuid.UUID,
    membership: Membership = Depends(_READER),  # noqa: B008
) -> InvestigationRead:
    paused = await _load_paused(organization_id, investigation_id)
    return _investigation_read(ExecutionResult(investigation=paused.investigation, outcomes=[]))


@router.post("/investigate/{investigation_id}/approve", response_model=InvestigationRead)
async def approve_investigation(
    organization_id: uuid.UUID,
    investigation_id: uuid.UUID,
    _payload: ApproveRequest,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(_APPROVER),  # noqa: B008
) -> InvestigationRead:
    paused = await _load_paused(organization_id, investigation_id)
    pending = paused.investigation.pending_approval
    if pending is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="this investigation has no pending approval"
        )

    provider_row = await _resolved_provider(db, organization_id)
    if provider_row is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="the native agent is not enabled, or has no default provider configured, "
            "for this organization",
        )
    provider = build_provider(provider_row)

    api_key = getattr(request.state, "api_key", None)
    effective = effective_role(membership, api_key)
    ctx = AgentContext(
        organization_id=organization_id,
        user_id=membership.user_id,
        effective_role=effective,
        db=db,
        request_id=str(uuid.uuid4()),
        provider=provider,
    )

    # `paused.investigation.plan_step_index` still points at the pending
    # step — `run_plan` re-enters its loop from exactly that index and
    # re-authorizes it, this time passing because its name is now in
    # `approved_tool_names`. Nothing here needs to pre-clear
    # `pending_approval` or advance the index by hand; the loop's own
    # branches set both correctly regardless of which way this step goes.
    result = await run_plan(
        ctx,
        paused.plan,
        tools_by_name(),
        paused.investigation,
        approved_tool_names=frozenset({pending.tool_name}),
        summarize=True,
    )

    await _record_outcomes(db, ctx, result.outcomes)
    await db.commit()

    store = InvestigationSessionStore()
    if result.investigation.status is InvestigationStatus.AWAITING_APPROVAL:
        try:
            await store.save(result.investigation, paused.plan)
        except SessionStoreUnavailable as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"could not save the paused investigation: {exc}",
            ) from exc
    else:
        # Best-effort: the key's own TTL still expires it either way.
        with contextlib.suppress(SessionStoreUnavailable):
            await store.delete(investigation_id)

    return _investigation_read(result)


@router.post("/investigate/{investigation_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_investigation(
    organization_id: uuid.UUID,
    investigation_id: uuid.UUID,
    membership: Membership = Depends(_APPROVER),  # noqa: B008
) -> None:
    await _load_paused(organization_id, investigation_id)
    store = InvestigationSessionStore()
    try:
        await store.delete(investigation_id)
    except SessionStoreUnavailable as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"could not cancel: {exc}"
        ) from exc
