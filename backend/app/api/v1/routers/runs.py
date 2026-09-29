"""Assessment run lifecycle endpoints (docs/BUILD_SPEC.md §15, §16)."""

import asyncio
import json
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api.v1.routers.targets import load_target
from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.orchestrator.context_builder import build_run_context
from app.core.pentest.exploitation_service import ExploitationFireRefused, request_fire
from app.core.probes.models import Severity
from app.core.runs.service import queue_run
from app.core.scope.errors import AuthorizationRequiredError, RoEValidationError
from app.db.session import get_session_factory
from app.models.assessment_run import (
    TERMINAL_STATUSES,
    AssessmentRun,
    RunEvent,
    RunEventKind,
    RunStatus,
)
from app.models.exploitation import ExploitationFire
from app.models.organization import Membership, Role
from app.models.scan_result import ScanResultRecord
from app.schemas.exploitation import ExploitationFireCreate, ExploitationFireRead
from app.schemas.run import RunCreate, RunEventRead, RunRead, ScanResultRead
from app.workers.cancellation import request_cancellation
from app.workers.celery_app import celery_app

router = APIRouter(prefix="/organizations/{organization_id}/runs", tags=["runs"])

SSE_POLL_SECONDS = 1.0
SSE_MAX_IDLE_POLLS = 300  # ~5 minutes of silence before the stream closes


async def _load_run(organization_id: uuid.UUID, run_id: uuid.UUID, db: DbSession) -> AssessmentRun:
    result = await db.execute(
        select(AssessmentRun).where(
            AssessmentRun.id == run_id, AssessmentRun.organization_id == organization_id
        )
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")
    return run


@router.post("", response_model=RunRead, status_code=status.HTTP_201_CREATED)
async def create_run(
    organization_id: uuid.UUID,
    payload: RunCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> RunRead:
    """Create a run and queue it.

    Authorization is verified *here*, before anything is queued, and again by
    the scope engine on every single request the run makes
    (docs/BUILD_SPEC.md §2.1: authorization is a hard gate, checked at every
    request rather than once at run start).
    """
    target = await load_target(organization_id, payload.target_id, db)

    if not payload.authorization_confirmed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="authorization_confirmed must be true to start an assessment",
        )

    try:
        context = build_run_context(target)
    except AuthorizationRequiredError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RoEValidationError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    now = datetime.now(UTC)
    # The scope engine would refuse every request from a run whose grant is
    # already outside its validity window, so refuse it here instead of
    # queueing work that can only halt on its first request.
    if now < context.authorization.valid_from or now >= context.authorization.valid_until:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="authorization for this target is not currently valid",
        )

    run = await queue_run(
        db,
        organization_id=organization_id,
        target=target,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        profile=payload.profile,
        safe_mode=payload.safe_mode,
        confirmed_at=now,
    )
    return RunRead.model_validate(run)


@router.get("", response_model=list[RunRead])
async def list_runs(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[RunRead]:
    result = await db.execute(
        select(AssessmentRun)
        .where(AssessmentRun.organization_id == organization_id)
        .order_by(AssessmentRun.created_at.desc())
    )
    return [RunRead.model_validate(run) for run in result.scalars().all()]


@router.get("/{run_id}", response_model=RunRead)
async def get_run(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> RunRead:
    return RunRead.model_validate(await _load_run(organization_id, run_id, db))


@router.get("/{run_id}/events", response_model=list[RunEventRead])
async def list_run_events(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    after_seq: int = 0,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[RunEventRead]:
    await _load_run(organization_id, run_id, db)
    result = await db.execute(
        select(RunEvent)
        .where(RunEvent.run_id == run_id, RunEvent.seq > after_seq)
        .order_by(RunEvent.seq)
    )
    return [RunEventRead.model_validate(event) for event in result.scalars().all()]


@router.get("/{run_id}/results", response_model=list[ScanResultRead])
async def list_run_results(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    include_informational: bool = True,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[ScanResultRead]:
    """What the probes reported for this run.

    `include_informational` defaults to true on purpose: the informational
    rows are where "this was not tested" lives, and a reader who filters
    them out should do so knowingly rather than by default
    (docs/BUILD_SPEC.md §14 coverage honesty).
    """
    await _load_run(organization_id, run_id, db)

    query = select(ScanResultRecord).where(ScanResultRecord.run_id == run_id)
    if not include_informational:
        query = query.where(ScanResultRecord.severity != Severity.INFORMATIONAL)

    result = await db.execute(query.order_by(ScanResultRecord.seq))
    return [ScanResultRead.model_validate(row) for row in result.scalars().all()]


@router.post("/{run_id}/cancel", response_model=RunRead)
async def cancel_run(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> RunRead:
    """Trip the kill switch for a run.

    The Redis flag is what reaches a run already executing in a worker; the
    status write is what stops a queued run from ever starting. A run that
    has already finished is left exactly as it was.
    """
    run = await _load_run(organization_id, run_id, db)
    if run.status in TERMINAL_STATUSES:
        return RunRead.model_validate(run)

    request_cancellation(str(run.id))

    if run.status is RunStatus.QUEUED:
        run.status = RunStatus.CANCELLED
        run.finished_at = datetime.now(UTC)
        run.halted_reason = "cancelled before execution started"

    db.add(
        RunEvent(
            run_id=run.id,
            kind=RunEventKind.CANCELLED,
            message="Cancellation requested by operator",
            payload={"requested_by": str(membership.user_id)},
        )
    )
    await record_event(
        db,
        action="run.cancel",
        resource_type="assessment_run",
        resource_id=str(run.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return RunRead.model_validate(run)


@router.get("/{run_id}/stream")
async def stream_run_progress(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    after_seq: int = 0,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> StreamingResponse:
    """Server-Sent Events over the run's persisted event log.

    Every frame is a replay of a row a worker actually wrote, so progress in
    a browser can never run ahead of the work (§16: "Do not fake progress").
    Authorization is checked once here, before the stream opens; the stream
    then uses its own short-lived sessions so it does not hold a request
    session open for its whole lifetime.
    """
    await _load_run(organization_id, run_id, db)

    async def event_source() -> AsyncGenerator[str, None]:
        session_factory = get_session_factory()
        last_seq = after_seq
        idle_polls = 0

        while idle_polls < SSE_MAX_IDLE_POLLS:
            async with session_factory() as stream_db:
                result = await stream_db.execute(
                    select(RunEvent)
                    .where(RunEvent.run_id == run_id, RunEvent.seq > last_seq)
                    .order_by(RunEvent.seq)
                )
                events = list(result.scalars().all())

                run_result = await stream_db.execute(
                    select(AssessmentRun.status).where(AssessmentRun.id == run_id)
                )
                run_status = run_result.scalar_one_or_none()

            if events:
                idle_polls = 0
                for event in events:
                    last_seq = event.seq
                    frame = {
                        "seq": event.seq,
                        "kind": event.kind.value,
                        "message": event.message,
                        "payload": event.payload,
                    }
                    yield f"event: {event.kind.value}\ndata: {json.dumps(frame)}\n\n"
            else:
                idle_polls += 1

            if run_status is not None and run_status in TERMINAL_STATUSES and not events:
                yield f"event: end\ndata: {json.dumps({'status': run_status.value})}\n\n"
                return

            await asyncio.sleep(SSE_POLL_SECONDS)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post(
    "/{run_id}/exploitation-fires",
    response_model=ExploitationFireRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_exploitation_fire(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    payload: ExploitationFireCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> ExploitationFireRead:
    """Pentest module Phase 12 — the "fire" half of simulate-then-fire.

    `run_id` must be an already-completed run whose scan_results contain
    the simulate marker for this exact host:port (produced automatically
    when a scan runs with asset_scope.max_depth=exploitation); see
    `app.core.pentest.exploitation_service.request_fire` for the full
    three-allowlist gate this enforces. Queues the real invocation on the
    worker (`kervy.fire_exploitation_module`) rather than running it
    inline — the same target-touching-work-belongs-on-the-worker rule
    every other scan on this platform already follows.
    """
    run = await _load_run(organization_id, run_id, db)
    target = await load_target(organization_id, run.target_id, db)

    try:
        fire = await request_fire(
            db,
            organization_id=organization_id,
            target=target,
            run=run,
            service_host=payload.service_host,
            service_port=payload.service_port,
            script_names=payload.script_names,
            requested_by_user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
        )
    except ExploitationFireRefused as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.commit()

    celery_app.send_task("kervy.fire_exploitation_module", args=[str(fire.id)])

    return ExploitationFireRead.model_validate(fire)


@router.get("/{run_id}/exploitation-fires", response_model=list[ExploitationFireRead])
async def list_exploitation_fires(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[ExploitationFireRead]:
    await _load_run(organization_id, run_id, db)
    result = await db.execute(
        select(ExploitationFire)
        .where(
            ExploitationFire.run_id == run_id,
            ExploitationFire.organization_id == organization_id,
        )
        .order_by(ExploitationFire.requested_at.desc())
    )
    return [ExploitationFireRead.model_validate(row) for row in result.scalars().all()]


@router.get("/{run_id}/exploitation-fires/{fire_id}", response_model=ExploitationFireRead)
async def get_exploitation_fire(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    fire_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> ExploitationFireRead:
    await _load_run(organization_id, run_id, db)
    result = await db.execute(
        select(ExploitationFire).where(
            ExploitationFire.id == fire_id,
            ExploitationFire.run_id == run_id,
            ExploitationFire.organization_id == organization_id,
        )
    )
    fire = result.scalar_one_or_none()
    if fire is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Exploitation fire not found")
    return ExploitationFireRead.model_validate(fire)
