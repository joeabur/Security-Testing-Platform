"""Remediation board and retest workflow (docs/BUILD_SPEC.md §26 Phase 9).

Two endpoints do the interesting work.

`PUT .../findings/{id}/remediation` turns a finding into tracked work:
assignee, due date, notes. It deliberately cannot change the finding's
security state — that is the findings endpoint's job, and splitting them is
what keeps "who owns this" and "is it still a problem" from drifting apart.

`POST .../retests` queues a run that re-checks named findings. It takes the
same explicit authorization confirmation a new assessment takes, because it
reaches the target in exactly the same way: having scanned something once is
not standing permission to scan it again.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.v1.routers.targets import load_target
from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.orchestrator.context_builder import build_run_context
from app.core.retest.service import baseline_of, mark_awaiting_retest
from app.core.runs.service import queue_run
from app.core.scope.errors import AuthorizationRequiredError, RoEValidationError
from app.models.assessment_run import AssessmentRun, RunKind
from app.models.finding import Finding
from app.models.organization import Membership, Role
from app.models.remediation import RemediationTask
from app.models.retest import RetestResult
from app.schemas.remediation import (
    RemediationBoardRow,
    RemediationRead,
    RemediationUpsert,
    RetestCreate,
    RetestResultRead,
)
from app.schemas.run import RunRead

router = APIRouter(prefix="/organizations/{organization_id}", tags=["remediation"])


@router.get("/remediation", response_model=list[RemediationBoardRow])
async def list_remediation(
    organization_id: uuid.UUID,
    db: DbSession,
    assignee_user_id: uuid.UUID | None = None,
    open_only: bool = False,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[RemediationBoardRow]:
    """The board, ordered by risk rather than by when someone filed it."""
    query = (
        select(RemediationTask)
        .where(RemediationTask.organization_id == organization_id)
        .options(selectinload(RemediationTask.finding))
    )
    if assignee_user_id is not None:
        query = query.where(RemediationTask.assignee_user_id == assignee_user_id)
    if open_only:
        query = query.where(RemediationTask.closed_at.is_(None))

    tasks = (await db.execute(query)).scalars().all()
    rows = [
        RemediationBoardRow(
            task=RemediationRead.model_validate(task),
            finding_id=task.finding.id,
            title=task.finding.title,
            severity=task.finding.severity,
            risk_score=task.finding.risk_score,
            status=task.finding.status,
            retest_result=task.finding.retest_result,
        )
        for task in tasks
    ]
    return sorted(rows, key=lambda row: row.risk_score, reverse=True)


@router.put("/findings/{finding_id}/remediation", response_model=RemediationRead)
async def upsert_remediation(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: RemediationUpsert,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> RemediationRead:
    finding = await _load_finding(organization_id, finding_id, db)

    if payload.assignee_user_id is not None:
        await _require_member(organization_id, payload.assignee_user_id, db)

    task = (
        await db.execute(select(RemediationTask).where(RemediationTask.finding_id == finding.id))
    ).scalar_one_or_none()

    if task is None:
        task = RemediationTask(
            organization_id=organization_id,
            finding_id=finding.id,
            # Defaulted from the finding rather than required: a task with a
            # summary nobody wrote is still better identified by the finding's
            # own title than by an empty string.
            summary=(payload.summary or finding.title)[:300],
            created_by_user_id=membership.user_id,
        )
        db.add(task)
    elif payload.summary is not None:
        task.summary = payload.summary[:300]

    task.assignee_user_id = payload.assignee_user_id
    task.due_date = payload.due_date
    task.notes = payload.notes

    await record_event(
        db,
        action="remediation.upsert",
        resource_type="remediation_task",
        resource_id=str(finding.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "assignee_user_id": str(payload.assignee_user_id) if payload.assignee_user_id else None,
            "due_date": payload.due_date.isoformat() if payload.due_date else None,
            "fingerprint": finding.fingerprint,
        },
    )
    await db.commit()
    return RemediationRead.model_validate(task)


@router.post("/retests", response_model=RunRead, status_code=status.HTTP_201_CREATED)
async def create_retest(
    organization_id: uuid.UUID,
    payload: RetestCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> RunRead:
    """Queue a run that re-checks the named findings.

    The baseline — each finding's fingerprint and the evidence digest it
    carries right now — is written down before the run starts. Both halves
    would otherwise move underneath the comparison: the run overwrites a
    reproduced finding's evidence reference, and someone triaging in the
    meantime changes its state.
    """
    target = await load_target(organization_id, payload.target_id, db)

    if not payload.authorization_confirmed:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="authorization_confirmed must be true to start a retest",
        )

    findings = list(
        (
            await db.execute(
                select(Finding)
                .where(
                    Finding.organization_id == organization_id,
                    Finding.id.in_(payload.finding_ids),
                )
                .options(selectinload(Finding.remediation_task))
            )
        )
        .scalars()
        .all()
    )
    missing = set(payload.finding_ids) - {finding.id for finding in findings}
    if missing:
        # Named but absent: refused rather than silently narrowed, because a
        # retest that quietly drops findings reports a clean result for work
        # it never checked.
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail=f"unknown finding(s): {', '.join(sorted(str(item) for item in missing))}",
        )

    try:
        context = build_run_context(target)
    except (AuthorizationRequiredError, RoEValidationError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    now = datetime.now(UTC)
    if now < context.authorization.valid_from or now >= context.authorization.valid_until:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="authorization for this target is not currently valid",
        )

    # The findings' own states record that a check is outstanding, which stays
    # true even if the run then fails to complete.
    mark_awaiting_retest(findings, membership.user_id)

    previous_run_ids = {finding.last_run_id for finding in findings if finding.last_run_id}
    run = await queue_run(
        db,
        organization_id=organization_id,
        target=target,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        profile=payload.profile,
        safe_mode=payload.safe_mode,
        confirmed_at=now,
        kind=RunKind.RETEST,
        # Only when the findings all came from one run; otherwise there is no
        # single "before" run to point at, and naming one of them would be a
        # guess presented as a record.
        retest_of_run_id=next(iter(previous_run_ids)) if len(previous_run_ids) == 1 else None,
        retest_baseline=baseline_of(findings),
    )
    return RunRead.model_validate(run)


@router.get("/runs/{run_id}/retest-results", response_model=list[RetestResultRead])
async def list_retest_results(
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[RetestResultRead]:
    run = (
        await db.execute(
            select(AssessmentRun).where(
                AssessmentRun.id == run_id,
                AssessmentRun.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Run not found")

    rows = (
        await db.execute(
            select(RetestResult)
            .where(RetestResult.run_id == run_id)
            .order_by(RetestResult.created_at)
        )
    ).scalars()
    return [RetestResultRead.model_validate(row) for row in rows.all()]


async def _load_finding(
    organization_id: uuid.UUID, finding_id: uuid.UUID, db: DbSession
) -> Finding:
    finding = (
        await db.execute(
            select(Finding).where(
                Finding.id == finding_id, Finding.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


async def _require_member(organization_id: uuid.UUID, user_id: uuid.UUID, db: DbSession) -> None:
    """An assignee has to be a member of this organization.

    Otherwise the board could name someone who cannot see the finding, which
    is both useless and a small information leak about who exists.
    """
    membership = (
        await db.execute(
            select(Membership).where(
                Membership.organization_id == organization_id,
                Membership.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="assignee is not a member of this organization",
        )
