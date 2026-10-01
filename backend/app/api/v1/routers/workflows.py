"""Workflows and their runs (docs/BUILD_SPEC.md §26 Phase 17).

Roles follow the same reasoning as the rest of the API: defining a workflow
changes what will gate a release, so that is **admin**. Triggering one runs an
assessment, so that is **security engineer** — the same role `POST /runs`
requires, because a workflow must not be a way to start a scan with less
authority than starting a scan.

Reading is analyst, so the people triaging findings can see why a gate failed
without being able to change the gate that failed it.
"""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.config import get_settings
from app.core.gate.model import GateConfigError
from app.core.workflow import service as workflow_service
from app.core.workflow.contract import WorkflowStatus
from app.core.workflow.service import finish, start, trigger_from
from app.core.workflow.webhook_secret import (
    WebhookEncryptionNotConfigured,
    encrypt_secret,
    generate_secret,
)
from app.models.organization import Membership, Role
from app.models.target import Target
from app.models.workflow import Workflow, WorkflowRun
from app.schemas.workflow import (
    WorkflowCreate,
    WorkflowRead,
    WorkflowRunApprovalRequest,
    WorkflowRunRead,
    WorkflowRunRejectionRequest,
    WorkflowRunRequest,
    WorkflowUpdate,
    WorkflowWebhookSecretRead,
)

router = APIRouter(prefix="/organizations/{organization_id}/workflows", tags=["workflows"])

_ADMIN = require_membership(Role.ADMIN)
_RUNNER = require_membership(Role.SECURITY_ENGINEER)
_READER = require_membership(Role.ANALYST)


async def _load(db: DbSession, organization_id: uuid.UUID, workflow_id: uuid.UUID) -> Workflow:
    workflow = (
        await db.execute(
            select(Workflow).where(
                Workflow.id == workflow_id, Workflow.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    if workflow is None:
        # 404, not 403: a workflow in another organization must not be
        # distinguishable from one that does not exist.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="workflow not found")
    return workflow


@router.post("", response_model=WorkflowRead, status_code=status.HTTP_201_CREATED)
async def create_workflow(
    organization_id: uuid.UUID,
    payload: WorkflowCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(_ADMIN),  # noqa: B008
) -> Workflow:
    target = (
        await db.execute(
            select(Target).where(
                Target.id == payload.target_id, Target.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="target not found")

    existing = (
        await db.execute(
            select(Workflow.id).where(
                Workflow.organization_id == organization_id, Workflow.name == payload.name
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="a workflow with that name exists")

    workflow = Workflow(
        organization_id=organization_id,
        target_id=payload.target_id,
        name=payload.name,
        trigger_kind=payload.trigger_kind.value,
        enabled=payload.enabled,
        gate_config=payload.gate_config,
        created_by_user_id=membership.user_id,
        schedule_interval_minutes=payload.schedule_interval_minutes,
        next_run_at=(
            datetime.now(UTC) + timedelta(minutes=payload.schedule_interval_minutes)
            if payload.schedule_interval_minutes is not None
            else None
        ),
    )
    db.add(workflow)
    await db.flush()
    await record_event(
        db,
        action="workflow.created",
        resource_type="workflow",
        resource_id=str(workflow.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        metadata={"name": workflow.name, "trigger": workflow.trigger_kind},
    )
    await db.commit()
    await db.refresh(workflow)
    return workflow


@router.get("", response_model=list[WorkflowRead])
async def list_workflows(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(_READER),  # noqa: B008
) -> list[Workflow]:
    result = await db.execute(
        select(Workflow).where(Workflow.organization_id == organization_id).order_by(Workflow.name)
    )
    return list(result.scalars().all())


@router.get("/{workflow_id}", response_model=WorkflowRead)
async def get_workflow(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(_READER),  # noqa: B008
) -> Workflow:
    return await _load(db, organization_id, workflow_id)


@router.patch("/{workflow_id}", response_model=WorkflowRead)
async def update_workflow(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    payload: WorkflowUpdate,
    db: DbSession,
    membership: Membership = Depends(_ADMIN),  # noqa: B008
) -> Workflow:
    workflow = await _load(db, organization_id, workflow_id)
    fields = payload.model_dump(exclude_unset=True)
    for field, value in fields.items():
        setattr(workflow, field, value)
    if "schedule_interval_minutes" in fields:
        # Re-arms the schedule from now, whether an interval was set for the
        # first time or changed to a different one. `None` (turning
        # scheduling off) clears `next_run_at` too, so a disabled schedule
        # is not silently still due.
        workflow.next_run_at = (
            datetime.now(UTC) + timedelta(minutes=workflow.schedule_interval_minutes)
            if workflow.schedule_interval_minutes is not None
            else None
        )
    await record_event(
        db,
        action="workflow.updated",
        resource_type="workflow",
        resource_id=str(workflow.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        # The gate is what decides whether a release ships, so a change to it
        # is recorded as a change to it — not as an unlabelled "updated".
        metadata={"fields": sorted(fields), "gate_changed": "gate_config" in fields},
    )
    await db.commit()
    await db.refresh(workflow)
    return workflow


@router.delete("/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workflow(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(_ADMIN),  # noqa: B008
) -> None:
    workflow = await _load(db, organization_id, workflow_id)
    await record_event(
        db,
        action="workflow.deleted",
        resource_type="workflow",
        resource_id=str(workflow.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        metadata={"name": workflow.name},
    )
    await db.delete(workflow)
    await db.commit()


@router.post(
    "/{workflow_id}/runs", response_model=WorkflowRunRead, status_code=status.HTTP_201_CREATED
)
async def run_workflow(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    payload: WorkflowRunRequest,
    db: DbSession,
    membership: Membership = Depends(_RUNNER),  # noqa: B008
) -> WorkflowRun:
    """Trigger a workflow: record the plan, gate the findings, store the result.

    The scan actions in the plan are *queued* by the assessment path, not
    executed here — one code path for "run an assessment" rather than two, and
    the same authorization check applies to both. What this endpoint owns is
    the trigger, the plan, and the gate decision.

    A disabled workflow is refused rather than silently run: an operator who
    turned it off should not be able to trigger it by URL.
    """
    workflow = await _load(db, organization_id, workflow_id)
    if not workflow.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="workflow is disabled")

    trigger = trigger_from(
        workflow,
        ref=payload.ref,
        commit=payload.commit,
        pull_number=payload.pull_number,
        actor=str(membership.user_id),
    )
    try:
        run, outcome = await start(db, workflow, trigger)
        await finish(db, run, workflow, outcome, actions_detail="triggered through the API")
    except GateConfigError as exc:
        # `finish` already refuses a stored gate it cannot parse; this catches
        # the same failure raised before a run row exists. Either way the
        # answer is a refusal, never a pass.
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f"gate configuration is invalid: {exc}"
        ) from exc
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    await db.commit()
    await db.refresh(run)
    if run.status == WorkflowStatus.REFUSED.value:
        # Persisted and returned with its reason. A refusal is a result, and
        # hiding it behind an error status would lose the stored record.
        pass
    if outcome.gate_passed is False:
        # Queued after this request's own commit, same reasoning as
        # `notify_run_finished`: a hanging channel must never hold this
        # request open, and a notification failure must never surface as
        # this endpoint's own failure.
        from app.workers.notifications import notify_workflow_gate_failed

        notify_workflow_gate_failed.delay(str(run.id))
    return run


@router.get("/{workflow_id}/runs", response_model=list[WorkflowRunRead])
async def list_workflow_runs(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(_READER),  # noqa: B008
    limit: int = 50,
) -> list[WorkflowRun]:
    await _load(db, organization_id, workflow_id)
    result = await db.execute(
        select(WorkflowRun)
        .where(
            WorkflowRun.organization_id == organization_id,
            WorkflowRun.workflow_id == workflow_id,
        )
        .order_by(WorkflowRun.created_at.desc())
        .limit(max(1, min(limit, 200)))
    )
    return list(result.scalars().all())


async def _load_run(
    db: DbSession, organization_id: uuid.UUID, workflow_id: uuid.UUID, run_id: uuid.UUID
) -> WorkflowRun:
    run = (
        await db.execute(
            select(WorkflowRun).where(
                WorkflowRun.id == run_id,
                WorkflowRun.workflow_id == workflow_id,
                WorkflowRun.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="workflow run not found")
    return run


@router.post("/{workflow_id}/webhook-secret", response_model=WorkflowWebhookSecretRead)
async def rotate_webhook_secret(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(_ADMIN),  # noqa: B008
) -> WorkflowWebhookSecretRead:
    """Generate a fresh webhook secret and enable inbound acceptance for
    this workflow. Same role tier as `create_workflow`/`update_workflow` —
    enabling inbound automation is a configuration change. The secret is
    returned in plaintext exactly once; it is never stored or shown again.
    """
    workflow = await _load(db, organization_id, workflow_id)
    settings = get_settings()
    secret = generate_secret()
    try:
        workflow.webhook_secret_encrypted = encrypt_secret(
            secret, key=settings.webhook_secret_encryption_key_bytes
        )
    except WebhookEncryptionNotConfigured as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    workflow.webhook_enabled = True
    await record_event(
        db,
        action="workflow.webhook_secret_rotated",
        resource_type="workflow",
        resource_id=str(workflow.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        metadata={"name": workflow.name},
    )
    await db.commit()
    base = (get_settings().public_base_url or "").rstrip("/")
    return WorkflowWebhookSecretRead(
        secret=secret, webhook_url=f"{base}/api/v1/webhooks/workflows/{workflow.id}"
    )


@router.post("/{workflow_id}/runs/{run_id}/approve", response_model=WorkflowRunRead)
async def approve_workflow_run(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    run_id: uuid.UUID,
    _payload: WorkflowRunApprovalRequest,
    db: DbSession,
    membership: Membership = Depends(_RUNNER),  # noqa: B008
) -> WorkflowRun:
    """Resume a run paused by an unattended trigger (Celery Beat or the
    inbound webhook) whose plan would queue a scan-touching action. Same
    role tier as `run_workflow`/the agent's `start_scan`/`run_workflow`
    tools — approving *is* authorizing a scan.
    """
    workflow = await _load(db, organization_id, workflow_id)
    run = await _load_run(db, organization_id, workflow_id, run_id)
    try:
        run = await workflow_service.approve(
            db, run, workflow, approved_by_user_id=membership.user_id
        )
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.commit()
    await db.refresh(run)
    return run


@router.post("/{workflow_id}/runs/{run_id}/reject", response_model=WorkflowRunRead)
async def reject_workflow_run(
    organization_id: uuid.UUID,
    workflow_id: uuid.UUID,
    run_id: uuid.UUID,
    payload: WorkflowRunRejectionRequest,
    db: DbSession,
    membership: Membership = Depends(_RUNNER),  # noqa: B008
) -> WorkflowRun:
    workflow = await _load(db, organization_id, workflow_id)
    run = await _load_run(db, organization_id, workflow_id, run_id)
    try:
        run = await workflow_service.reject(
            db, run, workflow, rejected_by_user_id=membership.user_id, reason=payload.reason
        )
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    await db.commit()
    await db.refresh(run)
    return run
