"""Persist a queued run, audit it, and hand it to the worker.

Promoted out of `app/api/v1/routers/runs.py` (where it was already imported
by `remediation.py` and `repositories.py` — three callers of one HTTP
router's private function) so the native agent's `start_scan` tool can queue
a run the same way, without an `app/core` module importing from `app/api`.
Takes `ip_address` rather than a FastAPI `Request`, and a bare `user_id`
rather than a `Membership` row: the only thing any caller ever read off
either was an id — a tool call has no request to hand it, and the native
agent's `AgentContext` carries a `user_id` but never a loaded `Membership`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.models.assessment_run import AssessmentRun, RunEvent, RunEventKind, RunKind, RunStatus
from app.models.target import Target
from app.workers.celery_app import celery_app


async def queue_run(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    target: Target,
    user_id: uuid.UUID,
    profile: str,
    safe_mode: bool,
    confirmed_at: datetime,
    ip_address: str | None = None,
    kind: RunKind = RunKind.ASSESSMENT,
    retest_of_run_id: uuid.UUID | None = None,
    retest_baseline: list[dict[str, Any]] | None = None,
) -> AssessmentRun:
    """Shared by assessments, retests, and the agent's `start_scan` tool on
    purpose. A retest — or an AI-initiated scan — is a scan, so it goes
    through the same authorization record, the same audit event and the same
    queue rather than a parallel path that would have to re-earn each of
    those properties, and could quietly diverge from them later.
    """
    run = AssessmentRun(
        organization_id=organization_id,
        target_id=target.id,
        status=RunStatus.QUEUED,
        kind=kind,
        retest_of_run_id=retest_of_run_id,
        retest_baseline=retest_baseline or [],
        profile=profile,
        safe_mode=safe_mode,
        created_by_user_id=user_id,
        authorization_confirmed_by_user_id=user_id,
        authorization_confirmed_at=confirmed_at,
        queued_at=confirmed_at,
    )
    db.add(run)
    await db.flush()

    db.add(
        RunEvent(
            run_id=run.id,
            kind=RunEventKind.QUEUED,
            message=f"{kind.value.capitalize()} queued for target {target.name}",
            payload={
                "profile": profile,
                "safe_mode": safe_mode,
                "kind": kind.value,
                "findings_checked": len(retest_baseline or []),
            },
        )
    )
    await record_event(
        db,
        action=f"{kind.value}.create",
        resource_type="assessment_run",
        resource_id=str(run.id),
        result="allow",
        organization_id=organization_id,
        user_id=user_id,
        ip_address=ip_address,
        metadata={
            "target_id": str(target.id),
            "profile": profile,
            "kind": kind.value,
            "findings_checked": len(retest_baseline or []),
        },
    )
    await db.commit()

    try:
        async_result = celery_app.send_task("aegis.run_assessment", args=[str(run.id)])
        run.celery_task_id = async_result.id
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - broker down is an operator problem, reported as such
        run.status = RunStatus.FAILED
        run.error_message = f"could not queue run: {exc}"
        run.finished_at = datetime.now(UTC)
        await db.commit()
    return run
