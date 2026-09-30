"""Delivering notifications out of band, and retrying the ones that failed.

Out of band on purpose. A notification is not part of an assessment's result,
so a Slack outage must not fail a run or hold a request open — the run records
the event and returns, and this worker does the sending.

The retry sweep is idempotent in the way that matters: it selects rows whose
`next_attempt_at` has passed and whose status is still retryable, and each
attempt advances both. Two sweeps running at once would at worst send a
notification twice, which is the right way round for an alerting path.
"""

from __future__ import annotations

import asyncio
import uuid

import structlog
from sqlalchemy import select

from app.core.config import get_settings
from app.core.integrations.dispatch import event_from_snapshot
from app.core.integrations.service import attempt, due_deliveries, enqueue
from app.db.session import dispose_engine, get_session_factory
from app.models.integration import DeliveryStatus, NotificationChannel
from app.workers.celery_app import celery_app

logger = structlog.get_logger(__name__)

#: How many due deliveries one sweep handles. Bounded so a backlog is worked
#: through over several sweeps rather than in one task that runs for an hour.
SWEEP_LIMIT = 50


async def _deliver_due(limit: int = SWEEP_LIMIT) -> int:
    settings = get_settings()
    delivered = 0
    factory = get_session_factory()
    async with factory() as db:
        deliveries = await due_deliveries(db, limit=limit)
        for delivery in deliveries:
            channel = await db.get(NotificationChannel, delivery.channel_id)
            if channel is None or not channel.enabled:
                # The channel was deleted or disabled after the row was
                # written. Nothing to deliver to, and nothing to retry.
                delivery.status = DeliveryStatus.REFUSED.value
                delivery.next_attempt_at = None
                delivery.last_error = "channel no longer enabled"
                continue
            snapshot = delivery.event_json or {}
            try:
                event = event_from_snapshot(delivery.organization_id, snapshot)
            except (KeyError, ValueError) as exc:
                delivery.status = DeliveryStatus.REFUSED.value
                delivery.next_attempt_at = None
                delivery.last_error = f"unreadable event snapshot: {exc}"[:400]
                continue
            result = await attempt(db, delivery, channel, event, settings=settings)
            if result.delivered:
                delivered += 1
        await db.commit()
    return delivered


@celery_app.task(name="kervy.deliver_notifications")
def deliver_notifications(limit: int = SWEEP_LIMIT) -> int:
    """Sweep due deliveries. Scheduled, and also called after a run finishes."""

    async def _run() -> int:
        try:
            return await _deliver_due(limit)
        finally:
            await dispose_engine()

    return asyncio.run(_run())


async def _notify_run(run_id: uuid.UUID) -> int:
    """Build the run's completion event, record intent, then deliver."""
    from app.core.integrations.dispatch import event_for_finding, event_for_retest, event_for_run
    from app.models.assessment_run import AssessmentRun, RunKind
    from app.models.finding import Finding
    from app.models.retest import RetestResult, RetestVerdict
    from app.models.target import Target

    factory = get_session_factory()
    async with factory() as db:
        run = await db.get(AssessmentRun, run_id)
        if run is None:
            return 0
        # `last_run_id`, not `first_run_id`: the counts describe what this
        # run found, which includes findings it saw again. A notification
        # that counted only new findings would report a clean run on a
        # target whose criticals are all still open.
        result = await db.execute(select(Finding.severity).where(Finding.last_run_id == run_id))
        counts: dict[str, int] = {}
        for (severity,) in result.all():
            key = str(getattr(severity, "value", severity)).lower()
            counts[key] = counts.get(key, 0) + 1
        # Selected explicitly rather than read off `run.target`: that
        # relationship is lazy, and a lazy load under asyncpg raises
        # MissingGreenlet instead of quietly doing the query.
        target_name: str | None = None
        if run.target_id is not None:
            target_name = (
                await db.execute(select(Target.name).where(Target.id == run.target_id))
            ).scalar_one_or_none()
        event = event_for_run(
            organization_id=run.organization_id,
            run_id=run_id,
            status=run.status.value,
            target_name=target_name,
            counts=counts,
        )
        queued = list(await enqueue(db, event))

        # A retest gets a second, more specific event alongside its own
        # assessment.completed — the verdict counts are the whole reason a
        # retest was requested, and a channel subscribed to retest.completed
        # only should not have to infer them from a run summary's generic
        # facts.
        if run.kind is RunKind.RETEST:
            verdict_counts: dict[str, int] = {}
            verdict_rows = (
                await db.execute(select(RetestResult.verdict).where(RetestResult.run_id == run_id))
            ).all()
            for (verdict,) in verdict_rows:
                key = str(getattr(verdict, "value", verdict))
                verdict_counts[key] = verdict_counts.get(key, 0) + 1
            queued.extend(
                await enqueue(
                    db,
                    event_for_retest(
                        organization_id=run.organization_id,
                        run_id=run_id,
                        target_name=target_name,
                        reproduced=verdict_counts.get(RetestVerdict.REPRODUCED.value, 0),
                        not_reproduced=verdict_counts.get(RetestVerdict.NOT_REPRODUCED.value, 0),
                        not_tested=verdict_counts.get(RetestVerdict.NOT_TESTED.value, 0),
                    ),
                )
            )

        # Findings first seen in this run each get their own event, so a
        # channel subscribed to `finding.critical` pages on the finding rather
        # than on a run summary that buries it among counts.
        new_findings = (
            await db.execute(
                select(Finding).where(Finding.first_run_id == run_id, Finding.last_run_id == run_id)
            )
        ).scalars()
        for finding in new_findings:
            queued.extend(
                await enqueue(
                    db,
                    event_for_finding(
                        organization_id=run.organization_id,
                        finding_id=finding.id,
                        title=finding.title,
                        severity=str(getattr(finding.severity, "value", finding.severity)),
                        target_name=target_name,
                        run_id=run_id,
                    ),
                )
            )

        await db.commit()
        if not queued:
            return 0
    # One sweep covers everything just queued, and the bound keeps a run that
    # found a hundred new criticals from becoming one very long task.
    return await _deliver_due(limit=max(len(queued), SWEEP_LIMIT))


@celery_app.task(name="kervy.notify_run_finished")
def notify_run_finished(run_id: str) -> int:
    """Fan a finished run out to its organization's subscribed channels.

    Separate from `kervy.run_assessment` so that a channel that hangs cannot
    hold a run's task open, and so a notification failure is never recorded as
    an assessment failure.
    """

    async def _run() -> int:
        try:
            return await _notify_run(uuid.UUID(run_id))
        except Exception:  # noqa: BLE001 - never let a notification fail a run
            logger.exception("notify_run_finished_failed", run_id=run_id)
            return 0
        finally:
            await dispose_engine()

    return asyncio.run(_run())


async def _notify_workflow_gate_failed(workflow_run_id: uuid.UUID) -> int:
    """Build the `gate.failed` event for one workflow run, then deliver.

    Reads the run's own stored decision rather than taking counts/reasons as
    arguments — by the time this task runs, `finish()`'s transaction has
    already committed them, and reading them back is the same "never trust a
    caller's snapshot of state that might have moved on" reasoning
    `_notify_run` already follows for `target_name`.
    """
    from app.core.integrations.dispatch import event_for_workflow_gate
    from app.models.workflow import Workflow, WorkflowRun

    factory = get_session_factory()
    async with factory() as db:
        run = await db.get(WorkflowRun, workflow_run_id)
        if run is None or run.gate_passed is not False:
            # Gone, or the decision moved on since this task was scheduled
            # (re-triggered, gate reconfigured) — nothing to report.
            return 0
        workflow = await db.get(Workflow, run.workflow_id)
        if workflow is None:
            return 0
        event = event_for_workflow_gate(
            organization_id=run.organization_id,
            workflow_run_id=run.id,
            workflow_name=workflow.name,
            reasons=list(run.gate_reasons or []),
            counts=dict(run.gate_counts or {}),
        )
        queued = list(await enqueue(db, event))
        await db.commit()
        if not queued:
            return 0
    return await _deliver_due(limit=max(len(queued), SWEEP_LIMIT))


@celery_app.task(name="kervy.notify_workflow_gate_failed")
def notify_workflow_gate_failed(workflow_run_id: str) -> int:
    """Fan a failed workflow gate out to its organization's subscribed
    channels. Scheduled from each of `finish()`'s three call sites, after
    their own commit — same reasoning as `notify_run_finished`: a hanging
    channel must never hold a workflow trigger's request open.
    """

    async def _run() -> int:
        try:
            return await _notify_workflow_gate_failed(uuid.UUID(workflow_run_id))
        except Exception:  # noqa: BLE001 - never let a notification fail a workflow run
            logger.exception("notify_workflow_gate_failed_failed", workflow_run_id=workflow_run_id)
            return 0
        finally:
            await dispose_engine()

    return asyncio.run(_run())
