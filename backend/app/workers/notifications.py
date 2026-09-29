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
    from app.core.integrations.dispatch import event_for_finding, event_for_run
    from app.models.assessment_run import AssessmentRun
    from app.models.finding import Finding
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
