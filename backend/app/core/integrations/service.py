"""Persisting notification intent and outcome.

The split from `dispatch.py` is deliberate: that module is pure and takes no
database session, so the interesting decisions (who gets this, is it
retryable, when next) are testable without Postgres. This module is the thin
part that writes rows and audit events.

Every attempt produces an audit event, including the ones that never reached
the network. "Was the team told about that critical finding?" is a question an
incident review asks, and a refused delivery that left no trace is the answer
nobody can give.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.core.config import Settings, get_settings
from app.core.integrations.contract import DeliveryResult, IntegrationEvent
from app.core.integrations.dispatch import (
    ChannelSecrets,
    deliver_once,
    event_snapshot,
    select_channels,
    status_after,
)
from app.models.integration import DeliveryStatus, NotificationChannel, NotificationDelivery


async def channels_for(db: AsyncSession, organization_id: uuid.UUID) -> list[NotificationChannel]:
    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.organization_id == organization_id,
            NotificationChannel.enabled.is_(True),
        )
    )
    return list(result.scalars().all())


async def enqueue(db: AsyncSession, event: IntegrationEvent) -> list[NotificationDelivery]:
    """Record one pending delivery per subscribed channel.

    Written before any attempt, so a worker that dies mid-send leaves the work
    findable rather than lost.
    """
    channels = select_channels(await channels_for(db, event.organization_id), event)
    deliveries: list[NotificationDelivery] = []
    snapshot = event_snapshot(event)
    for channel in channels:
        delivery = NotificationDelivery(
            organization_id=event.organization_id,
            channel_id=channel.id,
            event_type=event.event_type.value,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            status=DeliveryStatus.PENDING.value,
            attempts=0,
            next_attempt_at=datetime.now(UTC),
            event_json=snapshot,
        )
        db.add(delivery)
        deliveries.append(delivery)
    if deliveries:
        await db.flush()
    return deliveries


async def attempt(
    db: AsyncSession,
    delivery: NotificationDelivery,
    channel: NotificationChannel,
    event: IntegrationEvent,
    *,
    secrets: ChannelSecrets | None = None,
    environ: Mapping[str, str] | None = None,
    settings: Settings | None = None,
) -> DeliveryResult:
    """Make one attempt, record where it landed, and audit it."""
    config = settings or get_settings()
    delivery.attempts += 1
    result = await deliver_once(
        channel,
        event,
        secrets=secrets,
        environ=environ,
        operator_webhook_hosts=config.notify_allowed_webhook_hosts,
        operator_smtp_hosts=config.notify_allowed_smtp_hosts,
        base_url=config.public_base_url,
    )
    status, next_attempt = status_after(result, delivery.attempts)
    delivery.status = status.value
    delivery.next_attempt_at = next_attempt
    delivery.status_code = result.status_code
    delivery.last_error = None if result.delivered else result.detail
    delivery.external_reference = result.external_reference
    if result.delivered:
        delivery.delivered_at = datetime.now(UTC)

    await record_event(
        db,
        action=f"notification.{status.value}",
        resource_type="notification_delivery",
        resource_id=str(delivery.id),
        # `deny` only for a refusal — a decision we made. A transport failure
        # is `error`: nobody decided anything, the send did not land.
        result=(
            "allow"
            if result.delivered
            else ("deny" if status is DeliveryStatus.REFUSED else "error")
        ),
        organization_id=delivery.organization_id,
        metadata={
            "channel_id": str(channel.id),
            "channel_kind": channel.kind,
            # The redacted endpoint form, never the resolved URL.
            "endpoint": channel.endpoint_redacted or channel.smtp_host,
            "event_type": delivery.event_type,
            "attempt": delivery.attempts,
            "status_code": result.status_code,
            "detail": delivery.last_error,
        },
    )
    return result


async def due_deliveries(
    db: AsyncSession, *, limit: int = 50, now: datetime | None = None
) -> Sequence[NotificationDelivery]:
    """Deliveries whose backoff has elapsed, oldest first.

    `DEAD_LETTER` and `REFUSED` are excluded by status, not by a retry count,
    so a change to `MAX_ATTEMPTS` cannot accidentally resurrect them.
    """
    moment = now or datetime.now(UTC)
    result = await db.execute(
        select(NotificationDelivery)
        .where(
            NotificationDelivery.status.in_(
                [DeliveryStatus.PENDING.value, DeliveryStatus.FAILED.value]
            ),
            NotificationDelivery.next_attempt_at.is_not(None),
            NotificationDelivery.next_attempt_at <= moment,
        )
        .order_by(NotificationDelivery.next_attempt_at)
        .limit(limit)
    )
    return list(result.scalars().all())
