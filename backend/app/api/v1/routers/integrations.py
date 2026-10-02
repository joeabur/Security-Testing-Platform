"""Notification channel management (docs/BUILD_SPEC.md §27).

Admin and above to create, change or delete a channel, because a channel is a
standing outbound path for the organization's findings and severities — the
same reasoning that puts API keys at admin. Reading channels and their delivery
history is analyst, so the people triaging findings can see whether an alert
actually went out without being able to re-point it.

The test-delivery endpoint sends a fixed, synthetic event. It is the one place
that causes a real outbound request from an API call, so it is admin-only,
audited like any delivery, and carries nothing from the organization's data.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.config import get_settings
from app.core.integrations.contract import (
    ChannelKind,
    EventType,
    IntegrationError,
    IntegrationEvent,
)
from app.core.integrations.dispatch import event_snapshot
from app.core.integrations.policy import (
    resolve_sentinel_destination,
    resolve_smtp_host,
    resolve_webhook_destination,
)
from app.core.integrations.service import attempt
from app.models.integration import DeliveryStatus, NotificationChannel, NotificationDelivery
from app.models.organization import Membership, Role
from app.schemas.integration import (
    ChannelCreate,
    ChannelRead,
    ChannelTestResult,
    ChannelUpdate,
    DeliveryRead,
)

router = APIRouter(
    prefix="/organizations/{organization_id}/notification-channels", tags=["integrations"]
)


async def _load(
    db: DbSession, organization_id: uuid.UUID, channel_id: uuid.UUID
) -> NotificationChannel:
    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.organization_id == organization_id,
        )
    )
    channel = result.scalar_one_or_none()
    if channel is None:
        # 404, not 403: a channel in another organization must not be
        # distinguishable from one that does not exist.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="notification channel not found")
    return channel


@router.post("", response_model=ChannelRead, status_code=status.HTTP_201_CREATED)
async def create_channel(
    organization_id: uuid.UUID,
    payload: ChannelCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> NotificationChannel:
    settings = get_settings()
    redacted: str | None = None

    # Resolve the destination now, so a channel that could never deliver is
    # refused at creation rather than discovered during an incident. This also
    # produces the redacted display form, which is the only endpoint
    # representation the database ever holds.
    try:
        if payload.kind is ChannelKind.EMAIL_SMTP:
            resolve_smtp_host(
                payload.smtp_host or "", operator_hosts=settings.notify_allowed_smtp_hosts
            )
        elif payload.kind is ChannelKind.SIEM_SENTINEL:
            # No env-var-held secret to resolve here — the endpoint itself
            # carries no token — but the host still has to clear policy
            # before the channel is accepted.
            resolve_sentinel_destination(
                payload.sentinel_endpoint or "",
                operator_hosts=settings.notify_allowed_webhook_hosts,
            )
        else:
            destination = resolve_webhook_destination(
                payload.kind,
                payload.endpoint_env_var or "",
                operator_hosts=settings.notify_allowed_webhook_hosts,
            )
            redacted = destination.redacted
    except IntegrationError as exc:
        await record_event(
            db,
            action="notification_channel.refused",
            resource_type="notification_channel",
            result="deny",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"kind": payload.kind.value, "reason": str(exc)},
        )
        await db.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    channel = NotificationChannel(
        organization_id=organization_id,
        name=payload.name,
        kind=payload.kind.value,
        endpoint_env_var=payload.endpoint_env_var,
        endpoint_redacted=redacted,
        signing_secret_env_var=payload.signing_secret_env_var,
        auth_token_env_var=payload.auth_token_env_var,
        sentinel_endpoint=payload.sentinel_endpoint,
        azure_tenant_id=payload.azure_tenant_id,
        azure_client_id=payload.azure_client_id,
        azure_client_secret_env_var=payload.azure_client_secret_env_var,
        sentinel_dcr_immutable_id=payload.sentinel_dcr_immutable_id,
        sentinel_stream_name=payload.sentinel_stream_name,
        smtp_host=payload.smtp_host,
        smtp_port=payload.smtp_port,
        smtp_username=payload.smtp_username,
        smtp_password_env_var=payload.smtp_password_env_var,
        from_address=payload.from_address,
        recipients=list(payload.recipients),
        events=[event.value for event in payload.events],
        min_severity=payload.min_severity.value if payload.min_severity else None,
        enabled=payload.enabled,
        created_by_user_id=membership.user_id,
    )
    db.add(channel)
    await db.flush()

    await record_event(
        db,
        action="notification_channel.create",
        resource_type="notification_channel",
        resource_id=str(channel.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "kind": channel.kind,
            "endpoint": channel.endpoint_redacted or channel.smtp_host,
            "events": channel.events,
        },
    )
    await db.commit()
    await db.refresh(channel)
    return channel


@router.get("", response_model=list[ChannelRead])
async def list_channels(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> list[NotificationChannel]:
    result = await db.execute(
        select(NotificationChannel)
        .where(NotificationChannel.organization_id == organization_id)
        .order_by(NotificationChannel.created_at)
    )
    return list(result.scalars().all())


@router.patch("/{channel_id}", response_model=ChannelRead)
async def update_channel(
    organization_id: uuid.UUID,
    channel_id: uuid.UUID,
    payload: ChannelUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> NotificationChannel:
    channel = await _load(db, organization_id, channel_id)
    changed: dict[str, object] = {}
    if payload.events is not None:
        channel.events = [event.value for event in payload.events]
        changed["events"] = channel.events
    if payload.min_severity is not None:
        channel.min_severity = payload.min_severity.value
        changed["min_severity"] = channel.min_severity
    if payload.enabled is not None:
        channel.enabled = payload.enabled
        changed["enabled"] = channel.enabled
    if payload.recipients is not None:
        if channel.kind != ChannelKind.EMAIL_SMTP.value:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="recipients apply only to an email channel",
            )
        channel.recipients = list(payload.recipients)
        changed["recipients"] = len(channel.recipients)

    await record_event(
        db,
        action="notification_channel.update",
        resource_type="notification_channel",
        resource_id=str(channel.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata=changed,
    )
    await db.commit()
    await db.refresh(channel)
    return channel


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    organization_id: uuid.UUID,
    channel_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    channel = await _load(db, organization_id, channel_id)
    await record_event(
        db,
        action="notification_channel.delete",
        resource_type="notification_channel",
        resource_id=str(channel.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"kind": channel.kind, "name": channel.name},
    )
    await db.delete(channel)
    await db.commit()


@router.get("/{channel_id}/deliveries", response_model=list[DeliveryRead])
async def list_deliveries(
    organization_id: uuid.UUID,
    channel_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
    limit: int = 50,
) -> list[NotificationDelivery]:
    await _load(db, organization_id, channel_id)
    result = await db.execute(
        select(NotificationDelivery)
        .where(NotificationDelivery.channel_id == channel_id)
        .order_by(NotificationDelivery.created_at.desc())
        .limit(min(max(limit, 1), 200))
    )
    return list(result.scalars().all())


@router.post("/{channel_id}/test", response_model=ChannelTestResult)
async def test_channel(
    organization_id: uuid.UUID,
    channel_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> ChannelTestResult:
    channel = await _load(db, organization_id, channel_id)

    # A fixed synthetic event, carrying nothing from this organization's data:
    # a test delivery goes to a destination whose configuration is exactly what
    # is being questioned, so it must not be the thing that leaks a finding.
    event = IntegrationEvent(
        event_type=EventType.ASSESSMENT_COMPLETED,
        organization_id=organization_id,
        occurred_at_iso=datetime.now(UTC).isoformat(),
        title="Kervy test notification",
        severity=None,
        resource_type="notification_channel",
        resource_id=str(channel.id),
        facts={"test": "true"},
    )
    delivery = NotificationDelivery(
        organization_id=organization_id,
        channel_id=channel.id,
        event_type=event.event_type.value,
        resource_type="notification_channel",
        resource_id=str(channel.id),
        status=DeliveryStatus.PENDING.value,
        attempts=0,
        event_json=event_snapshot(event),
    )
    db.add(delivery)
    await db.flush()

    result = await attempt(db, delivery, channel, event)
    # A test delivery is a one-shot: a human is watching, so there is nothing
    # for a retry sweep to add.
    if not result.delivered:
        delivery.status = DeliveryStatus.REFUSED.value
        delivery.next_attempt_at = None
    await db.commit()
    return ChannelTestResult(
        delivered=result.delivered,
        status_code=result.status_code,
        detail=result.detail,
        delivery_id=delivery.id,
    )
