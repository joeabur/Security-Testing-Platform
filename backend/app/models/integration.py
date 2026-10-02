"""Notification channels and their delivery attempts (docs/BUILD_SPEC.md §27).

Note what is *not* on `NotificationChannel`: no webhook URL, no SMTP
password, no bearer token. A channel names the environment variable that
holds its credential and stores a redacted display form so an operator can
recognise it in a list. §5 says credentials are never stored in the database;
a Slack incoming webhook URL is a credential because its path is the token,
so the whole URL is held by reference.

`NotificationDelivery` is an attempt log, not a queue of pending work in the
messaging sense — the Celery task owns scheduling. It exists so that "did
the alert go out?" has an answer that survives a worker restart, and so a
dead-lettered delivery is visible rather than silently dropped.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class DeliveryStatus(StrEnum):
    """`DEAD_LETTER` is terminal and deliberately distinct from `FAILED`.

    A failed attempt will be retried; a dead-lettered delivery will not, and
    an operator needs to be able to list exactly those without reading retry
    counters.
    """

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"
    #: Refused before sending: a misconfigured channel, a host the policy
    #: does not permit, or a payload that tripped the secret detector. Never
    #: retried, because the same configuration fails the same way.
    REFUSED = "refused"


class NotificationChannel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "notification_channels"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_channel_org_name"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)

    #: Name of the environment variable holding the webhook URL. Never the URL.
    endpoint_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: What an operator sees instead: scheme, host and path shape only.
    endpoint_redacted: Mapped[str | None] = mapped_column(String(300), nullable=True)

    #: Generic webhook only: env var holding the HMAC signing secret. A
    #: receiver that cannot verify a signature cannot tell our notification
    #: from anyone else's POST.
    signing_secret_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: Email only. The password is by reference like everything else.
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    smtp_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_password_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)
    from_address: Mapped[str | None] = mapped_column(String(320), nullable=True)
    recipients: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    #: Jira Cloud only. `jira_site` is the label before `.atlassian.net` —
    #: not a secret, but constrained to a DNS-label charset at the schema
    #: layer because it becomes part of a request URL (`policy.py`). The
    #: API token is by reference like every other credential; the email
    #: identifies the Atlassian account the token belongs to and is not
    #: itself secret.
    jira_site: Mapped[str | None] = mapped_column(String(63), nullable=True)
    jira_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    jira_api_token_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)
    jira_project_key: Mapped[str | None] = mapped_column(String(32), nullable=True)
    jira_issue_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    #: ServiceNow only. Same shape as the Jira fields above: `servicenow_instance`
    #: is a DNS label, `servicenow_table` is the Table API table name (also
    #: constrained, since it too becomes part of a request URL), and the
    #: password is by reference.
    servicenow_instance: Mapped[str | None] = mapped_column(String(63), nullable=True)
    servicenow_table: Mapped[str | None] = mapped_column(String(64), nullable=True)
    servicenow_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    servicenow_password_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)

    #: Event types this channel is subscribed to, as `EventType` values.
    events: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    #: Floor on finding severity. Null means every subscribed event goes out.
    min_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class NotificationDelivery(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "notification_deliveries"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    channel_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Identifier of the thing the event is about, so a reader can join back
    #: to the run or finding without the payload being stored.
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=DeliveryStatus.PENDING.value
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Redacted before it is written, and short. Never a response body.
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    #: The ticket a `TICKET_*` channel's creation call returned — see
    #: `DeliveryResult.external_reference`. Null for every other kind.
    external_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)

    #: The event's scalar fields, kept so a dead-lettered delivery can be
    #: understood and replayed. Never the rendered body, which for a signed
    #: webhook would be re-signed anyway, and never anything from a target.
    event_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
