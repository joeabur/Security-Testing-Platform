import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Identity, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    """Append-only audit log, mirrored from the hash-chained file log.

    Per docs/BUILD_SPEC.md §6.2 and §28: application code only ever inserts
    rows here — it must never update or delete one. `app.audit.service` has
    no such path at all, and the database itself refuses one too: migration
    `fc7a77b3611c` installs a `BEFORE UPDATE OR DELETE` trigger on
    `audit_logs` that raises, closing the gap a plain `REVOKE` alone would
    leave open (the runtime role is this table's owner in every deployment
    this project documents, and an owner can `GRANT` a revoked privilege
    back to themselves — a trigger has no such escape hatch, by any role).

    `seq` is a real autoincrementing integer (unlike the UUID primary key)
    so the hash chain has an unambiguous, monotonic ordering to chain over.
    """

    __tablename__ = "audit_logs"

    seq: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False)  # allow | deny | error
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
