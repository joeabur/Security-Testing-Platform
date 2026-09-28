"""Assets *found*, as distinct from assets *authorized* (the security
assessment / pentest module — docs/roadmap.md).

A `Target` is an authorized, scannable unit: it carries its own
`Authorization` and `RulesOfEngagementRecord` row. A `DiscoveredAsset` is
something a scan turned up incidentally — a subdomain under a domain target,
a resource in a cloud account, a container image referenced by one, an open
service on a VM — that has none of that. It is never itself scanned more
deeply, and it never expands what a run may touch.

Promotion to a real `Target` (with its own authorization and scope) is a
separate, explicit human action — `promoted_to_target_id` is null until
someone does that. Nothing in this module sets it automatically; that is
the entire mechanism behind "never automatically expand testing to targets
outside the approved scope."
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssetKind(enum.StrEnum):
    """What kind of thing was found. Deliberately more granular than
    `TargetKind` — a single DOMAIN target can turn up many SUBDOMAIN assets,
    a single CLOUD_ACCOUNT target many CLOUD_RESOURCE assets. Extending this
    with a new discovery shape (e.g. a new cloud resource category) never
    needs a migration beyond adding the enum value here."""

    SUBDOMAIN = "subdomain"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER_IMAGE = "container_image"
    OPEN_SERVICE = "open_service"


class DiscoveredAsset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "discovered_assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # The target whose engine found this — a DOMAIN target's subdomain
    # enumeration, a CLOUD_ACCOUNT target's resource listing, etc.
    parent_target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    asset_kind: Mapped[AssetKind] = mapped_column(
        Enum(AssetKind, name="asset_kind_enum"), nullable=False
    )
    # The asset's own identity — a hostname, an ARN, an image reference, a
    # `host:port` pair. Free text because its shape depends on `asset_kind`.
    identifier: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Whatever the discovering engine learned about it (resource type, open
    # ports, TLS details, tags) — descriptive, never itself a scan result.
    asset_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # A rollup an engine may set when it also fingerprints obvious exposure
    # (e.g. a publicly readable bucket) without a full assessment run —
    # informational only, never a substitute for `Finding`.
    risk_summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # Null until a human explicitly promotes this discovery into its own
    # authorized, scannable Target. Never set by a scanner.
    promoted_to_target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
