"""Persisting a cloud engine run's inventoried buckets.

Mirrors `app.core.domain.service.promote_discovered_subdomains`: a bucket
is something *found*, not something authorized — this function only ever
writes to `DiscoveredAsset`, never to `Target`/`Authorization`. Promoting a
discovery into a scannable target of its own is a separate, explicit human
action.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cloud.contract import BucketExposure, CloudTarget
from app.models.discovered_asset import AssetKind, DiscoveredAsset


async def promote_discovered_buckets(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    parent_target_id: uuid.UUID,
    target: CloudTarget,
    exposures: list[BucketExposure],
) -> list[DiscoveredAsset]:
    """Upsert on `(parent_target_id, asset_kind, identifier)` — a bucket seen
    again updates `last_seen`/`risk_summary` rather than duplicating the
    row, the same "seen again" handling every other discovery service in
    this codebase gives a re-observed asset."""
    now = datetime.now(UTC)
    rows: list[DiscoveredAsset] = []
    for item in exposures:
        identifier = f"{target.provider}:{target.account_ref}:{item.name}"
        existing = (
            await db.execute(
                select(DiscoveredAsset).where(
                    DiscoveredAsset.organization_id == organization_id,
                    DiscoveredAsset.parent_target_id == parent_target_id,
                    DiscoveredAsset.asset_kind == AssetKind.CLOUD_RESOURCE,
                    DiscoveredAsset.identifier == identifier,
                )
            )
        ).scalar_one_or_none()

        metadata = {
            "provider": target.provider,
            "resource_type": "object_storage_bucket",
            "region": item.region,
        }
        risk_summary = {"is_public": item.is_public, "reason": item.public_reason}

        if existing is None:
            row = DiscoveredAsset(
                organization_id=organization_id,
                parent_target_id=parent_target_id,
                asset_kind=AssetKind.CLOUD_RESOURCE,
                identifier=identifier,
                asset_metadata=metadata,
                risk_summary=risk_summary,
                first_seen=now,
                last_seen=now,
            )
            db.add(row)
            rows.append(row)
        else:
            existing.last_seen = now
            existing.asset_metadata = metadata
            existing.risk_summary = risk_summary
            rows.append(existing)

    await db.flush()
    return rows
