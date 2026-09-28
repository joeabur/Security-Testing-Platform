"""Persisting a domain engine's discoveries as `DiscoveredAsset` rows.

A `DiscoveredAsset` is something *found*, not something authorized — this
function only ever writes to that table, never to `Target`/`Authorization`.
Promoting a discovery into a scannable target is a separate, explicit human
action (see `app/models/discovered_asset.py`'s `promoted_to_target_id`),
never something a run does on its own.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.contract import DiscoveredSubdomain
from app.models.discovered_asset import AssetKind, DiscoveredAsset


async def promote_discovered_subdomains(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    parent_target_id: uuid.UUID,
    subdomains: list[DiscoveredSubdomain],
) -> list[DiscoveredAsset]:
    """Upsert on `(parent_target_id, asset_kind, identifier)` — a subdomain
    seen again updates `last_seen` and its metadata rather than duplicating
    the row, the same "seen again" handling `promote_run_results` gives a
    finding re-observed on a later run.
    """
    now = datetime.now(UTC)
    rows: list[DiscoveredAsset] = []
    for item in subdomains:
        existing = (
            await db.execute(
                select(DiscoveredAsset).where(
                    DiscoveredAsset.organization_id == organization_id,
                    DiscoveredAsset.parent_target_id == parent_target_id,
                    DiscoveredAsset.asset_kind == AssetKind.SUBDOMAIN,
                    DiscoveredAsset.identifier == item.hostname,
                )
            )
        ).scalar_one_or_none()

        metadata = {
            "source": item.source.value,
            "resolved_ips": list(item.resolved_ips),
            "probed": item.probed,
        }

        if existing is None:
            row = DiscoveredAsset(
                organization_id=organization_id,
                parent_target_id=parent_target_id,
                asset_kind=AssetKind.SUBDOMAIN,
                identifier=item.hostname,
                asset_metadata=metadata,
                first_seen=now,
                last_seen=now,
            )
            db.add(row)
            rows.append(row)
        else:
            existing.last_seen = now
            existing.asset_metadata = metadata
            rows.append(existing)

    await db.flush()
    return rows
