"""Persisting a VM engine run's subprocess invocations and discovered open
services.

Mirrors `app.core.container.service.record_tool_invocations` (own copy, not
imported — see `vm/contract.py::ToolInvocationRecord`'s docstring) for the
tool-invocation half, and `app.core.cloud.service.promote_discovered_buckets`
for the discovered-asset half: an open port is something found, not itself
a vulnerability — whether it is noteworthy is what the finding, not the
discovery row, says.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.vm.contract import OpenPort, ToolInvocationRecord, VmTarget
from app.models.discovered_asset import AssetKind, DiscoveredAsset
from app.models.tool_invocation import RunToolInvocation


async def record_tool_invocations(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    invocations: list[ToolInvocationRecord],
) -> list[RunToolInvocation]:
    rows: list[RunToolInvocation] = []
    for item in invocations:
        row = RunToolInvocation(
            organization_id=organization_id,
            run_id=run_id,
            tool_name=item.tool_name,
            tool_version=item.tool_version,
            network_use=item.network_use,
            command_summary=item.command_summary,
            started_at=item.started_at,
            finished_at=item.finished_at,
            exit_status=item.exit_status,
        )
        db.add(row)
        rows.append(row)
    if rows:
        await db.flush()
    return rows


async def promote_discovered_open_services(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    parent_target_id: uuid.UUID,
    target: VmTarget,
    open_ports: list[OpenPort],
) -> list[DiscoveredAsset]:
    """Upsert on `(parent_target_id, asset_kind, identifier)`, identifier
    `host:port` — the same upsert-on-rerun shape
    `promote_discovered_subdomains`/`promote_discovered_buckets` already
    establish for the other two discovery kinds.
    """
    now = datetime.now(UTC)
    rows: list[DiscoveredAsset] = []
    for item in open_ports:
        identifier = f"{target.host}:{item.port}"
        existing = (
            await db.execute(
                select(DiscoveredAsset).where(
                    DiscoveredAsset.organization_id == organization_id,
                    DiscoveredAsset.parent_target_id == parent_target_id,
                    DiscoveredAsset.asset_kind == AssetKind.OPEN_SERVICE,
                    DiscoveredAsset.identifier == identifier,
                )
            )
        ).scalar_one_or_none()

        metadata = {
            "protocol": item.protocol,
            "service": item.service,
            "product": item.product,
            "version": item.version,
        }

        if existing is None:
            row = DiscoveredAsset(
                organization_id=organization_id,
                parent_target_id=parent_target_id,
                asset_kind=AssetKind.OPEN_SERVICE,
                identifier=identifier,
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
