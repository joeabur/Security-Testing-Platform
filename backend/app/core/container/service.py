"""Persisting a container engine run's subprocess invocations.

The first engine on this platform to populate `run_tool_invocations`
(`app/models/tool_invocation.py`) — the table Pentest module Phase 1 added
as schema-only foundation, "recording exactly which tool ran, with which
network posture, per assessment run" (docs/roadmap.md). Engines stay
DB-free (`app.core.appsec.tooling.run_tool` makes no database call), so —
mirroring `app.core.domain.service.promote_discovered_subdomains` for
`DiscoveredAsset` — the write happens here, once, after the check finishes,
never inside the engine itself.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container.contract import ToolInvocationRecord
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
