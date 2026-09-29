"""What a container assessment is, and what it needs to run.

Mirrors `app/core/domain/contract.py`'s shape: the engine's input is a
frozen dataclass resolved once from `RulesOfEngagementRecord.asset_scope`
(`resolve_container_scope`), never re-read from the RoE mid-run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ContainerTarget:
    """The input to the container engine.

    `allow_live_pull` defaults to `False` even though `resolve_container_scope`
    permits either value — the engine itself treats an unset-by-omission scope
    the same way `resolve_domain_scope`'s empty pattern list is treated
    elsewhere: silence means "do not reach the network", not "everything is
    permitted".
    """

    image_ref: str
    allowed_registries: tuple[str, ...] = ()
    allow_live_pull: bool = False


@dataclass(frozen=True)
class ToolInvocationRecord:
    """One subprocess call this engine made, in the shape
    `app.core.container.service.record_tool_invocations` persists into
    `RunToolInvocation` — the first engine on this platform to actually
    populate that table (docs/roadmap.md, Pentest module Phase 1's
    foundation work).
    """

    tool_name: str
    tool_version: str | None
    network_use: str
    command_summary: str
    started_at: datetime
    finished_at: datetime | None
    exit_status: int | None
