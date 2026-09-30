"""Per-organization tool configuration: enable/disable and a stricter
minimum-role override, read from `AgentTool` rows.

`AgentTool.minimum_role_override` existed since the agent's Phase 2 with no
code that ever read it — this module is that missing read (and write-time
guard) path. Loaded once per request (`load_tool_config`) rather than once
per tool call: a plan can touch a dozen tools, and a dozen separate queries
for one row each would be wasteful the same way a per-request settings
lookup elsewhere in this codebase is batched rather than repeated.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.tools.contract import Tool
from app.models.agent import AgentTool
from app.models.organization import Role

ToolConfig = Mapping[str, AgentTool]

_ORDER = Role.seniority_order()


def _rank(role: Role) -> int:
    """Lower rank is more privileged — `Role.seniority_order()`'s own index."""
    return _ORDER.index(role)


async def load_tool_config(db: AsyncSession, organization_id: uuid.UUID) -> ToolConfig:
    """One row per tool this organization has ever configured; a tool with
    no row here uses the code registry's own defaults untouched."""
    result = await db.execute(
        select(AgentTool).where(AgentTool.organization_id == organization_id)
    )
    return {row.tool_name: row for row in result.scalars().all()}


def effective_minimum_role(tool: Tool, config: ToolConfig) -> Role:
    """The code default, or the org's override — whichever demands *more*
    privilege. An override can only ever raise the bar
    (`app/models/agent.py`'s own docstring): `validate_role_override` below
    already refuses to store one that would lower it, but this function
    does not trust that a stored value necessarily passed through that
    guard — the same defence-in-depth reasoning `exploitation_service.py`'s
    three-allowlist gate documents for not trusting a single check alone.
    """
    row = config.get(tool.name)
    if row is None or row.minimum_role_override is None:
        return tool.minimum_role
    try:
        override = Role(row.minimum_role_override)
    except ValueError:
        return tool.minimum_role
    return override if _rank(override) < _rank(tool.minimum_role) else tool.minimum_role


def is_tool_enabled(tool: Tool, config: ToolConfig) -> bool:
    row = config.get(tool.name)
    return True if row is None else row.enabled


def permitted_tools(tools: list[Tool], config: ToolConfig, *, effective_role: Role) -> list[Tool]:
    """Every registered tool this org has not disabled, and whose
    (possibly raised) minimum role this caller meets."""
    return [
        tool
        for tool in tools
        if is_tool_enabled(tool, config)
        and effective_role.at_least(effective_minimum_role(tool, config))
    ]


def validate_role_override(tool: Tool, override: Role | None) -> None:
    """Reject a write that would lower a tool's minimum role below its code
    default — the one invariant `AgentTool.minimum_role_override`'s own
    docstring names, enforced here at write time rather than left to the
    read-time clamp in `effective_minimum_role` alone.
    """
    if override is not None and _rank(override) > _rank(tool.minimum_role):
        raise ValueError(
            f"{tool.name}'s minimum role cannot be set below its code default "
            f"({tool.minimum_role.value!r})"
        )
