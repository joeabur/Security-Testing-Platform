"""Whether a tool call is allowed to run — two independent checks.

Mirrors `app/core/assistant/autonomy.py`'s own separation: a role ceiling
(raised or lowered by configuration) and a SENSITIVE-tier approval gate
(never bypassed by configuration, the same way `TARGET_TOUCHING` is checked
independently of autonomy mode there). Raising a caller's role can never
substitute for an explicit approval, and no approval can substitute for the
role check — both must pass.
"""

from __future__ import annotations

from app.core.agent.tools.contract import RiskLevel, Tool
from app.models.organization import Role


class ToolPermissionError(PermissionError):
    """The caller's effective role does not meet this tool's minimum."""


class ApprovalRequiredError(Exception):
    """This is a SENSITIVE-tier tool and no approval has been recorded for
    this specific call. Never raised for READ_ONLY or STANDARD tools — see
    `docs/guardrails.md`'s three-tier classification."""

    def __init__(self, tool: Tool) -> None:
        super().__init__(
            f"{tool.name} is a sensitive action and requires explicit approval before it runs"
        )
        self.tool_name = tool.name
        self.risk_level = tool.risk_level
        self.description = tool.description


def authorize_role(effective_role: Role, tool: Tool) -> None:
    """Raise unless the caller's role meets this tool's minimum.

    Takes the role directly rather than the whole `AgentContext` so a
    permission decision never needs a database session to answer — the same
    reason `Role.at_least` itself takes no session.
    """
    if not effective_role.at_least(tool.minimum_role):
        raise ToolPermissionError(
            f"{tool.name} requires role {tool.minimum_role.value!r} or higher"
        )


def authorize_sensitive(tool: Tool, *, approved: bool) -> None:
    """Raise unless a SENSITIVE tool's call has been explicitly approved.

    A no-op for READ_ONLY and STANDARD tools regardless of `approved` — the
    approval gate exists only for the tier that can change platform state or
    touch a target, matching `docs/BUILD_SPEC.md`'s three-tier classification.
    """
    if tool.risk_level is RiskLevel.SENSITIVE and not approved:
        raise ApprovalRequiredError(tool)


def authorize_tool(effective_role: Role, tool: Tool, *, approved: bool = False) -> None:
    """Both checks, in order: a caller who cannot use the tool at all learns
    that before learning it also needed approval."""
    authorize_role(effective_role, tool)
    authorize_sensitive(tool, approved=approved)
