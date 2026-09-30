"""Whether a tool call is allowed to run — three independent checks.

Mirrors `app/core/assistant/autonomy.py`'s own separation: a role ceiling
(raised, never lowered, by an organization's `AgentTool` configuration — see
`app.core.agent.tool_config`), a per-organization enable/disable switch, and
a SENSITIVE-tier approval gate (never bypassed by configuration, the same
way `TARGET_TOUCHING` is checked independently of autonomy mode there).
None of the three can substitute for another — a disabled tool is refused
even for an OWNER, a role-insufficient caller is refused even for an
enabled tool, and no approval can substitute for either — all three must
pass.
"""

from __future__ import annotations

from app.core.agent.tools.contract import RiskLevel, Tool
from app.models.organization import Role


class ToolPermissionError(PermissionError):
    """The caller's effective role does not meet this tool's minimum."""


class ToolDisabledError(ToolPermissionError):
    """This organization has disabled this tool (`AgentTool.enabled`).

    A subclass of `ToolPermissionError`, not a sibling — every existing
    caller that already catches `ToolPermissionError` (`run_plan`,
    `call_tool`) handles this the same way, as a permission denial, with
    no separate branch required.
    """


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


def authorize_role(effective_role: Role, tool: Tool, *, minimum_role: Role | None = None) -> None:
    """Raise unless the caller's role meets this tool's minimum.

    Takes the role directly rather than the whole `AgentContext` so a
    permission decision never needs a database session to answer — the same
    reason `Role.at_least` itself takes no session. `minimum_role`, when
    given, is the org's own (possibly raised) effective minimum
    (`app.core.agent.tool_config.effective_minimum_role`) — the caller
    already resolved any per-organization override, so this function does
    not need the tool-config rows itself; it defaults to the tool's own
    code-level minimum when omitted, unchanged from before this parameter
    existed.
    """
    required = minimum_role if minimum_role is not None else tool.minimum_role
    if not effective_role.at_least(required):
        raise ToolPermissionError(f"{tool.name} requires role {required.value!r} or higher")


def authorize_enabled(tool: Tool, *, enabled: bool) -> None:
    """Raise unless this organization has this tool enabled.

    `enabled` is the caller's already-resolved
    `app.core.agent.tool_config.is_tool_enabled` result, for the same
    reason `authorize_role` takes an already-resolved minimum role rather
    than the tool-config rows themselves.
    """
    if not enabled:
        raise ToolDisabledError(f"{tool.name} is disabled for this organization")


def authorize_sensitive(tool: Tool, *, approved: bool) -> None:
    """Raise unless a SENSITIVE tool's call has been explicitly approved.

    A no-op for READ_ONLY and STANDARD tools regardless of `approved` — the
    approval gate exists only for the tier that can change platform state or
    touch a target, matching `docs/BUILD_SPEC.md`'s three-tier classification.
    """
    if tool.risk_level is RiskLevel.SENSITIVE and not approved:
        raise ApprovalRequiredError(tool)


def authorize_tool(
    effective_role: Role,
    tool: Tool,
    *,
    approved: bool = False,
    minimum_role: Role | None = None,
    enabled: bool = True,
) -> None:
    """All three checks, in order: a caller who cannot use the tool at all
    (disabled, then role) learns that before learning it also needed
    approval."""
    authorize_enabled(tool, enabled=enabled)
    authorize_role(effective_role, tool, minimum_role=minimum_role)
    authorize_sensitive(tool, approved=approved)
