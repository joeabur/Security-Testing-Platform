"""`app/core/agent/permissions.py`: the role ceiling and the SENSITIVE-tier
approval gate, checked independently — mirroring
`app/core/assistant/autonomy.py`'s own "a mode cannot grant what is not in
the table" design for `TARGET_TOUCHING`.
"""

from __future__ import annotations

import pytest

from app.core.agent.permissions import (
    ApprovalRequiredError,
    ToolDisabledError,
    ToolPermissionError,
    authorize_enabled,
    authorize_role,
    authorize_sensitive,
    authorize_tool,
)
from app.core.agent.tools.contract import RiskLevel, Tool, ToolNotFoundError
from app.models.organization import Role


async def _noop_handler(ctx: object, params: object) -> object:  # pragma: no cover - unused
    raise ToolNotFoundError("unused")


def _tool(risk_level: RiskLevel, minimum_role: Role) -> Tool:
    from pydantic import BaseModel

    class _Params(BaseModel):
        pass

    class _Result(BaseModel):
        pass

    return Tool(
        name="fake_tool",
        description="a fake tool for permission tests",
        input_model=_Params,
        output_model=_Result,
        risk_level=risk_level,
        minimum_role=minimum_role,
        handler=_noop_handler,  # type: ignore[arg-type]
    )


# --- role ceiling ------------------------------------------------------------


def test_a_caller_at_the_minimum_role_is_authorized() -> None:
    tool = _tool(RiskLevel.READ_ONLY, Role.ANALYST)
    authorize_role(Role.ANALYST, tool)  # no raise


def test_a_more_senior_caller_is_authorized() -> None:
    tool = _tool(RiskLevel.READ_ONLY, Role.ANALYST)
    authorize_role(Role.OWNER, tool)  # no raise


def test_a_less_senior_caller_is_refused() -> None:
    tool = _tool(RiskLevel.READ_ONLY, Role.ANALYST)
    with pytest.raises(ToolPermissionError):
        authorize_role(Role.VIEWER, tool)


def test_an_explicit_minimum_role_overrides_the_tools_own_default() -> None:
    """`minimum_role` stands in for an organization's own (already-resolved)
    `AgentTool.minimum_role_override` — the caller who meets the tool's code
    default but not the raised bar is refused."""
    tool = _tool(RiskLevel.READ_ONLY, Role.ANALYST)
    with pytest.raises(ToolPermissionError):
        authorize_role(Role.ANALYST, tool, minimum_role=Role.OWNER)
    authorize_role(Role.OWNER, tool, minimum_role=Role.OWNER)  # no raise


def test_omitting_minimum_role_falls_back_to_the_tools_own_default() -> None:
    tool = _tool(RiskLevel.READ_ONLY, Role.ANALYST)
    authorize_role(Role.ANALYST, tool, minimum_role=None)  # no raise


# --- enable/disable ------------------------------------------------------


def test_an_enabled_tool_is_authorized() -> None:
    authorize_enabled(_tool(RiskLevel.READ_ONLY, Role.VIEWER), enabled=True)  # no raise


def test_a_disabled_tool_is_refused_regardless_of_role() -> None:
    with pytest.raises(ToolDisabledError):
        authorize_enabled(_tool(RiskLevel.READ_ONLY, Role.VIEWER), enabled=False)


def test_tool_disabled_error_is_a_permission_error() -> None:
    """Every existing caller of `authorize_tool`/`run_plan` that already
    catches `ToolPermissionError` handles a disabled tool the same way,
    with no separate branch — this is the invariant that makes that true."""
    assert issubclass(ToolDisabledError, ToolPermissionError)


# --- sensitive approval gate --------------------------------------------


def test_a_read_only_tool_never_requires_approval() -> None:
    tool = _tool(RiskLevel.READ_ONLY, Role.VIEWER)
    authorize_sensitive(tool, approved=False)  # no raise


def test_a_standard_tool_never_requires_approval() -> None:
    tool = _tool(RiskLevel.STANDARD, Role.ANALYST)
    authorize_sensitive(tool, approved=False)  # no raise


def test_a_sensitive_tool_without_approval_is_refused() -> None:
    tool = _tool(RiskLevel.SENSITIVE, Role.SECURITY_ENGINEER)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        authorize_sensitive(tool, approved=False)
    assert excinfo.value.tool_name == "fake_tool"
    assert excinfo.value.risk_level is RiskLevel.SENSITIVE


def test_a_sensitive_tool_with_approval_is_authorized() -> None:
    tool = _tool(RiskLevel.SENSITIVE, Role.SECURITY_ENGINEER)
    authorize_sensitive(tool, approved=True)  # no raise


# --- combined ----------------------------------------------------------


def test_authorize_tool_checks_role_before_approval() -> None:
    """A caller who cannot use the tool at all learns that first, even if
    they also lack approval — the role check runs before the approval
    check, not after."""
    tool = _tool(RiskLevel.SENSITIVE, Role.SECURITY_ENGINEER)
    with pytest.raises(ToolPermissionError):
        authorize_tool(Role.VIEWER, tool, approved=True)


def test_authorize_tool_requires_both_checks_to_pass() -> None:
    tool = _tool(RiskLevel.SENSITIVE, Role.SECURITY_ENGINEER)
    with pytest.raises(ApprovalRequiredError):
        authorize_tool(Role.SECURITY_ENGINEER, tool, approved=False)
    authorize_tool(Role.SECURITY_ENGINEER, tool, approved=True)  # no raise


def test_authorize_tool_checks_enabled_before_role_or_approval() -> None:
    """A disabled tool is refused before either the role check or the
    approval check ever runs — the caller learns "this tool is off", not
    "you need approval for a tool you cannot use at all."""
    tool = _tool(RiskLevel.SENSITIVE, Role.SECURITY_ENGINEER)
    with pytest.raises(ToolDisabledError):
        authorize_tool(Role.OWNER, tool, approved=True, enabled=False)


def test_authorize_tool_applies_an_organizations_raised_minimum_role() -> None:
    tool = _tool(RiskLevel.STANDARD, Role.ANALYST)
    with pytest.raises(ToolPermissionError):
        authorize_tool(Role.ANALYST, tool, minimum_role=Role.OWNER)
    authorize_tool(Role.OWNER, tool, minimum_role=Role.OWNER)  # no raise
