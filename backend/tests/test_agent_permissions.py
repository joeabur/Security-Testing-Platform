"""`app/core/agent/permissions.py`: the role ceiling and the SENSITIVE-tier
approval gate, checked independently — mirroring
`app/core/assistant/autonomy.py`'s own "a mode cannot grant what is not in
the table" design for `TARGET_TOUCHING`.
"""

from __future__ import annotations

import pytest

from app.core.agent.permissions import (
    ApprovalRequiredError,
    ToolPermissionError,
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
