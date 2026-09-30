"""`app/core/agent/tool_config.py`: per-organization tool enable/disable and
minimum-role override — the read path `AgentTool.minimum_role_override` was
missing since the agent's Phase 2, plus the write-time guard that the
override can only ever raise a tool's bar, never lower it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent.tool_config import (
    effective_minimum_role,
    is_tool_enabled,
    load_tool_config,
    permitted_tools,
    validate_role_override,
)
from app.core.agent.tools.contract import RiskLevel, Tool, ToolNotFoundError
from app.models.agent import AgentTool
from app.models.organization import Organization, Role


async def _noop_handler(ctx: object, params: object) -> object:  # pragma: no cover - unused
    raise ToolNotFoundError("unused")


def _tool(name: str = "fake_tool", minimum_role: Role = Role.ANALYST) -> Tool:
    from pydantic import BaseModel

    class _Params(BaseModel):
        pass

    class _Result(BaseModel):
        pass

    return Tool(
        name=name,
        description="a fake tool for tool-config tests",
        input_model=_Params,
        output_model=_Result,
        risk_level=RiskLevel.READ_ONLY,
        minimum_role=minimum_role,
        handler=_noop_handler,  # type: ignore[arg-type]
    )


def _row(tool_name: str, *, enabled: bool = True, override: str | None = None) -> AgentTool:
    return AgentTool(
        organization_id=uuid.uuid4(),
        tool_name=tool_name,
        enabled=enabled,
        minimum_role_override=override,
    )


# --- effective_minimum_role --------------------------------------------


def test_no_row_means_the_code_default() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    assert effective_minimum_role(tool, {}) is Role.ANALYST


def test_an_override_raising_the_bar_is_used() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    config = {"fake_tool": _row("fake_tool", override="owner")}
    assert effective_minimum_role(tool, config) is Role.OWNER


def test_an_override_lowering_the_bar_is_ignored() -> None:
    """`AgentTool.minimum_role_override`'s own docstring: it may only ever
    raise a tool's effective minimum role, never lower it. A stored value
    that would lower it is read defensively rather than trusted, the same
    reasoning `validate_role_override` exists to stop it being stored in
    the first place."""
    tool = _tool(minimum_role=Role.ANALYST)
    config = {"fake_tool": _row("fake_tool", override="viewer")}
    assert effective_minimum_role(tool, config) is Role.ANALYST


def test_an_override_equal_to_the_default_is_a_no_op() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    config = {"fake_tool": _row("fake_tool", override="analyst")}
    assert effective_minimum_role(tool, config) is Role.ANALYST


def test_a_row_for_a_different_tool_does_not_apply() -> None:
    tool = _tool(name="fake_tool", minimum_role=Role.ANALYST)
    config = {"other_tool": _row("other_tool", override="owner")}
    assert effective_minimum_role(tool, config) is Role.ANALYST


# --- is_tool_enabled -----------------------------------------------------


def test_no_row_means_enabled() -> None:
    tool = _tool()
    assert is_tool_enabled(tool, {}) is True


def test_a_disabled_row_disables_the_tool() -> None:
    tool = _tool()
    config = {"fake_tool": _row("fake_tool", enabled=False)}
    assert is_tool_enabled(tool, config) is False


def test_an_enabled_row_is_explicit_but_equivalent_to_absent() -> None:
    tool = _tool()
    config = {"fake_tool": _row("fake_tool", enabled=True)}
    assert is_tool_enabled(tool, config) is True


# --- permitted_tools ------------------------------------------------------


def test_permitted_tools_excludes_a_disabled_tool_even_for_the_most_senior_role() -> None:
    tool = _tool(minimum_role=Role.VIEWER)
    config = {"fake_tool": _row("fake_tool", enabled=False)}
    assert permitted_tools([tool], config, effective_role=Role.OWNER) == []


def test_permitted_tools_excludes_a_role_insufficient_caller() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    assert permitted_tools([tool], {}, effective_role=Role.VIEWER) == []


def test_permitted_tools_respects_a_raised_override() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    config = {"fake_tool": _row("fake_tool", override="owner")}
    # Meets the code default but not the raised override.
    assert permitted_tools([tool], config, effective_role=Role.ANALYST) == []
    assert permitted_tools([tool], config, effective_role=Role.OWNER) == [tool]


def test_permitted_tools_includes_an_enabled_role_sufficient_tool() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    assert permitted_tools([tool], {}, effective_role=Role.ANALYST) == [tool]


# --- validate_role_override -----------------------------------------------


def test_validate_role_override_accepts_none() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    validate_role_override(tool, None)  # no raise


def test_validate_role_override_accepts_a_raised_role() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    validate_role_override(tool, Role.OWNER)  # no raise


def test_validate_role_override_accepts_the_same_role() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    validate_role_override(tool, Role.ANALYST)  # no raise


def test_validate_role_override_rejects_a_lowered_role() -> None:
    tool = _tool(minimum_role=Role.ANALYST)
    with pytest.raises(ValueError, match="cannot be set below its code default"):
        validate_role_override(tool, Role.VIEWER)


# --- load_tool_config (DB) ------------------------------------------------


async def test_load_tool_config_is_scoped_to_the_organization(db_session: AsyncSession) -> None:
    org_a = Organization(name="Org A", slug=f"org-a-{uuid.uuid4().hex[:8]}")
    org_b = Organization(name="Org B", slug=f"org-b-{uuid.uuid4().hex[:8]}")
    db_session.add_all([org_a, org_b])
    await db_session.flush()
    db_session.add_all(
        [
            AgentTool(organization_id=org_a.id, tool_name="fake_tool", enabled=False),
            AgentTool(organization_id=org_b.id, tool_name="fake_tool", enabled=True),
        ]
    )
    await db_session.flush()

    config_a = await load_tool_config(db_session, org_a.id)
    assert config_a["fake_tool"].enabled is False

    config_b = await load_tool_config(db_session, org_b.id)
    assert config_b["fake_tool"].enabled is True


async def test_load_tool_config_is_empty_for_an_unconfigured_organization(
    db_session: AsyncSession,
) -> None:
    assert await load_tool_config(db_session, uuid.uuid4()) == {}
