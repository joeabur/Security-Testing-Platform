"""Boundary and zero-persistence tests for `app/core/agent/` (the native AI
agent framework).

Same discipline as `test_assistant_boundary.py`: a hand-rolled regex scan
rather than a linter config, run as an ordinary release-blocking test. Two
extra tests exist here that the assistant boundary doesn't need, because
this subsystem carries an explicit, user-facing promise the assistant
doesn't: it must never persist a conversation, a prompt, a response, or
tool output — see `docs/guardrails.md` and `app/models/agent.py`'s module
docstring.
"""

from __future__ import annotations

import pathlib
import re

from app.db.base import Base

# Imported explicitly (not via a wildcard) so every table is registered on
# `Base.metadata` before this module's tests inspect it.
from app.models.agent import Agent, AgentProvider, AgentTool  # noqa: F401

# The complete, closed set of tables the native AI agent subsystem may ever
# create. A future table must be added here deliberately — the same "added
# on purpose, not by accident" idiom
# `tests/security/test_authorization_matrix.py` already uses for routes.
ALLOWED_AGENT_TABLES = frozenset(
    {
        "agents",
        "agent_providers",
        "agent_tools",
        "agent_configurations",
        "agent_usage_metadata",
    }
)

# Column-name fragments that would indicate a table has started holding
# conversational content rather than configuration or metrics — exactly
# what the zero-persistence requirement forbids.
_FORBIDDEN_COLUMN_NAME_FRAGMENTS = (
    "prompt",
    "response",
    "message",
    "conversation",
    "content",
    "transcript",
    "history",
)


def _agent_tables() -> list:
    return [table for name, table in Base.metadata.tables.items() if name.startswith("agent")]


def test_only_the_allowed_agent_tables_exist() -> None:
    names = {table.name for table in _agent_tables()}
    assert names <= ALLOWED_AGENT_TABLES, (
        f"unexpected agent table(s) {names - ALLOWED_AGENT_TABLES}; if this is "
        "deliberate, add it to ALLOWED_AGENT_TABLES here and confirm it holds no "
        "prompt/response/conversation content"
    )


def test_agent_tables_hold_no_conversational_content() -> None:
    offenders = [
        f"{table.name}.{column.name}"
        for table in _agent_tables()
        for column in table.columns
        if any(fragment in column.name.lower() for fragment in _FORBIDDEN_COLUMN_NAME_FRAGMENTS)
    ]
    assert offenders == [], (
        f"agent table column(s) look like stored AI content, not configuration: {offenders}"
    )


def test_no_module_outside_core_agent_or_api_imports_it() -> None:
    root = pathlib.Path(__file__).resolve().parents[2] / "app"
    pattern = re.compile(r"^\s*(from|import)\s+app\.core\.agent\b", re.MULTILINE)
    offenders = [
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if "/core/agent/" not in str(path)
        and "/api/" not in str(path)
        and pattern.search(path.read_text())
    ]
    assert offenders == [], f"core modules importing the agent package: {offenders}"
