"""Boundary and zero-persistence tests for `app/core/agent/` (the native AI
agent framework).

Same discipline as `test_assistant_boundary.py`: a hand-rolled regex scan
rather than a linter config, run as an ordinary release-blocking test.
Several extra tests exist here that the assistant boundary doesn't need,
because this subsystem carries an explicit, user-facing promise the
assistant doesn't: it must never persist a conversation, a prompt, a
response, or tool output — see `docs/guardrails.md` and
`app/models/agent.py`'s module docstring.
"""

from __future__ import annotations

import inspect
import pathlib
import re
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent import audit, session_store
from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel
from app.db.base import Base

# Imported explicitly (not via a wildcard) so every table is registered on
# `Base.metadata` before this module's tests inspect it.
from app.models.agent import (  # noqa: F401
    Agent,
    AgentConfiguration,
    AgentProvider,
    AgentTool,
    AgentUsageMetadata,
)
from app.models.audit import AuditEvent

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

# `AgentUsageMetadata`'s complete, closed column set. Checked separately from
# (and more strictly than) `_FORBIDDEN_COLUMN_NAME_FRAGMENTS` below: a
# metrics table is exactly where a well-meaning "let's log the response for
# debugging" column tends to appear, so this asserts the exact set rather
# than only the absence of a few forbidden words.
_ALLOWED_USAGE_METADATA_COLUMNS = frozenset(
    {
        "id",
        "created_at",
        "updated_at",
        "organization_id",
        "agent_id",
        "tool_name",
        "provider",
        "model",
        "tokens_sent",
        "tokens_received",
        "cost_usd",
        "duration_ms",
        "status",
        "error_code",
        "request_id",
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


def test_agent_usage_metadata_columns_are_exactly_the_allowed_set() -> None:
    table = Base.metadata.tables["agent_usage_metadata"]
    names = {column.name for column in table.columns}
    assert names == _ALLOWED_USAGE_METADATA_COLUMNS, (
        f"agent_usage_metadata's columns changed: {names ^ _ALLOWED_USAGE_METADATA_COLUMNS}; "
        "a metrics table is exactly where a stray content column would hide — update "
        "_ALLOWED_USAGE_METADATA_COLUMNS here deliberately if this is intentional"
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


def test_every_session_store_write_sets_an_explicit_expiry() -> None:
    """Static scan of `session_store.py`: every Redis write call must pass
    `ex=` explicitly. A bare `SET`/write with no expiry would silently turn
    this cache into a persistent store — exactly what the zero-persistence
    requirement forbids for anything holding investigation state."""
    source = inspect.getsource(session_store)
    write_calls = re.findall(r"\.set\(([^()]*(?:\([^()]*\)[^()]*)*)\)", source)
    assert write_calls, "expected at least one Redis write call in session_store.py"
    offenders = [call for call in write_calls if "ex=" not in call]
    assert offenders == [], f"session_store.py write(s) with no explicit expiry: {offenders}"


def test_record_tool_call_has_no_parameter_that_could_carry_content() -> None:
    """The actual enforcement behind the audit-metadata redaction
    requirement: `audit.record_tool_call`'s signature has no field a caller
    could put a prompt, a tool's raw arguments, or a tool's result into — so
    a future call site cannot leak one through it even by mistake, and this
    is checked structurally rather than trusted to code review."""
    params = set(inspect.signature(audit.record_tool_call).parameters)
    forbidden = {"prompt", "response", "content", "input", "output", "result", "params", "args"}
    assert params & forbidden == set()


async def test_a_tool_calls_audit_row_holds_only_the_fixed_operational_fields(
    db_session: AsyncSession,
) -> None:
    """Dynamic companion: what actually lands in `AuditEvent.metadata_json`
    for a tool call is exactly the fixed shape
    `docs/guardrails.md` promises — never anything else, whatever a future
    tool's error string might otherwise have said."""
    from sqlalchemy import select

    from app.models.organization import Organization, Role
    from app.models.user import User

    # `audit_logs` foreign-keys onto real organizations/users, so this needs
    # rows that exist rather than bare random ids.
    org = Organization(name="Audit Boundary Org", slug=f"audit-boundary-{uuid.uuid4().hex[:8]}")
    user = User(
        email=f"audit-boundary-{uuid.uuid4().hex[:8]}@example.test",
        full_name="U",
        password_hash="x",
    )
    db_session.add_all([org, user])
    await db_session.flush()

    ctx = AgentContext(
        organization_id=org.id,
        user_id=user.id,
        effective_role=Role.VIEWER,
        db=db_session,
        request_id="test-request-id",
    )

    await audit.record_tool_call(
        db_session,
        ctx,
        tool_name="start_scan",
        risk_level=RiskLevel.SENSITIVE,
        status="deny",
        duration_ms=12,
        error_code="tool_not_found",
    )
    await db_session.commit()

    row = (
        await db_session.execute(select(AuditEvent).where(AuditEvent.action == "agent.tool_call"))
    ).scalar_one()
    assert row.metadata_json == {
        "tool_name": "start_scan",
        "risk_level": "sensitive",
        "duration_ms": 12,
        "error_code": "tool_not_found",
        "request_id": "test-request-id",
    }
