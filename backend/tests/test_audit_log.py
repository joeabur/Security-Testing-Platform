"""Database-level append-only enforcement for `audit_logs`
(`alembic/versions/fc7a77b3611c_audit_log_append_only_enforcement.py`).

`app.audit.service.record_event` already has no update or delete path —
that half of the invariant is already covered by the absence of any such
function. What this tests is the other half: a caller that bypasses the
service entirely with a raw `UPDATE`/`DELETE` — the same shape a bug or a
compromised process would actually attempt — must still be refused, by
the database itself, not by application code remembering to stay out of
the way.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event


async def test_a_raw_update_against_audit_logs_is_refused_by_the_database(
    db_session: AsyncSession,
) -> None:
    event = await record_event(
        db_session, action="test.append_only_update", resource_type="test", result="allow"
    )
    await db_session.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(
            text("UPDATE audit_logs SET action = 'tampered' WHERE id = :id"),
            {"id": event.id},
        )
    # Postgres aborts the whole transaction on the trigger's RAISE; the
    # session cannot be reused until it is rolled back, the same recovery
    # a real caller that hit this would also need to do.
    await db_session.rollback()


async def test_a_raw_delete_against_audit_logs_is_refused_by_the_database(
    db_session: AsyncSession,
) -> None:
    event = await record_event(
        db_session, action="test.append_only_delete", resource_type="test", result="allow"
    )
    await db_session.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        await db_session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": event.id})
    await db_session.rollback()


async def test_record_event_still_inserts_normally(db_session: AsyncSession) -> None:
    """The trigger only fires on `UPDATE`/`DELETE` — a normal insert
    through the real service path must be completely unaffected."""
    event = await record_event(
        db_session, action="test.append_only_insert", resource_type="test", result="allow"
    )
    await db_session.commit()

    assert event.id is not None
    assert event.record_hash
