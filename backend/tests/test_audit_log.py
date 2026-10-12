"""Database-level append-only enforcement for `audit_logs`
(`alembic/versions/fc7a77b3611c_audit_log_append_only_enforcement.py`) and
its Row-Level Security policy
(`alembic/versions/631ae06041d2_audit_log_row_level_security.py`).

`app.audit.service.record_event` already has no update or delete path —
that half of the invariant is already covered by the absence of any such
function. What this tests is the other half: a caller that bypasses the
service entirely with a raw `UPDATE`/`DELETE` — the same shape a bug or a
compromised process would actually attempt — must still be refused, by
the database itself, not by application code remembering to stay out of
the way.

This suite's `db_session` connects as the same role the rest of the test
suite does, which is `postgres` — a superuser, and superusers bypass Row
Level Security unconditionally regardless of `FORCE`. So the RLS tests
below can only check the policy's *shape* (via `pg_policies`, a catalog
view readable by any role) and that normal inserts are unaffected; they
cannot exercise real enforcement. The enforcement itself — a platform-level
insert succeeding with no org context, a cross-org insert or read being
refused — was verified live against a dedicated non-superuser, `FORCE`-owned
role before this migration was written (see its own docstring), the same
way this project's own RLS blind spot was found once before by actually
running as a non-superuser role rather than trusting this suite alone
(`docs/roadmap.md`, `docs/security-model.md` §"The habit behind the tests").
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.models.organization import Organization


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


async def test_record_event_with_no_organization_still_inserts_normally(
    db_session: AsyncSession,
) -> None:
    """A platform-level event (login, register, 2FA, platform-owner
    grant/revoke) writes `organization_id = NULL` — the exact shape the
    RLS policy added in `631ae06041d2` has to treat as its own case rather
    than as a row no session can ever see."""
    event = await record_event(
        db_session,
        action="test.platform_level_insert",
        resource_type="test",
        result="allow",
        organization_id=None,
    )
    await db_session.commit()

    assert event.id is not None
    assert event.organization_id is None


async def test_record_event_with_an_organization_still_inserts_normally(
    db_session: AsyncSession,
) -> None:
    org = Organization(name="RLS Test Org", slug=f"rls-test-org-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()

    event = await record_event(
        db_session,
        action="test.org_scoped_insert",
        resource_type="test",
        result="allow",
        organization_id=org.id,
    )
    await db_session.commit()

    assert event.id is not None
    assert event.organization_id == org.id


async def test_audit_logs_carries_the_expected_null_aware_rls_policy(
    db_session: AsyncSession,
) -> None:
    """Checks the policy's shape via `pg_policies`, a plain catalog view
    any role can read — the one piece of `631ae06041d2` this suite's
    superuser `db_session` can actually check; real enforcement needs a
    non-superuser role and was verified live, not by this test (see the
    migration's own docstring and this file's module docstring)."""
    result = await db_session.execute(
        text(
            "SELECT permissive, roles, cmd, qual, with_check "
            "FROM pg_policies "
            "WHERE tablename = 'audit_logs' AND policyname = 'tenant_isolation'"
        )
    )
    row = result.mappings().one()

    assert row["permissive"] == "PERMISSIVE"
    assert row["cmd"] == "ALL"
    for clause in (row["qual"], row["with_check"]):
        assert clause is not None
        assert "organization_id IS NULL" in clause
        assert "kervy.org_id" in clause

    forced = await db_session.execute(
        text(
            "SELECT relrowsecurity, relforcerowsecurity "
            "FROM pg_class WHERE relname = 'audit_logs'"
        )
    )
    flags = forced.mappings().one()
    assert flags["relrowsecurity"] is True
    assert flags["relforcerowsecurity"] is True
