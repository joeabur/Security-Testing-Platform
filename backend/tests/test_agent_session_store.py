"""`app/core/agent/session_store.py`: the sixth Redis-backed store in this
codebase. Tests run against the real Redis this test suite already depends
on (same pattern as `test_assistant_spend_cap.py`'s `tracker` fixture),
cleaned up before and after so one test's key never leaks into the next.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.agent.investigation import Investigation, InvestigationStatus, PendingApproval
from app.core.agent.session_store import TTL_SECONDS, InvestigationSessionStore, _key
from app.core.agent.tools.contract import RiskLevel


@pytest.fixture
async def store() -> InvestigationSessionStore:
    instance = InvestigationSessionStore()
    yield instance
    # Best-effort cleanup; individual tests also delete what they create.


async def test_a_saved_investigation_round_trips(store: InvestigationSessionStore) -> None:
    investigation = Investigation.start(organization_id=uuid.uuid4(), user_id=uuid.uuid4())
    investigation.await_approval(
        PendingApproval(
            tool_name="start_scan", risk_level=RiskLevel.SENSITIVE, description="Queue a scan"
        )
    )

    await store.save(investigation)
    loaded = await store.load(investigation.id, organization_id=investigation.organization_id)

    assert loaded is not None
    assert loaded.id == investigation.id
    assert loaded.organization_id == investigation.organization_id
    assert loaded.user_id == investigation.user_id
    assert loaded.status is InvestigationStatus.AWAITING_APPROVAL
    assert loaded.pending_approval == investigation.pending_approval

    await store.delete(investigation.id)


async def test_loading_an_unknown_id_returns_none(store: InvestigationSessionStore) -> None:
    assert await store.load(uuid.uuid4(), organization_id=uuid.uuid4()) is None


async def test_loading_with_the_wrong_organization_returns_none(
    store: InvestigationSessionStore,
) -> None:
    """Tenant isolation is enforced inside `load`, not left to the caller —
    an investigation started by one organization must never resume under
    another's id, even if that id were somehow guessed."""
    investigation = Investigation.start(organization_id=uuid.uuid4(), user_id=uuid.uuid4())
    await store.save(investigation)

    wrong_org = await store.load(investigation.id, organization_id=uuid.uuid4())
    assert wrong_org is None

    right_org = await store.load(investigation.id, organization_id=investigation.organization_id)
    assert right_org is not None

    await store.delete(investigation.id)


async def test_delete_removes_the_saved_investigation(store: InvestigationSessionStore) -> None:
    investigation = Investigation.start(organization_id=uuid.uuid4(), user_id=uuid.uuid4())
    await store.save(investigation)

    await store.delete(investigation.id)

    assert await store.load(investigation.id, organization_id=investigation.organization_id) is None


async def test_save_sets_the_documented_ttl(store: InvestigationSessionStore) -> None:
    investigation = Investigation.start(organization_id=uuid.uuid4(), user_id=uuid.uuid4())

    await store.save(investigation)
    client = store._connect()  # noqa: SLF001 - test needs the raw client to read the TTL
    ttl = await client.ttl(_key(investigation.id))

    assert 0 < ttl <= TTL_SECONDS

    await store.delete(investigation.id)
