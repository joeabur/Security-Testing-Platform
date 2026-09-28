"""`app.auth.dependencies.effective_role` — the role-ceiling computation
factored out of `require_membership` so the native AI agent's tool
permission check (and anything else that needs "what may this caller do")
uses the exact same logic the HTTP boundary already enforces.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.auth.dependencies import effective_role
from app.models.api_key import ApiKey
from app.models.organization import Membership, Role


def _membership(role: Role) -> Membership:
    return Membership(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        role=role,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _api_key(scopes: list[str]) -> ApiKey:
    return ApiKey(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        created_by_user_id=uuid.uuid4(),
        key_id="test",
        token_digest="x",
        scopes=scopes,
        name="test key",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def test_no_api_key_means_the_members_own_role() -> None:
    membership = _membership(Role.ADMIN)
    assert effective_role(membership, None) is Role.ADMIN


def test_an_api_key_caps_a_more_senior_members_role() -> None:
    membership = _membership(Role.OWNER)
    key = _api_key(["scan"])  # role_for_scopes(["scan"]) -> SECURITY_ENGINEER

    assert effective_role(membership, key) is Role.SECURITY_ENGINEER


def test_an_api_key_never_exceeds_the_members_own_role() -> None:
    """A key minted while its creator was an admin does not retroactively
    become more powerful if the creator's own role is later downgraded."""
    membership = _membership(Role.VIEWER)
    key = _api_key(["scan"])  # would cap at SECURITY_ENGINEER, but VIEWER is lower

    assert effective_role(membership, key) is Role.VIEWER
