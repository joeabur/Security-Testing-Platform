"""Platform-owner authority: above every organization's own `Role.OWNER`.

Covers the property app/api/v1/routers/platform.py's own docstring states:
authorization here is purely `User.platform_role`, never an organization
role and never a comparison against a hard-coded email.
"""

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.user import PlatformRole, User

pytestmark = pytest.mark.asyncio


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0].title(), "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _login(client: AsyncClient, email: str, password: str) -> dict:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _grant_platform_owner(db_session: AsyncSession, email: str) -> None:
    user = (await db_session.execute(select(User).where(User.email == email))).scalar_one()
    user.platform_role = PlatformRole.OWNER
    await db_session.commit()


async def test_unauthenticated_request_is_rejected(client: AsyncClient) -> None:
    response = await client.get("/api/v1/platform/owners")
    assert response.status_code == 401


async def test_ordinary_user_is_not_a_platform_owner(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "ordinary@example.test", strong_password)
    response = await client.get(
        "/api/v1/platform/owners", headers=_auth_headers(user["access_token"])
    )
    assert response.status_code == 403


async def test_organization_owner_role_does_not_grant_platform_authority(
    client: AsyncClient, strong_password: str
) -> None:
    """The exact isolation this feature exists to guarantee: founding an
    organization (and so holding its `Role.OWNER`) must not imply any
    platform-wide authority — the two are unrelated columns on unrelated
    tables, and this is the test that would fail if they were ever conflated.
    """
    user = await _register(client, "orgfounder@example.test", strong_password)
    headers = _auth_headers(user["access_token"])
    create = await client.post(
        "/api/v1/organizations", json={"name": "Founder's Org"}, headers=headers
    )
    assert create.json()["role"] == "owner"

    response = await client.get("/api/v1/platform/owners", headers=headers)
    assert response.status_code == 403


async def test_platform_owner_can_list_self(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    user = await _register(client, "firstowner@example.test", strong_password)
    await _grant_platform_owner(db_session, "firstowner@example.test")

    response = await client.get(
        "/api/v1/platform/owners", headers=_auth_headers(user["access_token"])
    )
    assert response.status_code == 200
    emails = {row["email"] for row in response.json()}
    assert emails == {"firstowner@example.test"}


async def test_platform_owner_can_grant_another_registered_user(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    owner = await _register(client, "grantor@example.test", strong_password)
    await _grant_platform_owner(db_session, "grantor@example.test")
    await _register(client, "grantee@example.test", strong_password)
    headers = _auth_headers(owner["access_token"])

    response = await client.post(
        "/api/v1/platform/owners", json={"email": "grantee@example.test"}, headers=headers
    )
    assert response.status_code == 201
    assert response.json()["email"] == "grantee@example.test"

    listing = await client.get("/api/v1/platform/owners", headers=headers)
    assert {row["email"] for row in listing.json()} == {
        "grantor@example.test",
        "grantee@example.test",
    }


async def test_grant_refuses_an_unregistered_email(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    owner = await _register(client, "soleowner@example.test", strong_password)
    await _grant_platform_owner(db_session, "soleowner@example.test")

    response = await client.post(
        "/api/v1/platform/owners",
        json={"email": "nobody@example.test"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert response.status_code == 404


async def test_grant_refuses_an_already_granted_owner(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    owner = await _register(client, "ownerone@example.test", strong_password)
    await _grant_platform_owner(db_session, "ownerone@example.test")
    await _register(client, "ownertwo@example.test", strong_password)
    headers = _auth_headers(owner["access_token"])
    await client.post(
        "/api/v1/platform/owners", json={"email": "ownertwo@example.test"}, headers=headers
    )

    response = await client.post(
        "/api/v1/platform/owners", json={"email": "ownertwo@example.test"}, headers=headers
    )
    assert response.status_code == 409


async def test_non_owner_cannot_grant_platform_ownership(
    client: AsyncClient, strong_password: str
) -> None:
    await _register(client, "regular@example.test", strong_password)
    attacker = await _register(client, "attacker@example.test", strong_password)

    response = await client.post(
        "/api/v1/platform/owners",
        json={"email": "regular@example.test"},
        headers=_auth_headers(attacker["access_token"]),
    )
    assert response.status_code == 403


async def test_last_platform_owner_cannot_be_revoked(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    owner = await _register(client, "lastowner@example.test", strong_password)
    await _grant_platform_owner(db_session, "lastowner@example.test")
    headers = _auth_headers(owner["access_token"])
    user_id = (await client.get("/api/v1/platform/owners", headers=headers)).json()[0]["user_id"]

    response = await client.delete(f"/api/v1/platform/owners/{user_id}", headers=headers)
    assert response.status_code == 409


async def test_revoking_one_of_two_owners_succeeds_and_takes_effect(
    client: AsyncClient, db_session: AsyncSession, strong_password: str
) -> None:
    owner = await _register(client, "revokerone@example.test", strong_password)
    await _grant_platform_owner(db_session, "revokerone@example.test")
    second = await _register(client, "revoketwo@example.test", strong_password)
    headers = _auth_headers(owner["access_token"])
    await client.post(
        "/api/v1/platform/owners", json={"email": "revoketwo@example.test"}, headers=headers
    )

    second_user_id = (await client.get("/api/v1/platform/owners", headers=headers)).json()
    target_id = next(
        row["user_id"] for row in second_user_id if row["email"] == "revoketwo@example.test"
    )

    response = await client.delete(f"/api/v1/platform/owners/{target_id}", headers=headers)
    assert response.status_code == 204

    # The revoked account immediately loses platform-owner authority — this
    # is the same request `second` could have made a moment earlier, now
    # answered 403 instead of 200.
    second_headers = _auth_headers(second["access_token"])
    followup = await client.get("/api/v1/platform/owners", headers=second_headers)
    assert followup.status_code == 403


async def test_bootstrap_script_grants_the_first_owner(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, strong_password: str
) -> None:
    from scripts.bootstrap_platform_owner import _bootstrap

    await _register(client, "bootstrapped@example.test", strong_password)

    monkeypatch.setenv("KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL", "bootstrapped@example.test")
    get_settings.cache_clear()
    try:
        exit_code = await _bootstrap()
    finally:
        monkeypatch.delenv("KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL", raising=False)
        get_settings.cache_clear()

    assert exit_code == 0
    login = await _login(client, "bootstrapped@example.test", strong_password)
    response = await client.get(
        "/api/v1/platform/owners", headers=_auth_headers(login["access_token"])
    )
    assert response.status_code == 200
    assert {row["email"] for row in response.json()} == {"bootstrapped@example.test"}


async def test_bootstrap_script_refuses_once_an_owner_already_exists(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    strong_password: str,
) -> None:
    from scripts.bootstrap_platform_owner import _bootstrap

    await _register(client, "alreadyowner@example.test", strong_password)
    await _grant_platform_owner(db_session, "alreadyowner@example.test")
    await _register(client, "wouldbesecond@example.test", strong_password)

    monkeypatch.setenv("KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL", "wouldbesecond@example.test")
    get_settings.cache_clear()
    try:
        exit_code = await _bootstrap()
    finally:
        monkeypatch.delenv("KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL", raising=False)
        get_settings.cache_clear()

    assert exit_code == 1
    login = await _login(client, "wouldbesecond@example.test", strong_password)
    follow_up = await client.get(
        "/api/v1/platform/owners", headers=_auth_headers(login["access_token"])
    )
    assert follow_up.status_code == 403
