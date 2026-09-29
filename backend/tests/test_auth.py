import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

pytestmark = pytest.mark.asyncio


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def test_register_creates_user_and_sets_session_cookie(
    client: AsyncClient, strong_password: str
) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.test",
            "full_name": "Alice Analyst",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "alice@example.test"
    assert "access_token" in body
    assert "kervy_session" in response.cookies


async def test_register_duplicate_email_rejected(client: AsyncClient, strong_password: str) -> None:
    payload = {"email": "bob@example.test", "full_name": "Bob", "password": strong_password}
    headers = await _anon_headers(client)
    first = await client.post("/api/v1/auth/register", json=payload, headers=headers)
    assert first.status_code == 201

    second = await client.post("/api/v1/auth/register", json=payload, headers=headers)
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "CONFLICT"


async def test_register_rejects_weak_password(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/register",
        # pragma: allowlist nextline secret
        json={"email": "weak@example.test", "full_name": "Weak", "password": "short"},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 422


async def test_login_with_correct_credentials_succeeds(
    client: AsyncClient, strong_password: str
) -> None:
    headers = await _anon_headers(client)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "carol@example.test", "full_name": "Carol", "password": strong_password},
        headers=headers,
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "carol@example.test", "password": strong_password},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "carol@example.test"


async def test_login_with_wrong_password_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    headers = await _anon_headers(client)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "dave@example.test", "full_name": "Dave", "password": strong_password},
        headers=headers,
    )
    response = await client.post(
        "/api/v1/auth/login",
        # pragma: allowlist nextline secret
        json={"email": "dave@example.test", "password": "wrong-password-entirely"},
        headers=headers,
    )
    assert response.status_code == 401


async def test_login_with_unknown_email_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/login",
        # pragma: allowlist nextline secret
        json={"email": "ghost@example.test", "password": "whatever-12345"},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 401


async def test_me_requires_authentication(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


async def test_me_returns_current_user_via_bearer_token(
    client: AsyncClient, strong_password: str
) -> None:
    register = await client.post(
        "/api/v1/auth/register",
        json={"email": "erin@example.test", "full_name": "Erin", "password": strong_password},
        headers=await _anon_headers(client),
    )
    token = register.json()["access_token"]

    response = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "erin@example.test"


async def test_me_returns_current_user_via_session_cookie(
    client: AsyncClient, strong_password: str
) -> None:
    await client.post(
        "/api/v1/auth/register",
        json={"email": "frank@example.test", "full_name": "Frank", "password": strong_password},
        headers=await _anon_headers(client),
    )
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "frank@example.test"


async def test_logout_clears_session_cookie(client: AsyncClient, strong_password: str) -> None:
    await client.post(
        "/api/v1/auth/register",
        json={"email": "grace@example.test", "full_name": "Grace", "password": strong_password},
        headers=await _anon_headers(client),
    )
    logout = await client.post("/api/v1/auth/logout")
    assert logout.status_code == 204

    me_after_logout = await client.get("/api/v1/auth/me")
    assert me_after_logout.status_code == 401


async def test_invalid_token_rejected(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"}
    )
    assert response.status_code == 401


async def test_passwords_are_never_stored_in_plaintext(
    client: AsyncClient, db_session, strong_password: str
) -> None:
    from sqlalchemy import select

    from app.models.user import User

    await client.post(
        "/api/v1/auth/register",
        json={"email": "henry@example.test", "full_name": "Henry", "password": strong_password},
        headers=await _anon_headers(client),
    )
    result = await db_session.execute(select(User).where(User.email == "henry@example.test"))
    user = result.scalar_one()
    assert user.password_hash != strong_password
    assert strong_password not in user.password_hash
