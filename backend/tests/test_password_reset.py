"""Forgot / reset password.

`send_password_reset_email` is monkeypatched to a recorder rather than
exercised end to end here: it is a thin wrapper over
`app.core.integrations.send.send_email`, whose own SMTP-over-scope-engine
path already has its own coverage; this file is about the token lifecycle
and the non-enumeration shape around it, not SMTP delivery.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.api.v1.routers import auth as auth_router
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.integrations.contract import DeliveryResult
from app.models.password_reset import PasswordResetToken, digest_of, mint_reset_token
from app.models.user import User
from app.models.user_session import UserSession

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _smtp_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KERVY_PLATFORM_SMTP_HOST", "smtp.kervy.example.test")
    monkeypatch.setenv("KERVY_PLATFORM_SMTP_FROM_ADDRESS", "no-reply@kervy.example.test")
    monkeypatch.setenv("KERVY_PUBLIC_BASE_URL", "https://app.kervy.example.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def sent_emails(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    sent: list[dict[str, str]] = []

    async def _fake_send(settings, *, to_address, reset_url):  # noqa: ANN001
        sent.append({"to": to_address, "url": reset_url})
        return DeliveryResult(delivered=True, detail="ok")

    monkeypatch.setattr(auth_router, "send_password_reset_email", _fake_send)
    return sent


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def _register(client: AsyncClient, email: str, password: str) -> None:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "Reset Target", "password": password},
        headers=await _anon_headers(client),
    )


async def test_forgot_password_emails_a_registered_user(
    client: AsyncClient, strong_password: str, sent_emails: list[dict[str, str]], db_session
) -> None:
    await _register(client, "reset@example.test", strong_password)

    response = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "reset@example.test"}
    )
    assert response.status_code == 202
    assert sent_emails
    assert sent_emails[0]["to"] == "reset@example.test"
    assert "token=" in sent_emails[0]["url"]

    result = await db_session.execute(
        select(PasswordResetToken).join(User).where(User.email == "reset@example.test")
    )
    token_row = result.scalar_one()
    assert token_row.used_at is None


async def test_forgot_password_is_202_and_silent_for_an_unknown_address(
    client: AsyncClient, sent_emails: list[dict[str, str]]
) -> None:
    response = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "ghost@example.test"}
    )
    assert response.status_code == 202
    assert sent_emails == []


async def test_forgot_password_is_silent_for_an_oauth_only_account(
    client: AsyncClient, db_session, sent_emails: list[dict[str, str]]
) -> None:
    user = User(email="oauthonly@example.test", full_name="OAuth Only", password_hash=None)
    db_session.add(user)
    await db_session.commit()

    response = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "oauthonly@example.test"}
    )
    assert response.status_code == 202
    assert sent_emails == []


async def test_requesting_a_new_link_invalidates_the_old_one(
    client: AsyncClient, strong_password: str, sent_emails: list[dict[str, str]], db_session
) -> None:
    await _register(client, "tworeset@example.test", strong_password)

    await client.post("/api/v1/auth/forgot-password", json={"email": "tworeset@example.test"})
    first_url = sent_emails[0]["url"]
    first_token = first_url.split("token=")[1]

    await client.post("/api/v1/auth/forgot-password", json={"email": "tworeset@example.test"})
    second_url = sent_emails[1]["url"]
    second_token = second_url.split("token=")[1]

    assert first_token != second_token

    stale = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": first_token, "new_password": "Another-Strong-Password-42"},
    )
    assert stale.status_code == 400

    fresh = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": second_token, "new_password": "Another-Strong-Password-42"},
    )
    assert fresh.status_code == 204


async def test_reset_password_sets_the_new_password_and_logs_in_with_it(
    client: AsyncClient, strong_password: str, sent_emails: list[dict[str, str]]
) -> None:
    await _register(client, "changeit@example.test", strong_password)
    await client.post("/api/v1/auth/forgot-password", json={"email": "changeit@example.test"})
    token = sent_emails[0]["url"].split("token=")[1]

    new_password = "Brand-New-Password-99"
    reset = await client.post(
        "/api/v1/auth/reset-password", json={"token": token, "new_password": new_password}
    )
    assert reset.status_code == 204
    assert "kervy_session" not in reset.cookies

    old_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "changeit@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    assert old_login.status_code == 401

    new_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "changeit@example.test", "password": new_password},
        headers=await _anon_headers(client),
    )
    assert new_login.status_code == 200


async def test_reset_password_invalidates_every_existing_session(
    client: AsyncClient, strong_password: str, sent_emails: list[dict[str, str]], db_session
) -> None:
    await _register(client, "wipeout@example.test", strong_password)
    me_before = await client.get("/api/v1/auth/me")
    assert me_before.status_code == 200

    await client.post("/api/v1/auth/forgot-password", json={"email": "wipeout@example.test"})
    token = sent_emails[0]["url"].split("token=")[1]
    await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "Yet-Another-Strong-One-7"},
    )

    me_after = await client.get("/api/v1/auth/me")
    assert me_after.status_code == 401

    user_result = await db_session.execute(select(User).where(User.email == "wipeout@example.test"))
    user = user_result.scalar_one()
    session_result = await db_session.execute(
        select(UserSession).where(UserSession.user_id == user.id)
    )
    for session in session_result.scalars().all():
        assert session.revoked_at is not None


async def test_reset_password_rejects_an_unknown_token(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": "not-a-real-token", "new_password": "Whatever-Strong-Password-1"},
    )
    assert response.status_code == 400


async def test_reset_password_rejects_an_expired_token(
    client: AsyncClient, strong_password: str, db_session
) -> None:
    await _register(client, "expired@example.test", strong_password)
    user_result = await db_session.execute(select(User).where(User.email == "expired@example.test"))
    user = user_result.scalar_one()

    token, digest = mint_reset_token()
    db_session.add(
        PasswordResetToken(
            user_id=user.id,
            token_digest=digest,
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    )
    await db_session.commit()

    response = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "Whatever-Strong-Password-1"},
    )
    assert response.status_code == 400


async def test_reset_password_token_is_single_use(
    client: AsyncClient, strong_password: str, sent_emails: list[dict[str, str]]
) -> None:
    await _register(client, "onceonly@example.test", strong_password)
    await client.post("/api/v1/auth/forgot-password", json={"email": "onceonly@example.test"})
    token = sent_emails[0]["url"].split("token=")[1]

    first = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "First-Strong-Password-1"},
    )
    assert first.status_code == 204

    second = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": "Second-Strong-Password-2"},
    )
    assert second.status_code == 400


async def test_reset_password_digest_is_never_the_plaintext_token() -> None:
    token, digest = mint_reset_token()
    assert digest == digest_of(token)
    assert token not in digest
