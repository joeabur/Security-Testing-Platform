"""Two-factor authentication (TOTP).

Covers the enroll/enable/disable lifecycle, the login challenge that stands
in for "the password check already passed" once 2FA is on, the recovery-
code fallback, and the two properties that make the challenge safe to hand
to an unauthenticated caller: it can never be accepted by `get_current_user`
as a Bearer token, and it can be redeemed at most once.
"""

from __future__ import annotations

import base64
import uuid

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.twofactor.challenge_store import consume_or_raise
from app.models.totp_recovery_code import TotpRecoveryCode
from app.models.user import User

pytestmark = pytest.mark.asyncio

_TOTP_KEY_B64 = base64.b64encode(b"\x00" * 32).decode()


@pytest.fixture(autouse=True)
def _totp_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KERVY_TOTP_ENCRYPTION_KEY", _TOTP_KEY_B64)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "Two Factor", "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 201
    return response.json()


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _enable_totp(client: AsyncClient, token: str) -> tuple[str, list[str]]:
    """Registers a secret and confirms it. Returns `(secret, recovery_codes)`."""
    setup = await client.post("/api/v1/auth/2fa/setup", headers=_auth_headers(token))
    assert setup.status_code == 200
    secret = setup.json()["secret"]

    code = pyotp.TOTP(secret).now()
    enable = await client.post(
        "/api/v1/auth/2fa/enable", json={"code": code}, headers=_auth_headers(token)
    )
    assert enable.status_code == 200
    return secret, enable.json()["recovery_codes"]


async def test_setup_is_503_when_totp_is_not_configured(
    client: AsyncClient, strong_password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("KERVY_TOTP_ENCRYPTION_KEY", raising=False)
    get_settings.cache_clear()
    user = await _register(client, "unconfigured2fa@example.test", strong_password)

    response = await client.post(
        "/api/v1/auth/2fa/setup", headers=_auth_headers(user["access_token"])
    )
    assert response.status_code == 503
    get_settings.cache_clear()


async def test_setup_returns_a_secret_and_a_scannable_uri(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "setup2fa@example.test", strong_password)
    response = await client.post(
        "/api/v1/auth/2fa/setup", headers=_auth_headers(user["access_token"])
    )
    assert response.status_code == 200
    body = response.json()
    assert body["secret"]
    assert body["provisioning_uri"].startswith("otpauth://totp/")


async def test_enable_without_setup_first_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "noenable2fa@example.test", strong_password)
    response = await client.post(
        "/api/v1/auth/2fa/enable",
        json={"code": "000000"},
        headers=_auth_headers(user["access_token"]),
    )
    assert response.status_code == 400


async def test_enable_with_the_wrong_code_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "wrongcode2fa@example.test", strong_password)
    token = user["access_token"]
    await client.post("/api/v1/auth/2fa/setup", headers=_auth_headers(token))

    response = await client.post(
        "/api/v1/auth/2fa/enable", json={"code": "000000"}, headers=_auth_headers(token)
    )
    assert response.status_code == 400


async def test_enable_with_the_correct_code_turns_it_on(
    client: AsyncClient, strong_password: str, db_session
) -> None:
    user = await _register(client, "enable2fa@example.test", strong_password)
    _, recovery_codes = await _enable_totp(client, user["access_token"])

    assert len(recovery_codes) == 10
    assert len(set(recovery_codes)) == 10

    result = await db_session.execute(select(User).where(User.email == "enable2fa@example.test"))
    db_user = result.scalar_one()
    assert db_user.totp_enabled is True


async def test_cannot_setup_again_once_enabled(client: AsyncClient, strong_password: str) -> None:
    user = await _register(client, "resetup2fa@example.test", strong_password)
    await _enable_totp(client, user["access_token"])

    response = await client.post(
        "/api/v1/auth/2fa/setup", headers=_auth_headers(user["access_token"])
    )
    assert response.status_code == 409


async def test_login_returns_a_challenge_instead_of_a_session(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "challenge2fa@example.test", strong_password)
    await _enable_totp(client, user["access_token"])
    client.cookies.clear()

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "challenge2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["requires_totp"] is True
    assert body["challenge"]
    assert "kervy_session" not in response.cookies


async def test_login_2fa_completes_with_a_valid_code(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "complete2fa@example.test", strong_password)
    secret, _ = await _enable_totp(client, user["access_token"])
    client.cookies.clear()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "complete2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    challenge = login.json()["challenge"]

    code = pyotp.TOTP(secret).now()
    response = await client.post(
        "/api/v1/auth/login/2fa",
        json={"challenge": challenge, "code": code},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "complete2fa@example.test"
    assert "kervy_session" in response.cookies


async def test_login_2fa_rejects_a_wrong_code(client: AsyncClient, strong_password: str) -> None:
    user = await _register(client, "wrongloginco2fa@example.test", strong_password)
    await _enable_totp(client, user["access_token"])
    client.cookies.clear()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "wrongloginco2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    challenge = login.json()["challenge"]

    response = await client.post(
        "/api/v1/auth/login/2fa",
        json={"challenge": challenge, "code": "000000"},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 401


async def test_login_2fa_challenge_is_single_use(client: AsyncClient, strong_password: str) -> None:
    user = await _register(client, "singleuse2fa@example.test", strong_password)
    secret, _ = await _enable_totp(client, user["access_token"])
    client.cookies.clear()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "singleuse2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    challenge = login.json()["challenge"]
    code = pyotp.TOTP(secret).now()
    anon_headers = await _anon_headers(client)

    first = await client.post(
        "/api/v1/auth/login/2fa", json={"challenge": challenge, "code": code}, headers=anon_headers
    )
    assert first.status_code == 200

    second = await client.post(
        "/api/v1/auth/login/2fa", json={"challenge": challenge, "code": code}, headers=anon_headers
    )
    assert second.status_code == 401


async def test_a_totp_challenge_token_cannot_authenticate_as_a_bearer_token(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "challengebearer2fa@example.test", strong_password)
    await _enable_totp(client, user["access_token"])
    client.cookies.clear()

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "challengebearer2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    challenge = login.json()["challenge"]

    response = await client.get("/api/v1/auth/me", headers=_auth_headers(challenge))
    assert response.status_code == 401


async def test_login_2fa_accepts_a_recovery_code_exactly_once(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "recoverylogin2fa@example.test", strong_password)
    _, recovery_codes = await _enable_totp(client, user["access_token"])
    client.cookies.clear()
    recovery_code = recovery_codes[0]

    login1 = await client.post(
        "/api/v1/auth/login",
        json={"email": "recoverylogin2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    challenge1 = login1.json()["challenge"]
    first = await client.post(
        "/api/v1/auth/login/2fa",
        json={"challenge": challenge1, "code": recovery_code},
        headers=await _anon_headers(client),
    )
    assert first.status_code == 200

    client.cookies.clear()
    login2 = await client.post(
        "/api/v1/auth/login",
        json={"email": "recoverylogin2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    challenge2 = login2.json()["challenge"]
    second = await client.post(
        "/api/v1/auth/login/2fa",
        json={"challenge": challenge2, "code": recovery_code},
        headers=await _anon_headers(client),
    )
    assert second.status_code == 401


async def test_disable_requires_a_valid_code(client: AsyncClient, strong_password: str) -> None:
    user = await _register(client, "baddisable2fa@example.test", strong_password)
    await _enable_totp(client, user["access_token"])

    response = await client.post(
        "/api/v1/auth/2fa/disable",
        json={"code": "000000"},
        headers=_auth_headers(user["access_token"]),
    )
    assert response.status_code == 400


async def test_disable_with_a_valid_code_turns_it_off_and_clears_state(
    client: AsyncClient, strong_password: str, db_session
) -> None:
    user = await _register(client, "gooddisable2fa@example.test", strong_password)
    secret, _ = await _enable_totp(client, user["access_token"])

    code = pyotp.TOTP(secret).now()
    response = await client.post(
        "/api/v1/auth/2fa/disable",
        json={"code": code},
        headers=_auth_headers(user["access_token"]),
    )
    assert response.status_code == 204

    result = await db_session.execute(
        select(User).where(User.email == "gooddisable2fa@example.test")
    )
    db_user = result.scalar_one()
    assert db_user.totp_enabled is False
    assert db_user.totp_secret_encrypted is None

    remaining = await db_session.execute(
        select(TotpRecoveryCode).where(TotpRecoveryCode.user_id == db_user.id)
    )
    assert remaining.scalars().all() == []


async def test_disable_cannot_be_called_when_not_enabled(
    client: AsyncClient, strong_password: str
) -> None:
    user = await _register(client, "neverenabled2fa@example.test", strong_password)
    response = await client.post(
        "/api/v1/auth/2fa/disable",
        json={"code": "000000"},
        headers=_auth_headers(user["access_token"]),
    )
    assert response.status_code == 409


async def test_login_without_2fa_is_unaffected(client: AsyncClient, strong_password: str) -> None:
    """The unconditional-success path — nothing about 2FA touches a login
    for an account that never enabled it."""
    await _register(client, "no2fa@example.test", strong_password)
    client.cookies.clear()

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "no2fa@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "requires_totp" not in body


async def test_a_challenge_id_can_be_redeemed_at_most_once() -> None:
    from app.core.twofactor.challenge_store import TotpChallengeAlreadyConsumed

    # A fresh id per run: this hits real Redis (not the in-memory fixtures
    # `_fresh_rate_limit_store`/`_fresh_revocation_store` reset per test), so
    # a fixed literal would collide with a key an earlier run already
    # claimed and left to expire on its own 5-minute TTL.
    challenge_id = f"test-challenge-{uuid.uuid4()}"
    await consume_or_raise(challenge_id)
    with pytest.raises(TotpChallengeAlreadyConsumed):
        await consume_or_raise(challenge_id)
