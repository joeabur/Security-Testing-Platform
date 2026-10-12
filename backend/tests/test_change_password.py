"""Self-service password change (`docs/revocation.md` §"What this does not
cover"): already logged in, knows the old password — the gap `logout-all`
was named as standing in for until this existed.

Distinct from `tests/test_password_reset.py`: that proves control of the
account's email inbox and deliberately does not start a session. This proves
the opposite — a browser that already holds a working session and the
current password — so it is trusted to walk away with a fresh one rather
than being sent back to `/login`.
"""

from __future__ import annotations

from httpx import AsyncClient

from app.auth.security import create_access_token
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.user import User


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def _register_and_login(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "Change Password", "password": password},
        headers=await _anon_headers(client),
    )
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 200, response.text
    return {
        "bearer": response.json()["access_token"],
        "session": response.cookies[get_settings().session_cookie_name],
    }


async def test_the_wrong_current_password_is_refused_and_changes_nothing(
    client: AsyncClient, strong_password: str
) -> None:
    creds = await _register_and_login(client, "cp-wrong@example.test", strong_password)
    headers = {"Authorization": f"Bearer {creds['bearer']}"}

    response = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "not-the-real-password", "new_password": "Another-Strong-9"},
        headers=headers,
    )
    assert response.status_code == 400

    # The old token still works — nothing was rotated.
    still_alive = await client.get("/api/v1/auth/me", headers=headers)
    assert still_alive.status_code == 200


async def test_a_correct_change_rotates_the_hash_and_reissues_the_caller_a_fresh_token(
    client: AsyncClient, strong_password: str
) -> None:
    creds = await _register_and_login(client, "cp-ok@example.test", strong_password)
    old_headers = {"Authorization": f"Bearer {creds['bearer']}"}

    response = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": strong_password, "new_password": "A-Brand-New-Password-9"},
        headers=old_headers,
    )
    assert response.status_code == 200, response.text
    new_token = response.json()["access_token"]
    assert new_token != creds["bearer"]

    # The caller is not logged out by its own password change: the new
    # token returned in the response body works immediately.
    new_headers = {"Authorization": f"Bearer {new_token}"}
    alive = await client.get("/api/v1/auth/me", headers=new_headers)
    assert alive.status_code == 200

    # The token used to *make* the change request is itself stale now — it
    # was issued before the `tokens_valid_after` cutover this request set.
    dead = await client.get("/api/v1/auth/me", headers=old_headers)
    assert dead.status_code == 401

    # And the new password, not the old one, is what signs in from here on.
    old_password_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "cp-ok@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    assert old_password_login.status_code == 401

    new_password_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "cp-ok@example.test", "password": "A-Brand-New-Password-9"},
        headers=await _anon_headers(client),
    )
    assert new_password_login.status_code == 200


async def test_every_other_session_is_revoked_not_only_the_one_that_asked(
    client: AsyncClient, strong_password: str
) -> None:
    """`change-password` is a compromise-adjacent event: a session this
    request never learned the jti of (a second device, say) must die too —
    the same cutoff-not-enumeration shape `logout-all` already uses.
    """
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "cp-other-session@example.test",
            "full_name": "R",
            "password": strong_password,
        },
        headers=await _anon_headers(client),
    )
    device_a = await client.post(
        "/api/v1/auth/login",
        json={"email": "cp-other-session@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    device_b = await client.post(
        "/api/v1/auth/login",
        json={"email": "cp-other-session@example.test", "password": strong_password},
        headers=await _anon_headers(client),
    )
    assert device_a.status_code == device_b.status_code == 200
    token_a = device_a.json()["access_token"]
    token_b = device_b.json()["access_token"]
    assert token_a != token_b

    change = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": strong_password, "new_password": "Yet-Another-Strong-9"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert change.status_code == 200

    # device_b never appeared in this request at all, yet it must die too.
    other_device = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token_b}"}
    )
    assert other_device.status_code == 401


async def test_an_oauth_only_account_with_no_local_password_gets_a_400_not_a_500(
    client: AsyncClient, db_session
) -> None:
    user = User(
        email="cp-oauth-only@example.test",
        full_name="OAuth Only",
        password_hash=None,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()

    token = create_access_token(subject=user.id)
    await db_session.commit()

    response = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "anything-at-all", "new_password": "Does-Not-Matter-9"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert response.status_code != 500


async def test_repeated_wrong_guesses_are_eventually_refused_with_retry_after(
    client: AsyncClient, strong_password: str
) -> None:
    creds = await _register_and_login(client, "cp-ratelimit@example.test", strong_password)
    headers = {"Authorization": f"Bearer {creds['bearer']}"}

    saw_429 = False
    for _ in range(30):
        response = await client.post(
            "/api/v1/auth/change-password",
            json={"current_password": "definitely-wrong", "new_password": "Irrelevant-Pass-9"},
            headers=headers,
        )
        if response.status_code == 429:
            saw_429 = True
            assert int(response.headers["Retry-After"]) > 0
            break
        assert response.status_code == 400

    assert saw_429, "unlimited current-password guessing was permitted"


async def test_a_cookie_authenticated_request_without_a_csrf_token_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    """Bearer calls (every other test in this file) bypass CSRF by design —
    only a cookie-authenticated browser request needs the header. Proven
    directly rather than assumed, since `/auth/change-password` is
    deliberately *not* added to `EXEMPT_PATHS`/`ANONYMOUS_CSRF_PATHS`
    (`app/core/csrf/enforce.py`) the way `logout`/`reset-password` are."""
    email = "cp-csrf@example.test"
    await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "R", "password": strong_password},
        headers=await _anon_headers(client),
    )
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": strong_password},
        headers=await _anon_headers(client),
    )
    assert login.status_code == 200
    session_cookie = login.cookies[get_settings().session_cookie_name]

    # Cookie-authenticated, no CSRF header at all.
    response = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": strong_password, "new_password": "Would-Be-Fine-9"},
        cookies={get_settings().session_cookie_name: session_cookie},
    )
    assert response.status_code == 403
