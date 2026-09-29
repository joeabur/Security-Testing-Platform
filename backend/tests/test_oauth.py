"""Social OAuth login (Google, GitHub).

Covers the authorization-code round trip end to end (`/authorize` issues a
state nonce and redirects; `/callback` consumes it, exchanges the code, and
either logs an existing identity in or creates a new account), the identity
rule that keeps a provider profile from silently taking over an existing
password account (`app/models/oauth.py`'s module docstring), and the
single-use state store on its own.

`exchange_code_for_profile`'s outbound calls are never let onto a real
network: `GatedTransport` is injected with a `FakeDnsResolver` so the scope
engine's allowlist check passes without a real lookup, and `respx` replaces
the actual socket — the same two-part substitution
`tests/test_assistant_api.py::_worker_transport` uses for the lab fixture.
"""

from __future__ import annotations

import pytest
import respx
from httpx import AsyncClient, Response
from sqlalchemy import select

from app.core.config import get_settings
from app.core.oauth import providers as oauth_providers
from app.core.oauth.state import OAuthStateInvalid, OAuthStateStore
from app.core.scope.transport import GatedTransport
from app.models.oauth import OAuthIdentity, OAuthProvider
from app.models.user import User
from tests.security.conftest import FakeDnsResolver

pytestmark = pytest.mark.asyncio

_GOOGLE_HOSTS = {
    "oauth2.googleapis.com": ["203.0.113.10"],
    "openidconnect.googleapis.com": ["203.0.113.11"],
}
_GITHUB_HOSTS = {"github.com": ["203.0.113.12"], "api.github.com": ["203.0.113.13"]}


@pytest.fixture(autouse=True)
def _oauth_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET_ENV_VAR", "TEST_GOOGLE_SECRET")
    monkeypatch.setenv("TEST_GOOGLE_SECRET", "google-secret")  # pragma: allowlist secret
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "github-client-id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET_ENV_VAR", "TEST_GITHUB_SECRET")
    monkeypatch.setenv("TEST_GITHUB_SECRET", "github-secret")  # pragma: allowlist secret
    monkeypatch.setenv("KERVY_OAUTH_CALLBACK_BASE_URL", "https://api.kervy.example.test")
    monkeypatch.setenv("KERVY_PUBLIC_BASE_URL", "https://app.kervy.example.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _fake_oauth_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every provider host the tests use resolves through a fake resolver, so
    the scope engine's allowlist check passes without a real DNS lookup —
    `respx` (below, per test) is what actually stops a socket from opening."""
    resolver = FakeDnsResolver({**_GOOGLE_HOSTS, **_GITHUB_HOSTS})
    transport = GatedTransport(dns_resolver=resolver)
    monkeypatch.setattr(oauth_providers, "GatedTransport", lambda *a, **k: transport)


async def test_providers_reports_which_are_configured(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/oauth/providers")
    assert response.status_code == 200
    assert response.json() == {"google": True, "github": True}


async def test_providers_reports_false_when_unconfigured(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    get_settings.cache_clear()
    response = await client.get("/api/v1/auth/oauth/providers")
    assert response.json() == {"google": True, "github": False}
    get_settings.cache_clear()


async def test_unknown_provider_is_404(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/oauth/notaprovider/authorize", follow_redirects=False
    )
    assert response.status_code == 404


async def test_disabled_provider_is_404(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    get_settings.cache_clear()
    response = await client.get("/api/v1/auth/oauth/github/authorize", follow_redirects=False)
    assert response.status_code == 404
    get_settings.cache_clear()


async def test_authorize_redirects_with_a_fresh_state(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/oauth/google/authorize", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "client_id=google-client-id" in location
    assert "state=" in location
    assert "redirect_uri=" in location


def _google_userinfo(*, sub: str, email: str) -> Response:
    return Response(200, json={"sub": sub, "email": email, "name": "Ada Example"})


def _mock_google_token_and_profile(router: respx.MockRouter, *, sub: str, email: str) -> None:
    router.post("https://oauth2.googleapis.com/token").mock(
        return_value=Response(200, json={"access_token": "at-1", "token_type": "bearer"})
    )
    router.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=_google_userinfo(sub=sub, email=email)
    )


async def _issued_state(provider: OAuthProvider) -> str:
    return await OAuthStateStore().issue(provider=provider.value)


async def test_callback_creates_a_new_account_and_signs_in(
    client: AsyncClient, db_session
) -> None:
    state = await _issued_state(OAuthProvider.GOOGLE)
    with respx.mock(assert_all_called=False) as router:
        _mock_google_token_and_profile(router, sub="google-subject-1", email="newbie@example.test")
        response = await client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"code": "auth-code", "state": state},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert response.headers["location"] == "https://app.kervy.example.test/organizations/new"
    assert "kervy_session" in response.cookies

    user_result = await db_session.execute(select(User).where(User.email == "newbie@example.test"))
    user = user_result.scalar_one()
    assert user.password_hash is None

    identity_result = await db_session.execute(
        select(OAuthIdentity).where(OAuthIdentity.user_id == user.id)
    )
    identity = identity_result.scalar_one()
    assert identity.provider == "google"
    assert identity.provider_user_id == "google-subject-1"


async def test_callback_logs_in_an_existing_linked_account(client: AsyncClient, db_session) -> None:
    state = await _issued_state(OAuthProvider.GOOGLE)
    with respx.mock(assert_all_called=False) as router:
        _mock_google_token_and_profile(
            router, sub="google-subject-2", email="returning@example.test"
        )
        first = await client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"code": "auth-code-1", "state": state},
            follow_redirects=False,
        )
    assert first.status_code == 302

    state2 = await _issued_state(OAuthProvider.GOOGLE)
    with respx.mock(assert_all_called=False) as router:
        _mock_google_token_and_profile(
            router, sub="google-subject-2", email="returning@example.test"
        )
        second = await client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"code": "auth-code-2", "state": state2},
            follow_redirects=False,
        )
    assert second.status_code == 302
    assert second.headers["location"] == "https://app.kervy.example.test/dashboard"

    users = (
        await db_session.execute(select(User).where(User.email == "returning@example.test"))
    ).scalars().all()
    assert len(users) == 1


async def test_callback_refuses_to_link_an_existing_password_account_by_email(
    client: AsyncClient, strong_password: str
) -> None:
    from app.core.csrf import anon as csrf_anon
    from app.core.csrf.enforce import HEADER_NAME

    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "haspassword@example.test",
            "full_name": "Has Password",
            "password": strong_password,
        },
        headers={HEADER_NAME: token},
    )

    state = await _issued_state(OAuthProvider.GOOGLE)
    with respx.mock(assert_all_called=False) as router:
        _mock_google_token_and_profile(
            router, sub="google-subject-attacker", email="haspassword@example.test"
        )
        response = await client.get(
            "/api/v1/auth/oauth/google/callback",
            params={"code": "auth-code", "state": state},
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert "oauth_error=email_already_registered" in response.headers["location"]
    assert "kervy_session" not in response.cookies


async def test_callback_rejects_a_state_it_never_issued(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/oauth/google/callback",
        params={"code": "auth-code", "state": "not-a-real-state"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "oauth_error=invalid_state" in response.headers["location"]


async def test_callback_rejects_missing_code(client: AsyncClient) -> None:
    state = await _issued_state(OAuthProvider.GOOGLE)
    response = await client.get(
        "/api/v1/auth/oauth/google/callback",
        params={"state": state},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "oauth_error=missing_code_or_state" in response.headers["location"]


async def test_callback_reflects_a_provider_denial(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/auth/oauth/google/callback",
        params={"error": "access_denied"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "oauth_error=provider_denied" in response.headers["location"]


async def test_a_state_can_be_redeemed_at_most_once() -> None:
    store = OAuthStateStore()
    state = await store.issue(provider="google")
    await store.consume(state, provider="google")
    with pytest.raises(OAuthStateInvalid):
        await store.consume(state, provider="google")


async def test_a_state_cannot_be_redeemed_for_a_different_provider() -> None:
    store = OAuthStateStore()
    state = await store.issue(provider="google")
    with pytest.raises(OAuthStateInvalid):
        await store.consume(state, provider="github")


async def test_github_falls_back_to_the_verified_emails_endpoint_when_private() -> None:
    """GitHub's `/user` omits `email` when the account keeps it private; the
    client must fetch `/user/emails` and pick the primary, verified one."""
    resolver = FakeDnsResolver({**_GOOGLE_HOSTS, **_GITHUB_HOSTS})
    transport = GatedTransport(dns_resolver=resolver)
    settings = get_settings()

    with respx.mock(assert_all_called=False) as router:
        router.post("https://github.com/login/oauth/access_token").mock(
            return_value=Response(200, json={"access_token": "gh-at-1", "token_type": "bearer"})
        )
        router.get("https://api.github.com/user").mock(
            return_value=Response(200, json={"id": 42, "login": "octocat", "email": None})
        )
        router.get("https://api.github.com/user/emails").mock(
            return_value=Response(
                200,
                json=[
                    {"email": "secondary@example.test", "primary": False, "verified": True},
                    {"email": "primary@example.test", "primary": True, "verified": True},
                ],
            )
        )
        profile = await oauth_providers.exchange_code_for_profile(
            settings,
            OAuthProvider.GITHUB,
            code="code",
            redirect_uri="https://api.kervy.example.test/api/v1/auth/oauth/github/callback",
            transport=transport,
        )

    assert profile.provider_user_id == "42"
    assert profile.email == "primary@example.test"
    assert profile.full_name == "octocat"
