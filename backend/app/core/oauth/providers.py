"""Provider-specific OAuth 2.0 authorization-code-flow mechanics.

Two providers, Google and GitHub, each with its own authorize/token/profile
URLs and its own quirk in the profile step — Google's `userinfo` endpoint
returns an email directly; GitHub's `/user` does not reliably (a user may
keep their email private), so a second call to `/user/emails` is needed to
find the verified primary address. Both quirks are handled here so
`app/api/v1/routers/auth.py`'s callback handler sees one normalized
`OAuthProfile` regardless of provider.

Every outbound call goes through `GatedTransport` under
`app.core.oauth.egress.oauth_egress_context`, scoped to exactly the host the
call needs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import urlencode

from app.core.config import Settings
from app.core.oauth.egress import oauth_egress_context
from app.core.scope.transport import GatedTransport, ScopeBlockedError
from app.models.oauth import OAuthProvider


class OAuthProviderDisabled(Exception):
    """This provider has no client id/secret configured."""


class OAuthExchangeError(Exception):
    """The provider refused the code, or its response could not be parsed
    into a profile. The detail is safe to log but not to show verbatim to
    the caller — it may echo back part of what we sent."""


@dataclass(frozen=True)
class OAuthProfile:
    provider_user_id: str
    email: str
    full_name: str


@dataclass(frozen=True)
class _ProviderConfig:
    authorize_url: str
    token_url: str
    token_host: str
    userinfo_url: str
    userinfo_host: str
    scope: str


_CONFIGS: dict[OAuthProvider, _ProviderConfig] = {
    OAuthProvider.GOOGLE: _ProviderConfig(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        token_host="oauth2.googleapis.com",
        userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
        userinfo_host="openidconnect.googleapis.com",
        scope="openid email profile",
    ),
    OAuthProvider.GITHUB: _ProviderConfig(
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        token_host="github.com",
        userinfo_url="https://api.github.com/user",
        userinfo_host="api.github.com",
        scope="read:user user:email",
    ),
}


def _client_id(settings: Settings, provider: OAuthProvider) -> str:
    value = (
        settings.google_oauth_client_id
        if provider is OAuthProvider.GOOGLE
        else settings.github_oauth_client_id
    )
    if not value:
        raise OAuthProviderDisabled(f"{provider.value} OAuth is not configured")
    return value


def _client_secret(settings: Settings, provider: OAuthProvider) -> str:
    """Read fresh from `os.environ` every call — never cached on `Settings` —
    the same indirection `ai_api_key_env_var` uses for the AI provider key."""
    env_var = (
        settings.google_oauth_client_secret_env_var
        if provider is OAuthProvider.GOOGLE
        else settings.github_oauth_client_secret_env_var
    )
    secret = os.environ.get(env_var) if env_var else None
    if not secret:
        raise OAuthProviderDisabled(f"{provider.value} OAuth is not configured")
    return secret


def enabled(settings: Settings, provider: OAuthProvider) -> bool:
    return (
        settings.google_oauth_enabled
        if provider is OAuthProvider.GOOGLE
        else settings.github_oauth_enabled
    )


def redirect_uri_for(settings: Settings, provider: OAuthProvider) -> str:
    """Where a provider sends the browser back to, on this backend's own
    origin — `app.core.config.Settings.oauth_callback_base_url`'s docstring
    explains why this is deliberately not `public_base_url` (the frontend)."""
    if not settings.oauth_callback_base_url:
        raise OAuthProviderDisabled("KERVY_OAUTH_CALLBACK_BASE_URL is not configured")
    base = settings.oauth_callback_base_url.rstrip("/")
    return f"{base}/api/v1/auth/oauth/{provider.value}/callback"


def authorize_url(
    settings: Settings, provider: OAuthProvider, *, redirect_uri: str, state: str
) -> str:
    config = _CONFIGS[provider]
    params = {
        "client_id": _client_id(settings, provider),
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": config.scope,
        "state": state,
    }
    if provider is OAuthProvider.GOOGLE:
        # Least-privilege at the provider's own consent screen too: ask for
        # only what this flow reads, and force a refreshed consent rather
        # than silently reusing a grant from a different client.
        params["access_type"] = "online"
        params["prompt"] = "select_account"
    return f"{config.authorize_url}?{urlencode(params)}"


async def exchange_code_for_profile(
    settings: Settings,
    provider: OAuthProvider,
    *,
    code: str,
    redirect_uri: str,
    transport: GatedTransport | None = None,
) -> OAuthProfile:
    """Trade an authorization code for the provider's profile. Raises
    `OAuthExchangeError` on anything short of a usable profile — a caller
    never has to guess which of several optional fields is missing.

    `transport` is injectable the same way `app.core.vcs.github.GitHubClient`
    takes one: production leaves it as the real `GatedTransport`, a test
    passes something duck-typing `.send()` so it never needs to resolve a
    real provider hostname or a live respx-mocked socket.
    """
    config = _CONFIGS[provider]
    client_id = _client_id(settings, provider)
    client_secret = _client_secret(settings, provider)
    transport = transport or GatedTransport()

    try:
        token_response = await transport.send(
            oauth_egress_context(config.token_host),
            method="POST",
            url=config.token_url,
            headers={"Accept": "application/json"},
            content=urlencode(
                {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                }
            ).encode("ascii"),
            timeout_seconds=15.0,
        )
    except ScopeBlockedError as exc:
        raise OAuthExchangeError(
            f"token exchange refused by scope engine: {exc.decision.reason}"
        ) from exc

    if token_response.status_code != 200:
        raise OAuthExchangeError(f"token endpoint returned HTTP {token_response.status_code}")

    try:
        token_payload = json.loads(token_response.body)
        access_token = str(token_payload["access_token"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise OAuthExchangeError("token endpoint response did not contain access_token") from exc

    try:
        profile_response = await transport.send(
            oauth_egress_context(config.userinfo_host),
            method="GET",
            url=config.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            timeout_seconds=15.0,
        )
    except ScopeBlockedError as exc:
        raise OAuthExchangeError(
            f"profile fetch refused by scope engine: {exc.decision.reason}"
        ) from exc

    if profile_response.status_code != 200:
        raise OAuthExchangeError(f"profile endpoint returned HTTP {profile_response.status_code}")

    try:
        profile_payload = json.loads(profile_response.body)
    except json.JSONDecodeError as exc:
        raise OAuthExchangeError("profile endpoint response was not valid JSON") from exc

    if provider is OAuthProvider.GOOGLE:
        return await _google_profile(profile_payload)
    return await _github_profile(
        profile_payload, access_token=access_token, transport=transport, config=config
    )


async def _google_profile(payload: dict[str, object]) -> OAuthProfile:
    try:
        subject = str(payload["sub"])
        email = str(payload["email"])
    except KeyError as exc:
        raise OAuthExchangeError("Google profile response is missing sub/email") from exc
    full_name = str(payload.get("name") or email)
    return OAuthProfile(provider_user_id=subject, email=email, full_name=full_name)


async def _github_profile(
    payload: dict[str, object],
    *,
    access_token: str,
    transport: GatedTransport,
    config: _ProviderConfig,
) -> OAuthProfile:
    try:
        subject = str(payload["id"])
    except KeyError as exc:
        raise OAuthExchangeError("GitHub profile response is missing id") from exc
    full_name = str(payload.get("name") or payload.get("login") or subject)

    email = payload.get("email")
    if not email:
        try:
            emails_response = await transport.send(
                oauth_egress_context(config.userinfo_host),
                method="GET",
                url="https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout_seconds=15.0,
            )
        except ScopeBlockedError as exc:
            raise OAuthExchangeError(
                f"email fetch refused by scope engine: {exc.decision.reason}"
            ) from exc
        if emails_response.status_code != 200:
            raise OAuthExchangeError(f"emails endpoint returned HTTP {emails_response.status_code}")
        try:
            emails = json.loads(emails_response.body)
        except json.JSONDecodeError as exc:
            raise OAuthExchangeError("emails endpoint response was not valid JSON") from exc
        primary = next(
            (row["email"] for row in emails if row.get("primary") and row.get("verified")), None
        )
        email = primary or next((row["email"] for row in emails if row.get("verified")), None)
        if not email:
            raise OAuthExchangeError("GitHub account has no verified email to sign in with")

    return OAuthProfile(provider_user_id=subject, email=str(email), full_name=full_name)
