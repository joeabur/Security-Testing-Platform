"""Redis-backed state-nonce store for the OAuth authorization-code flow.

Eighth Redis-backed store in this codebase (`app/core/workflow/replay_guard.py`
was the seventh), the same "state a fresh read, an explicit TTL, a stated
fail direction" discipline. **Fails CLOSED**, like the replay guard and
`app.core.agent.session_store` and unlike `app.core.ratelimit`'s deliberate
fail-open: a `state` parameter that cannot be proven to be one this server
issued is refused, never treated as valid because the store could not be
reached.

The nonce is what stands in for the anonymous CSRF token `/auth/login` and
`/auth/register` use (`app/core/csrf/anon.py`): there is no session yet to
bind a same-site check to, and `GET .../authorize` cannot itself require a
header a redirect cannot carry. `issue` mints one and the caller sets it as
the `state` query parameter sent to the provider; `consume` looks it up and
deletes it in one round trip (`GETDEL`), so a `state` value can be redeemed
at most once — a second callback replaying the same value, whether accidental
(a reloaded page) or an attempted login-CSRF, fails the same way an unknown
one does.
"""

from __future__ import annotations

import secrets

import redis.asyncio as redis_async

from app.core.config import get_settings

_KEY_PREFIX = "kervy:oauth:state:"
TTL_SECONDS = 600
_STATE_BYTES = 32


class OAuthStateUnavailable(Exception):
    """Redis could not be reached. Callers must refuse the callback."""


class OAuthStateInvalid(Exception):
    """This `state` was never issued, has already been redeemed, or has
    expired. Indistinguishable from each other on purpose — telling an
    attacker which one happened would leak nothing useful but is one more
    thing to get wrong."""


class OAuthStateStore:
    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
        return self._client

    async def issue(self, *, provider: str) -> str:
        """A fresh nonce, claimed for `provider` only — the value returned by
        `consume` must match the provider the callback is for, so a state
        minted for a Google login cannot be replayed against the GitHub
        callback."""
        state = secrets.token_urlsafe(_STATE_BYTES)
        try:
            await self._connect().set(f"{_KEY_PREFIX}{state}", provider, ex=TTL_SECONDS)
        except (redis_async.RedisError, OSError) as exc:
            raise OAuthStateUnavailable(str(exc)) from exc
        return state

    async def consume(self, state: str, *, provider: str) -> None:
        """Redeem `state` for `provider`, or raise. Single-use: the key is
        deleted whether or not it matched, so a stolen but already-redeemed
        value is never valid again."""
        try:
            value = await self._connect().getdel(f"{_KEY_PREFIX}{state}")
        except (redis_async.RedisError, OSError) as exc:
            raise OAuthStateUnavailable(str(exc)) from exc
        if value != provider:
            raise OAuthStateInvalid("state is unknown, expired, or already used")
