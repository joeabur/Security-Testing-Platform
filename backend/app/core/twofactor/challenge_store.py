"""Redis-backed single-use consumption for a TOTP login challenge.

Ninth Redis-backed store in this codebase, the same fail-closed idiom
`app.core.oauth.state` and `app.core.workflow.replay_guard` already use.
Without this, `create_totp_challenge_token` (`app/auth/security.py`) is
valid for its full 5-minute window and could be redeemed more than once —
every other short-lived, security-relevant token in this platform
(password reset, OAuth state) is single-use, and there is no reason this
one should be the exception.

The dedup key is the challenge token's own `jti` claim, not the token
itself: shorter, and it never puts the token's bytes into Redis.
"""

from __future__ import annotations

import redis.asyncio as redis_async

from app.core.config import get_settings

_KEY_PREFIX = "kervy:totp:challenge-consumed:"
#: Matches the challenge token's own expiry (`_TOTP_CHALLENGE_TTL` in
#: `app/auth/security.py`) — nothing inside the accepted window can be
#: replayed after this key expires, and an expired token independently
#: fails its own `exp` check first regardless.
TTL_SECONDS = 5 * 60


class TotpChallengeConsumptionUnavailable(Exception):
    """Redis could not be reached. Callers must refuse the login attempt,
    never treat an unconfirmed challenge as fresh."""


class TotpChallengeAlreadyConsumed(Exception):
    """This challenge was already redeemed once."""


async def consume_or_raise(jti: str) -> None:
    """Atomically claim `jti`. Raises `TotpChallengeAlreadyConsumed` if it
    was already claimed, `TotpChallengeConsumptionUnavailable` if Redis
    cannot be reached — never silently proceeds either way."""
    client = redis_async.Redis.from_url(get_settings().redis_url, decode_responses=True)
    try:
        claimed = await client.set(f"{_KEY_PREFIX}{jti}", "1", nx=True, ex=TTL_SECONDS)
    except (redis_async.RedisError, OSError) as exc:
        raise TotpChallengeConsumptionUnavailable(str(exc)) from exc
    if not claimed:
        raise TotpChallengeAlreadyConsumed(f"challenge {jti!r} was already redeemed")
