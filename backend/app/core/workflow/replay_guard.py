"""Redis-backed replay protection for the inbound webhook endpoint.

The seventh Redis-backed store in this codebase, following the same "state
a fresh read, an explicit TTL, a stated fail direction" discipline as the
other six (Celery broker, run kill switch, rate limiter, JWT revocation, AI
spend cap, agent investigation session store).

**Fails CLOSED**, the same choice `app.core.agent.session_store` and
`app.core.assistant.spend_cap` make and the opposite of `app.core.ratelimit`'s
deliberate fail-open — replay protection exists specifically to refuse a
request that looks legitimate; degrading to "let it through" on a Redis
outage would defeat the entire point. An unattended trigger that cannot be
proven fresh is refused, never accepted as if it were.

The dedup key is the signature string itself, not a caller-supplied
delivery-id header: `signing.sign()` covers the timestamp and the exact
body bytes, so two distinct legitimate deliveries will not collide, and a
replay of the exact same signed request will. The TTL is double
`signing.DEFAULT_TOLERANCE_SECONDS` so nothing inside the accepted
timestamp window can be replayed after this key expires and a stale replay
independently fails the timestamp check first.
"""

from __future__ import annotations

import redis.asyncio as redis_async

from app.core.config import get_settings
from app.core.integrations.signing import DEFAULT_TOLERANCE_SECONDS

_KEY_PREFIX = "aegis:workflow:webhook-seen:"
TTL_SECONDS = DEFAULT_TOLERANCE_SECONDS * 2


class WebhookReplayGuardUnavailable(Exception):
    """Redis could not be reached. Callers must refuse the webhook, never
    accept it as unseen-by-default — see the module docstring."""


class WebhookReplayed(Exception):
    """This exact signature was already accepted once."""


def _key(signature: str) -> str:
    return f"{_KEY_PREFIX}{signature}"


class WebhookReplayGuard:
    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
        return self._client

    async def mark_seen_or_raise(self, signature: str) -> None:
        """Atomically claim this signature. Raises `WebhookReplayed` if it
        was already claimed, `WebhookReplayGuardUnavailable` if Redis cannot
        be reached — never silently proceeds either way."""
        try:
            # `SET ... NX EX` in one round trip: the claim and the TTL are
            # set together, so there is no window where a key exists
            # without an expiry attached to it.
            claimed = await self._connect().set(_key(signature), "1", nx=True, ex=TTL_SECONDS)
        except (redis_async.RedisError, OSError) as exc:
            raise WebhookReplayGuardUnavailable(str(exc)) from exc
        if not claimed:
            raise WebhookReplayed(f"signature {signature!r} was already accepted")
