"""Where revoked token ids live.

Same shape as `app/core/ratelimit/stores.py` — a `MemoryStore` for tests and a
single process, a `RedisStore` for real deployments — but the failure mode is
the opposite. The rate-limit store swallows a Redis error and lets the caller
decide to fail open; this one **raises**, because `contract.py` requires the
caller to fail closed and a store that hid the error would make that
impossible to get right at the call site.
"""

from __future__ import annotations

import time

import redis.asyncio as redis_async

from app.core.config import get_settings
from app.core.revocation.contract import RevocationStoreUnavailable

_KEY_PREFIX = "kervy:revoked:jti"


class MemoryStore:
    """An in-process deny-list. Tests and single-process deployments only —
    two API workers would each have their own list, so a token revoked
    against one would keep working against the other."""

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}

    def _now(self) -> float:
        return time.monotonic()

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        self._entries[jti] = self._now() + ttl_seconds

    async def is_revoked(self, jti: str) -> bool:
        expires = self._entries.get(jti)
        if expires is None:
            return False
        if expires <= self._now():
            del self._entries[jti]
            return False
        return True


class RedisStore:
    """The real one: a deny-list shared across every API process."""

    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
        return self._client

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        try:
            # `ttl_seconds` can be zero or negative for a token that is already
            # past expiry (clock skew, a very long-lived request). SET with a
            # non-positive EX is a Redis error, and there is nothing left to
            # revoke at that point anyway, so it is a deliberate no-op rather
            # than a crash on logout.
            if ttl_seconds <= 0:
                return
            await self._connect().set(f"{_KEY_PREFIX}:{jti}", "1", ex=ttl_seconds)
        except (redis_async.RedisError, OSError) as exc:
            raise RevocationStoreUnavailable(str(exc)) from exc

    async def is_revoked(self, jti: str) -> bool:
        try:
            return bool(await self._connect().exists(f"{_KEY_PREFIX}:{jti}"))
        except (redis_async.RedisError, OSError) as exc:
            raise RevocationStoreUnavailable(str(exc)) from exc
