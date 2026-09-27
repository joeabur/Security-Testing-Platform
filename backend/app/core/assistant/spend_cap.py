"""A cumulative AI spend cap, enforced across calls, not just within one.

`PROVIDER_BUDGETS` (egress.py) bounds a single interaction: `platform_egress_
context()` builds a fresh `BudgetTracker` every call, so its $5.00 cost
ceiling resets on every request and nothing stops a thousand $4.99
interactions from costing $4,990. This module is the boundary that actually
accumulates: one counter, shared across every process via Redis (the same
store `app/core/ratelimit/` and `app/core/revocation/` already depend on),
that rolls over once a day and refuses a call that would push the day's
total over `settings.ai_daily_spend_cap_usd`.

Scoped to the whole platform, not per organization, for the same reason the
`$5.00` interaction budget is: this guards the operator's own provider bill,
which is one bill regardless of which organization's assessment triggered
the spend. A per-organization cap is a legitimate product feature (showback,
chargebacks) but a different one — this module is the safety ceiling, not
cost allocation.

**Fails closed.** If Redis is unreachable, a call is refused rather than let
through unmetered — the opposite trade the rate limiter makes (see
`app/core/ratelimit/contract.py` for why *that* boundary fails open). The
two controls protect different things: an unmetered login attempt costs
nothing; an unmetered provider call costs real money and cannot be undone
once sent.
"""

from __future__ import annotations

from datetime import UTC, datetime

import redis.asyncio as redis_async
from redis.commands.core import AsyncScript

from app.core.config import get_settings

_KEY_PREFIX = "aegis:ai_spend:"
_DAY_SECONDS = 26 * 60 * 60  # a day plus slack, so a slow clock never drops the key early

# Atomic check-then-increment: without this in one script, two concurrent
# calls could each read a total just under the cap and both proceed,
# together pushing it well over. `INCRBYFLOAT` alone has no way to refuse.
_RESERVE_SCRIPT = """
local key = KEYS[1]
local cap = tonumber(ARGV[1])
local cost = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local current = tonumber(redis.call('GET', key) or '0')
if current + cost > cap then
    return {0, current}
end
local new_total = redis.call('INCRBYFLOAT', key, cost)
redis.call('EXPIRE', key, ttl)
return {1, new_total}
"""


class DailySpendCapExceeded(Exception):
    """This call would push the platform's cumulative AI spend for today
    over the configured cap."""

    def __init__(self, cap_usd: float, spent_usd: float) -> None:
        super().__init__(
            f"cumulative AI spend for today (${spent_usd:.2f}) plus this call "
            f"would exceed the ${cap_usd:.2f} daily cap"
        )
        self.cap_usd = cap_usd
        self.spent_usd = spent_usd


class SpendCapStoreUnavailable(Exception):
    """The Redis-backed counter could not be reached. Callers must treat
    this as a refusal, not a pass-through — see the module docstring."""


def _today_key() -> str:
    return f"{_KEY_PREFIX}{datetime.now(UTC).date().isoformat()}"


class SpendCapTracker:
    """Reserves cumulative spend against the operator's configured daily cap."""

    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None
        self._script: AsyncScript | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
            self._script = self._client.register_script(_RESERVE_SCRIPT)
        return self._client

    async def reserve(self, cost_usd: float, *, cap_usd: float | None = None) -> float:
        """Charge `cost_usd` against today's total, or raise if that would
        exceed the cap. Returns the new running total on success."""
        cap = cap_usd if cap_usd is not None else get_settings().ai_daily_spend_cap_usd
        self._connect()
        assert self._script is not None
        try:
            allowed, total = await self._script(
                keys=[_today_key()], args=[cap, cost_usd, _DAY_SECONDS]
            )
        except (redis_async.RedisError, OSError) as exc:
            raise SpendCapStoreUnavailable(str(exc)) from exc
        total = float(total)
        if not allowed:
            raise DailySpendCapExceeded(cap, total)
        return total

    async def spent_today(self) -> float:
        try:
            value = await self._connect().get(_today_key())
        except (redis_async.RedisError, OSError) as exc:
            raise SpendCapStoreUnavailable(str(exc)) from exc
        return float(value) if value is not None else 0.0
