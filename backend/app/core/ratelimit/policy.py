"""The rules, and the limiter that applies them.

The numbers live here so they are in one reviewable place rather than spread
across handlers, and so a test can assert the shape of the policy rather than
observe it a request at a time.

## Choosing the numbers

They are chosen against what each attack needs, not picked to look strict.

**Login, per identity: 10 failures per 15 minutes.** An online guessing attack
needs thousands of attempts to be worth running; 40/hour makes even a
thousand-word list take a day per account, at which point the audit log has
been screaming for hours. A real person who has forgotten which password they
used gets about ten tries before waiting, which is generous rather than
punishing.

**Login, per IP: 60 failures per 15 minutes.** Higher, because an office behind
one NAT is many legitimate people sharing an address. It still bounds spraying
from a single host to four accounts an hour.

**Registration, per IP: 10 per hour.** Registration is unauthenticated and
creates rows; without a bound it is a free write primitive. Nothing legitimate
needs eleven accounts an hour from one address.

**Only failures count against the identity budget.** A successful login resets
it. Counting successes would mean a busy legitimate user throttles themselves,
which is how a rate limit gets switched off in production. The IP budget counts
failures too, for the same reason — a shared office address should not exhaust
itself on people logging in correctly.

**Agent tool calls, per identity: 60 per 5 minutes.** Unlike login, every
call here counts, success or failure — a tool call is an authenticated
action with its own audit trail, not a guess to forgive. The bound exists
for a runaway planning loop (Implementation phase 4), not a legitimate
investigation: sixty reads in five minutes is generous for a person, and a
loop that would exceed it is the thing worth stopping.
"""

from __future__ import annotations

import structlog

from app.core.ratelimit.contract import (
    Decision,
    Dimension,
    RateLimitStore,
    Rule,
    StoreUnavailable,
)
from app.core.ratelimit.keys import identity_key, ip_key

logger = structlog.get_logger()

LOGIN_IDENTITY = Rule(name="login", dimension=Dimension.IDENTITY, limit=10, window_seconds=15 * 60)
LOGIN_IP = Rule(name="login", dimension=Dimension.IP, limit=60, window_seconds=15 * 60)
REGISTER_IP = Rule(name="register", dimension=Dimension.IP, limit=10, window_seconds=60 * 60)
# Registered ahead of need: no route calls `check("agent_tool_call", ...)`
# yet (the agent's own API surface lands in a later phase), but the policy
# entry is added alongside the tool registry it bounds rather than as an
# afterthought once a route exists to forget it for.
AGENT_TOOL_CALL_IDENTITY = Rule(
    name="agent_tool_call", dimension=Dimension.IDENTITY, limit=60, window_seconds=5 * 60
)

#: What each protected route consumes. A route absent from here is not limited,
#: which is why `tests/security/test_rate_limit.py` asserts the set rather than
#: trusting that somebody remembered.
POLICY: dict[str, tuple[Rule, ...]] = {
    "login": (LOGIN_IDENTITY, LOGIN_IP),
    "register": (REGISTER_IP,),
    "agent_tool_call": (AGENT_TOOL_CALL_IDENTITY,),
}


class RateLimiter:
    """Applies a policy against a store.

    Holds no state of its own: the counters are the store's, and the rules are
    module constants. That makes an instance cheap to build per request and
    trivial to substitute in a test.
    """

    def __init__(self, store: RateLimitStore, *, pepper: str) -> None:
        self._store = store
        self._pepper = pepper

    def _key(self, rule: Rule, *, client_ip: str, identity: str | None) -> str | None:
        if rule.dimension is Dimension.IP:
            return ip_key(rule.name, client_ip)
        if identity is None:
            # An identity rule with no identity to key on is skipped rather
            # than folded into a shared bucket: one shared identity bucket
            # would let any caller exhaust it for everyone.
            return None
        return identity_key(rule.name, identity, pepper=self._pepper)

    async def check(self, route: str, *, client_ip: str, identity: str | None = None) -> Decision:
        """Consume budget for `route` and decide.

        Returns the **first** refusal, so a caller learns which rule stopped it
        and gets a `Retry-After` for that rule specifically. Rules after a
        refusal are not consumed: an already-throttled attacker should not also
        be able to drive another bucket up by continuing to knock.
        """
        for rule in POLICY.get(route, ()):
            key = self._key(rule, client_ip=client_ip, identity=identity)
            if key is None:
                continue
            try:
                count = await self._store.incr(key, rule.window_seconds)
                if count > rule.limit:
                    retry_after = await self._store.ttl(key) or rule.window_seconds
                    return Decision(
                        allowed=False,
                        rule_name=f"{rule.name}:{rule.dimension.value}",
                        remaining=0,
                        retry_after_seconds=retry_after,
                    )
            except StoreUnavailable as exc:
                # Fail open, loudly. `contract.py` explains why this boundary
                # is the one that does. The log is the operator's only signal
                # that a control they believe is on has stopped counting.
                logger.error(
                    "rate_limit_store_unavailable",
                    route=route,
                    rule=f"{rule.name}:{rule.dimension.value}",
                    error=str(exc),
                )
                return Decision(allowed=True, rule_name=rule.name, degraded=True)
        return Decision(allowed=True, rule_name=route)

    async def clear(self, route: str, *, client_ip: str, identity: str | None = None) -> None:
        """Forget this attempt's counters after a success.

        Called on a successful login so a person who mistyped their password
        four times is not one mistake away from a wait. Failures alone should
        accumulate; that is the signal being measured.
        """
        for rule in POLICY.get(route, ()):
            key = self._key(rule, client_ip=client_ip, identity=identity)
            if key is None:
                continue
            try:
                await self._store.reset(key)
            except StoreUnavailable:
                # Nothing to do and nothing at risk: an uncleared counter
                # expires on its own, and the next failure is counted normally.
                logger.warning("rate_limit_reset_failed", route=route, rule=rule.name)
