"""The scope engine — the single choke point every outbound request is
checked against before it is allowed to be sent. docs/BUILD_SPEC.md §6.

Every branch below either allows or denies with a named `rule`; there is no
path that returns "allowed" as a fallback. The whole `check()` call is
wrapped so that *any* unexpected exception fails closed (denied, run
halted) rather than propagating into a caller that might treat "an
exception happened" as "well, I'll just send it anyway."
"""

from collections.abc import Mapping
from urllib.parse import urlsplit

from app.core.scope.budgets import BudgetExceeded
from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver
from app.core.scope.hostmatch import (
    hostname_matches_any,
    is_blocked_ip,
    parse_ip_ranges,
    path_matches_any,
)
from app.core.scope.models import ScopeDecision


class ScopeEngine:
    async def check(
        self,
        ctx: RunContext,
        *,
        dns_resolver: DnsResolver,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        estimated_tokens_sent: int = 0,
        estimated_tokens_received: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> ScopeDecision:
        try:
            return await self._check(
                ctx,
                dns_resolver=dns_resolver,
                method=method,
                url=url,
                headers=headers or {},
                estimated_tokens_sent=estimated_tokens_sent,
                estimated_tokens_received=estimated_tokens_received,
                estimated_cost_usd=estimated_cost_usd,
            )
        except Exception as exc:  # noqa: BLE001 - deliberate fail-closed boundary
            ctx.halt(f"scope engine internal error: {exc}")
            return ScopeDecision(
                allowed=False,
                rule="internal_error",
                reason=f"scope engine raised an unexpected error: {exc}",
                halted=True,
            )

    async def _check(
        self,
        ctx: RunContext,
        *,
        dns_resolver: DnsResolver,
        method: str,
        url: str,
        headers: Mapping[str, str],
        estimated_tokens_sent: int,
        estimated_tokens_received: int,
        estimated_cost_usd: float,
    ) -> ScopeDecision:
        if ctx.halted:
            return ScopeDecision(False, "halted", ctx.halted_reason or "run halted", halted=True)

        if ctx.kill_switch.tripped:
            ctx.halt("kill switch tripped")
            return ScopeDecision(False, "kill_switch", "kill switch tripped", halted=True)

        now = ctx.clock()
        if now < ctx.authorization.valid_from or now >= ctx.authorization.valid_until:
            ctx.halt("authorization is not currently valid")
            return ScopeDecision(
                False, "authorization_expired", "authorization is not currently valid", halted=True
            )

        for window in ctx.roe.blackout_windows:
            if window.contains(now):
                return ScopeDecision(
                    False, "blackout_window", "current time is in a blackout window"
                )

        shape_decision = await self._check_url_shape(
            ctx, dns_resolver=dns_resolver, method=method, url=url, headers=headers
        )
        if not shape_decision.allowed:
            return shape_decision

        try:
            await ctx.budgets.reserve(
                estimated_tokens_sent=estimated_tokens_sent,
                estimated_tokens_received=estimated_tokens_received,
                estimated_cost_usd=estimated_cost_usd,
            )
        except BudgetExceeded as exc:
            ctx.halt(f"{exc.dimension} budget exceeded")
            return ScopeDecision(False, f"budget_exceeded:{exc.dimension}", str(exc), halted=True)

        return ScopeDecision(True, "allow", "request is in scope")

    async def _check_url_shape(
        self,
        ctx: RunContext,
        *,
        dns_resolver: DnsResolver,
        method: str,
        url: str,
        headers: Mapping[str, str],
    ) -> ScopeDecision:
        """Domain/path/method/header/IP checks only — no budget, no auth,
        no kill-switch. Used by `_check` for the real pipeline, and reused
        as-is by `check_redirect_target` to validate a 3xx Location header
        without consuming any of the original request's budget reservation.
        """
        parsed = urlsplit(url)
        if "@" in parsed.netloc:
            return ScopeDecision(False, "userinfo_in_url", "URL contains userinfo (user@host)")

        hostname = parsed.hostname
        if not hostname:
            return ScopeDecision(False, "unparseable_url", "could not determine a hostname")

        if hostname_matches_any(hostname, ctx.roe.excluded_domains):
            return ScopeDecision(False, "excluded_domain", f"{hostname} is explicitly excluded")

        if not hostname_matches_any(hostname, ctx.roe.allowed_domains):
            return ScopeDecision(False, "domain_not_allowlisted", f"{hostname} is not allowlisted")

        path = parsed.path or "/"
        if path_matches_any(path, ctx.roe.excluded_paths):
            return ScopeDecision(False, "excluded_path", f"{path} is explicitly excluded")

        if ctx.roe.allowed_paths and not path_matches_any(path, ctx.roe.allowed_paths):
            return ScopeDecision(False, "path_not_allowlisted", f"{path} is not allowlisted")

        if method.upper() not in ctx.roe.allowed_methods:
            return ScopeDecision(False, "method_not_allowed", f"{method} is not an allowed method")

        header_names_lower = {h.lower() for h in headers}
        for forbidden in ctx.roe.forbidden_headers:
            if forbidden.lower() in header_names_lower:
                return ScopeDecision(
                    False, "forbidden_header", f"{forbidden} is a forbidden header"
                )

        try:
            ips = await dns_resolver.resolve(hostname)
        except Exception as exc:  # noqa: BLE001 - an unresolvable host is a normal outcome
            # Fail closed — without an address there is no way to prove the
            # host is not internal, so the request is refused. But this is
            # **not** a halt: a hostname that does not resolve says nothing
            # about the other work in this run, and treating it as an engine
            # fault let one dead host abort an entire assessment.
            return ScopeDecision(
                False,
                "dns_resolution_failed",
                f"{hostname} could not be resolved ({exc}); refusing to send without "
                "being able to check the address",
            )

        if not ips:
            return ScopeDecision(
                False,
                "dns_resolution_failed",
                f"{hostname} resolved to no addresses; refusing to send without being "
                "able to check the address",
            )

        allowed_ranges = parse_ip_ranges(ctx.roe.allowed_ip_ranges)
        for ip in ips:
            if is_blocked_ip(ip, allowed_ranges):
                return ScopeDecision(False, "blocked_ip", f"{hostname} resolved to blocked IP {ip}")

        return ScopeDecision(True, "allow", "url is in scope")

    async def explain(
        self,
        ctx: RunContext,
        *,
        dns_resolver: DnsResolver,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        estimated_tokens_sent: int = 0,
        estimated_tokens_received: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> ScopeDecision:
        """`kervy-ai scope explain` / the dry-run preview
        (docs/BUILD_SPEC.md §6.2, §18): reports the decision this request
        *would* get, including whether it would exceed budget, without
        reserving budget, tripping `ctx.halted`, or sending anything.
        """
        try:
            if ctx.halted:
                return ScopeDecision(
                    False, "halted", ctx.halted_reason or "run halted", halted=True
                )
            if ctx.kill_switch.tripped:
                return ScopeDecision(False, "kill_switch", "kill switch tripped", halted=True)

            now = ctx.clock()
            if now < ctx.authorization.valid_from or now >= ctx.authorization.valid_until:
                return ScopeDecision(
                    False,
                    "authorization_expired",
                    "authorization is not currently valid",
                    halted=True,
                )

            for window in ctx.roe.blackout_windows:
                if window.contains(now):
                    return ScopeDecision(
                        False, "blackout_window", "current time is in a blackout window"
                    )

            shape_decision = await self._check_url_shape(
                ctx, dns_resolver=dns_resolver, method=method, url=url, headers=headers or {}
            )
            if not shape_decision.allowed:
                return shape_decision

            budget_problem = ctx.budgets.peek(
                estimated_tokens_sent=estimated_tokens_sent,
                estimated_tokens_received=estimated_tokens_received,
                estimated_cost_usd=estimated_cost_usd,
            )
            if budget_problem is not None:
                return ScopeDecision(
                    False, f"budget_exceeded:{budget_problem.dimension}", str(budget_problem)
                )

            return ScopeDecision(True, "allow", "request would be in scope")
        except Exception as exc:  # noqa: BLE001 - fail closed for previews too
            return ScopeDecision(False, "internal_error", f"scope explain failed: {exc}")

    async def check_redirect_target(
        self, ctx: RunContext, *, dns_resolver: DnsResolver, location: str
    ) -> ScopeDecision:
        try:
            return await self._check_url_shape(
                ctx, dns_resolver=dns_resolver, method="GET", url=location, headers={}
            )
        except Exception as exc:  # noqa: BLE001 - fail closed here too
            return ScopeDecision(False, "internal_error", f"redirect check failed: {exc}")
