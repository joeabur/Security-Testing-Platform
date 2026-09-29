"""The only place in this codebase allowed to construct an `httpx` client.

`tests/security/test_scope_controls.py::test_no_ungated_httpx_client_construction_outside_transport`
enforces that in CI: any `httpx.Client(`/`httpx.AsyncClient(` found anywhere
else in `app/` fails the build. Every outbound request — from the API, a
Celery worker, a probe, or the CLI — must go through `GatedTransport.send()`.
"""

import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver
from app.core.scope.engine import ScopeEngine
from app.core.scope.models import ScopeDecision

DecisionSink = Callable[[ScopeDecision], Awaitable[None]]


class ScopeBlockedError(Exception):
    """Raised when a request is denied. Callers must not treat this as a
    retryable transport error — it means the scope engine refused to send."""

    def __init__(self, decision: ScopeDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


@dataclass(frozen=True)
class Observation:
    method: str
    url: str
    status_code: int
    headers: dict[str, str]
    elapsed_ms: float
    blocked_redirect_location: str | None = None
    blocked_redirect_decision: ScopeDecision | None = None
    body: bytes = field(default=b"", repr=False)


class GatedTransport:
    """Wraps `httpx` so that every request is checked by the `ScopeEngine`
    first, redirects are never auto-followed (docs/BUILD_SPEC.md §6.2), and
    concurrency stays within the run's budget.

    Evidence capture and redaction (the full `Observation` -> sealed
    evidence bundle pipeline from §13) land in Phase 7; this Phase-2 version
    returns the raw response so the gate itself can be tested end to end.
    """

    def __init__(
        self, engine: ScopeEngine | None = None, dns_resolver: DnsResolver | None = None
    ) -> None:
        from app.core.scope.dns import SystemDnsResolver

        self._engine = engine or ScopeEngine()
        self._dns_resolver = dns_resolver or SystemDnsResolver()

    async def send(
        self,
        ctx: RunContext,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
        timeout_seconds: float = 30.0,
        on_decision: DecisionSink | None = None,
        estimated_tokens_sent: int = 0,
        estimated_tokens_received: int = 0,
        estimated_cost_usd: float = 0.0,
    ) -> Observation:
        decision = await self._engine.check(
            ctx,
            dns_resolver=self._dns_resolver,
            method=method,
            url=url,
            headers=headers,
            estimated_tokens_sent=estimated_tokens_sent,
            estimated_tokens_received=estimated_tokens_received,
            estimated_cost_usd=estimated_cost_usd,
        )
        if on_decision is not None:
            await on_decision(decision)
        if not decision.allowed:
            raise ScopeBlockedError(decision)

        async with ctx.budgets.acquire_concurrency():
            start = time.monotonic()
            # This *is* the choke point the rule below exists to protect.
            # Every outbound request reaches the network here and nowhere
            # else, and `tests/security/test_scope_controls.py` greps `app/`
            # to keep it that way. Suppressed at the line rather than by
            # excluding the file, so the exception stays visible.
            # nosemgrep: kervy.ungated-http-client
            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
                response = await client.request(method, url, headers=headers, content=content)
            elapsed_ms = (time.monotonic() - start) * 1000

        if 300 <= response.status_code < 400 and "location" in response.headers:
            location = urljoin(url, response.headers["location"])
            redirect_decision = await self._engine.check_redirect_target(
                ctx, dns_resolver=self._dns_resolver, location=location
            )
            if on_decision is not None:
                await on_decision(redirect_decision)
            return Observation(
                method=method,
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                elapsed_ms=elapsed_ms,
                blocked_redirect_location=location,
                blocked_redirect_decision=redirect_decision,
            )

        return Observation(
            method=method,
            url=url,
            status_code=response.status_code,
            headers=dict(response.headers),
            elapsed_ms=elapsed_ms,
            body=response.content,
        )
