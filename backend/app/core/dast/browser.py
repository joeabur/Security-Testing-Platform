"""Browser-based DAST crawl via Playwright — the gap `docs/dast.md` and
`docs/competitive-gap-analysis.md` both named as the largest one in this
pillar: "No JS execution, no SPA crawling, no authenticated browser
sessions."

**Why this waited for the egress gateway.** A real browser engine opens its
own sockets exactly like Nuclei and ZAP do, and `docs/competitive-gap-
analysis.md` is explicit that adding one *before* `egress_proxy.py` existed
would have repeated the same socket-bypass mistake those two tools already
made. So `BrowserCrawler` is never run standalone: `engine.py` only
constructs it inside an `EgressGateway` context, and every navigation is
given that gateway's `proxy_url` — Chromium is launched with
`proxy={"server": proxy_url}`, which routes *all* of its traffic, including
same-origin XHR/fetch calls a script makes after the initial navigation,
through the same per-connection, freshly-DNS-resolved scope check Nuclei and
ZAP already get. A redirect or client-side navigation to a different host
gets its own fresh check at the gateway; it cannot pivot to an unauthorized
host by staying inside one page's JavaScript.

**What this closes, concretely.** `crawl.py`'s regex-based link extraction
only sees what is already present in the raw HTML response — a single-page
application that builds its navigation with JavaScript after load is
invisible to it. `BrowserCrawler` reads the *rendered* DOM after Chromium has
run the page's scripts, so links a client-side router injects are found the
same way a real visitor's browser would find them.

**Stated limitation: "authenticated browser session" means exactly one
thing here.** `DastTarget.storage_state` lets an operator hand this crawler
a Playwright storage state (cookies/localStorage) already captured from a
session they authenticated themselves, and every navigation carries it. This
module does **not** drive a login form on the target's behalf: typing a
password into an arbitrary page this same run is simultaneously attacking is
a materially different trust decision than crawling with a session the
operator already established, and is not attempted here.

**Everything else from `crawl.py` still applies and is reused, not
reinvented**: the same pre-queue scope check before a URL becomes work, the
same `CrawlLimits` bounds, the same refusal-is-a-finding behaviour, and the
same "forms are recorded, never submitted" rule — this module returns the
identical `CrawlResult` shape, so `engine.crawl_findings()` reports a
browser-driven crawl exactly as it reports the regex-driven one.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from typing import Any

from app.core.dast.contract import (
    CrawledPage,
    CrawlLimits,
    CrawlOutcome,
    CrawlResult,
    DastTarget,
    RefusedUrl,
)
from app.core.dast.crawl import normalize
from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver, SystemDnsResolver
from app.core.scope.engine import ScopeEngine

#: Generous but bounded: a page that never fires `load` must not hang the
#: crawl indefinitely.
NAV_TIMEOUT_MS = 15_000
#: A short settle window after `load` so a script that injects navigation
#: links on a timer has a chance to run — bounded rather than "wait for
#: network idle", which an app with a polling request would never reach.
SETTLE_MS = 500

_LINK_SELECTOR = "a[href], area[href]"
_FORM_SELECTOR = "form"


class PlaywrightUnavailable(RuntimeError):
    """The `playwright` package, or its browser binary, is not available.

    Caught by the caller and turned into `tool_unavailable(...)` — the same
    graceful-degradation rule every optional-tool adapter in this codebase
    follows (`docs/dast.md`, `app/core/appsec/contract.py`).
    """


async def _launch(
    proxy_url: str, *, launch_kwargs: Mapping[str, Any] | None = None
) -> tuple[Any, Any]:
    """Start Chromium pointed at `proxy_url`. Imports `playwright` lazily so
    this module — and everything that imports it — loads fine without the
    `browser` extra installed; only calling this function requires it.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise PlaywrightUnavailable(
            "the playwright package is not installed "
            "(pip install -e '.[browser]', then `playwright install chromium`)"
        ) from exc

    playwright = await async_playwright().start()
    try:
        browser = await playwright.chromium.launch(
            headless=True,
            proxy={"server": proxy_url},
            **dict(launch_kwargs or {}),
        )
    except Exception as exc:
        await playwright.stop()
        raise PlaywrightUnavailable(f"chromium failed to launch: {exc}") from exc
    return playwright, browser


class BrowserCrawler:
    """Same contract as `crawl.ScopedCrawler.crawl`: a `DastTarget` in, a
    `CrawlResult` out — driven by a real, JS-executing browser instead of a
    raw HTTP GET and a regex.
    """

    def __init__(
        self,
        *,
        engine: ScopeEngine | None = None,
        dns_resolver: DnsResolver | None = None,
        launch_kwargs: Mapping[str, Any] | None = None,
    ) -> None:
        self._engine = engine or ScopeEngine()
        # Passed explicitly for the same reason `ScopedCrawler` does: the
        # pre-queue check and the gateway's own send-time check must resolve
        # names consistently with each other, and reaching into either one's
        # internals to arrange that would break the first time it changed.
        self._dns_resolver = dns_resolver or SystemDnsResolver()
        # Test-only seam: lets a test point `chromium.launch` at this
        # sandbox's own pre-installed binary when the installed `playwright`
        # package's bundled-revision lookup does not match it. Empty by
        # default in every shipped code path — production relies entirely on
        # Playwright's own standard resolution (`playwright install
        # chromium`), never a hardcoded path.
        self._launch_kwargs = launch_kwargs or {}

    async def _permitted(self, ctx: RunContext, url: str) -> tuple[bool, str, str]:
        decision = await self._engine.explain(
            ctx, dns_resolver=self._dns_resolver, method="GET", url=url
        )
        return decision.allowed, decision.rule, decision.reason

    async def crawl(
        self,
        ctx: RunContext,
        target: DastTarget,
        *,
        proxy_url: str,
    ) -> CrawlResult:
        limits: CrawlLimits = target.limits
        result = CrawlResult(seed=target.seed_url)

        queue: deque[tuple[str, int]] = deque()
        queued: set[str] = set()

        async def enqueue(raw: str, depth: int, *, discovered_on: str) -> None:
            candidate = normalize(discovered_on or raw, raw)
            if candidate is None or candidate in queued:
                return
            if depth > limits.max_depth:
                return
            allowed, rule, reason = await self._permitted(ctx, candidate)
            deferred = rule.startswith("budget_exceeded") or rule in ("kill_switch", "halted")
            if not allowed and not deferred:
                result.refused.append(
                    RefusedUrl(url=candidate, rule=rule, reason=reason, discovered_on=discovered_on)
                )
                return
            queued.add(candidate)
            queue.append((candidate, depth))

        for seed in (target.seed_url, *target.extra_seeds):
            await enqueue(seed, 0, discovered_on="")

        if ctx.halted or ctx.kill_switch.tripped:
            result.outcome = CrawlOutcome.HALTED
            result.unvisited = [url for url, _ in queue]
            return result

        if not queue:
            result.unvisited = []
            return result

        playwright, browser = await _launch(proxy_url, launch_kwargs=self._launch_kwargs)
        try:
            context = await browser.new_context(
                storage_state=dict(target.storage_state) if target.storage_state else None,
                # The target is under test, not necessarily holding a
                # certificate this run's own trust store would accept
                # (a lab fixture's self-signed cert, for one) — the same
                # reasoning `GatedTransport`'s own test fixtures use.
                ignore_https_errors=True,
            )
            page = await context.new_page()

            while queue:
                if ctx.halted or ctx.kill_switch.tripped:
                    result.outcome = CrawlOutcome.HALTED
                    break
                if len(result.pages) >= limits.max_pages:
                    result.outcome = CrawlOutcome.PAGE_LIMIT
                    break

                url, depth = queue.popleft()
                try:
                    response = await page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="load")
                    await page.wait_for_timeout(SETTLE_MS)
                except Exception:  # noqa: BLE001 - one unreachable page is not a failed crawl
                    continue
                if response is None:
                    continue

                links = await _extract_links(page, limit=limits.max_links_per_page)
                forms = await _extract_forms(page, limit=limits.max_links_per_page)
                try:
                    title = (await page.title())[:200]
                except Exception:  # noqa: BLE001 - a title read failing is not a crawl failure
                    title = ""

                result.pages.append(
                    CrawledPage(
                        url=page.url,
                        status_code=response.status,
                        content_type=response.headers.get("content-type", ""),
                        depth=depth,
                        links=tuple(links),
                        forms=tuple(forms),
                        title=title,
                    )
                )

                for link in links:
                    await enqueue(link, depth + 1, discovered_on=url)
        finally:
            await browser.close()
            await playwright.stop()

        result.unvisited = [url for url, _ in queue]
        return result


async def _extract_links(page: Any, *, limit: int) -> list[str]:
    """In-DOM links after JavaScript has run — this is the whole point.

    `.href` on an anchor/area element is the browser's own already-resolved
    absolute URL, not the raw attribute, so a relative or script-written
    `href` is handled the same as a hardcoded absolute one. Still passed
    through `normalize()` so the extension-skip, fragment-drop and
    userinfo-rejection rules match the regex crawler's exactly.
    """
    try:
        hrefs: list[str] = await page.eval_on_selector_all(
            _LINK_SELECTOR, "(elements) => elements.map((e) => e.href)"
        )
    except Exception:  # noqa: BLE001 - a page that errors on evaluation yields no links
        return []

    found: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        try:
            candidate = normalize(page.url, str(href))
        except ValueError:
            continue
        if candidate and candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
        if len(found) >= limit:
            break
    return found


async def _extract_forms(page: Any, *, limit: int) -> list[str]:
    try:
        actions: list[str] = await page.eval_on_selector_all(
            _FORM_SELECTOR, "(elements) => elements.map((e) => e.action)"
        )
    except Exception:  # noqa: BLE001 - see _extract_links
        return []

    found: list[str] = []
    seen: set[str] = set()
    for action in actions:
        try:
            candidate = normalize(page.url, str(action)) or page.url
        except ValueError:
            continue
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
        if len(found) >= limit:
            break
    return found
