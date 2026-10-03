"""Browser-based DAST crawl (`app/core/dast/browser.py`).

Two tiers, like `test_dast_egress_proxy.py` and `test_dast.py` together:

* A real end-to-end test against a real, pre-installed headless Chromium and
  a real local HTTP server — the actual claim under test is "a link injected
  by client-side JavaScript after load is found", which only a real browser
  can prove. Faking the browser here would be exactly the kind of thin,
  untested wrapper this codebase's own rules reject.
* Fake-double wiring tests for `DastEngine`'s dispatch (`use_browser`,
  `PlaywrightUnavailable` degrading gracefully) and for `storage_state`
  being forwarded, where a real browser adds nothing a double does not
  already prove.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import NoReturn
from urllib.parse import urlsplit

import pytest

from app.core.dast.browser import BrowserCrawler, PlaywrightUnavailable, _extract_links
from app.core.dast.contract import CrawlOutcome, CrawlResult, DastTarget
from app.core.dast.egress_proxy import EgressGateway
from app.core.dast.engine import BROWSER_META, DastEngine
from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

HOST = "127.0.0.1"

# A pre-installed Chromium exists in this sandbox at a revision the pinned
# `playwright` package's own bundled-revision lookup does not match (the
# lookup expects whatever revision ships with that exact pip version).
# Real deployments run `playwright install chromium`, which always fetches a
# matching revision, so production code never needs this — it is a
# test-only seam (`BrowserCrawler(launch_kwargs=...)`), not a hardcoded path
# in anything shipped.
_SANDBOX_CHROMIUM = "/opt/pw-browsers/chromium"


def _page(body: bytes) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


# The seed links only to /static in its raw HTML. A script that runs after
# load injects a second link, to /spa-only, directly into the DOM — nothing
# a regex over the raw response could ever see. Built with `setAttribute`
# and string concatenation specifically so the raw script source never
# contains the byte sequence `href=`/`href =` next to a quoted path — that
# would make `crawl.py`'s own link regex match the *script text* and defeat
# the negative control below for an uninteresting reason (the regex is
# scanning for an HTML attribute, not evaluating JavaScript).
_INDEX = _page(
    b"<html><body>"
    b'<a href="/static">static</a>'
    b"<script>"
    b"var a = document.createElement('a');"
    b"a.setAttribute('href', '/spa' + '-only');"
    b"a.textContent = 'spa';"
    b"document.body.appendChild(a);"
    b"</script>"
    b"</body></html>"
)
_STATIC = _page(b"<html><body>static page, no further links</body></html>")
_SPA_ONLY = _page(b"<html><body>reached only via client-side JS</body></html>")

_ROUTES = {"/": _INDEX, "/static": _STATIC, "/spa-only": _SPA_ONLY}


async def _serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    request_line = await reader.readline()
    # Drain headers without needing to parse them — every request here is a
    # bodyless GET.
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b""):
            break
    target = request_line.decode("latin-1").split(" ", 2)[1] if request_line else "/"
    # The browser's own proxy traffic (`BrowserCrawler` routes every request
    # through `EgressGateway`) arrives in absolute-URI form, per the HTTP
    # proxying spec — `GET http://host:port/path HTTP/1.1`, not `GET /path
    # HTTP/1.1`. Reduced to a path either way, so this fixture serves both
    # proxied and direct requests (the latter used by the regex-crawler
    # negative control, which fetches directly).
    path = urlsplit(target).path or "/" if "://" in target else target
    writer.write(_ROUTES.get(path, _page(b"not found")))
    await writer.drain()
    writer.close()


@pytest.fixture
async def lab_server() -> AsyncGenerator[str, None]:
    server = await asyncio.start_server(_serve, host=HOST, port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"http://{HOST}:{port}"
    finally:
        server.close()
        await server.wait_closed()


def _context(*, allowed_domains: tuple[str, ...] = (HOST,)) -> RunContext:
    now = datetime.now(UTC)
    budgets = Budgets(
        max_requests=300,
        max_concurrency=4,
        requests_per_second=200.0,
        max_tokens_sent=0,
        max_tokens_received=0,
        max_estimated_cost_usd=0.0,
        max_wall_clock_minutes=5,
    )
    roe = RulesOfEngagement(
        allowed_domains=allowed_domains,
        excluded_domains=(),
        # Loopback is blocked by default; this is the deliberate opt-in a
        # real engagement against a lab target would also need.
        allowed_ip_ranges=("127.0.0.0/8",),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("GET",),
        forbidden_headers=(),
        budgets=budgets,
        safe_mode=True,
    )
    authorization = ResolvedAuthorization(
        valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=1)
    )
    return RunContext(
        roe=roe,
        authorization=authorization,
        budgets=BudgetTracker(budgets),
        kill_switch=KillSwitch(),
    )


# --- real Chromium, real HTTP server -----------------------------------------


async def test_a_script_injected_link_is_found_by_the_browser_crawl(lab_server: str) -> None:
    ctx = _context()
    async with EgressGateway(ctx) as gateway:
        crawler = BrowserCrawler(launch_kwargs={"executable_path": _SANDBOX_CHROMIUM})
        result = await crawler.crawl(
            ctx, DastTarget(seed_url=f"{lab_server}/"), proxy_url=gateway.proxy_url
        )

    assert result.outcome is CrawlOutcome.EXHAUSTED
    urls = set(result.urls)
    assert f"{lab_server}/static" in urls
    # The claim this whole module exists to prove: a link that only appears
    # after JavaScript runs is still found.
    assert f"{lab_server}/spa-only" in urls


async def test_the_same_page_defeats_the_regex_crawler(lab_server: str) -> None:
    """Negative control: proves the gap this module closes is real, not
    merely asserted. The raw response for `/` never contains the literal
    string `/spa-only` — it is written into the DOM by a script — so the
    regex extractor genuinely cannot see it."""
    import httpx

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{lab_server}/")
    from app.core.dast.crawl import extract_links

    links = extract_links(f"{lab_server}/", response.content, limit=100)
    assert f"{lab_server}/spa-only" not in links
    assert f"{lab_server}/static" in links


async def test_a_js_discovered_link_outside_scope_is_refused_before_navigation(
    lab_server: str,
) -> None:
    """Same pre-queue guarantee `crawl.py` has: a link only JavaScript
    revealed is checked before it becomes work, exactly like one found in
    raw HTML."""
    out_of_scope = _page(
        b"<html><body><script>"
        b"var a = document.createElement('a');"
        b"a.href = 'http://tracker.invalid/px';"
        b"document.body.appendChild(a);"
        b"</script></body></html>"
    )
    _ROUTES["/"] = out_of_scope
    try:
        ctx = _context()
        async with EgressGateway(ctx) as gateway:
            crawler = BrowserCrawler(launch_kwargs={"executable_path": _SANDBOX_CHROMIUM})
            result = await crawler.crawl(
                ctx, DastTarget(seed_url=f"{lab_server}/"), proxy_url=gateway.proxy_url
            )
    finally:
        _ROUTES["/"] = _INDEX

    assert "tracker.invalid" not in " ".join(result.urls)
    refused_urls = [item.url for item in result.refused]
    assert any("tracker.invalid" in url for url in refused_urls)


async def test_extract_links_normalizes_and_deduplicates_like_the_regex_crawler() -> None:
    """A focused check on the DOM-extraction helper itself, independent of a
    live navigation: `.href` on an anchor is already absolute, and
    `normalize()` must still de-duplicate and drop fragments the same way it
    does for the regex crawler."""

    class _FakeElementHandle:
        def __init__(self, hrefs: list[str]) -> None:
            self._hrefs = hrefs

        async def eval_on_selector_all(self, selector: str, script: str) -> list[str]:
            assert selector == "a[href], area[href]"
            return self._hrefs

    page = _FakeElementHandle(
        [
            "https://app.example.test/a",
            "https://app.example.test/a#section",  # same page, different fragment
            "https://app.example.test/a",  # exact duplicate
            "https://app.example.test/b.png",  # skipped extension
        ]
    )
    page.url = "https://app.example.test/"  # type: ignore[attr-defined]

    links = await _extract_links(page, limit=10)
    assert links == ["https://app.example.test/a"]


# --- wiring: PlaywrightUnavailable, use_browser dispatch, storage_state -----


class _FakeBrowserCrawlerUnavailable:
    async def crawl(
        self, ctx: RunContext, target: DastTarget, *, proxy_url: str
    ) -> NoReturn:
        raise PlaywrightUnavailable("playwright is not installed in this test double")


async def test_the_engine_reports_not_tested_when_playwright_is_unavailable() -> None:
    engine = DastEngine(
        browser_crawler=_FakeBrowserCrawlerUnavailable(),  # type: ignore[arg-type]
        run_tools=True,
    )
    target = DastTarget(seed_url="http://127.0.0.1:9/", use_browser=True)
    results = await engine.run(_context(), target)

    ids = [item.id for item in results]
    assert ids.count("KERVY-APPSEC-000") == 3
    not_tested_title = f"Not tested: {BROWSER_META.name}"
    browser_note = next(item for item in results if item.title == not_tested_title)
    assert "playwright is not installed" in browser_note.evidence


class _RecordingBrowserCrawler:
    """Records what it was called with, without touching a real browser —
    for asserting the engine's own dispatch and pass-through, which a real
    Chromium run would not make any easier to check."""

    def __init__(self) -> None:
        self.calls: list[tuple[DastTarget, str]] = []

    async def crawl(
        self, ctx: RunContext, target: DastTarget, *, proxy_url: str
    ) -> CrawlResult:
        self.calls.append((target, proxy_url))
        return CrawlResult(seed=target.seed_url)


async def test_use_browser_false_never_touches_the_browser_crawler() -> None:
    recorder = _RecordingBrowserCrawler()
    engine = DastEngine(browser_crawler=recorder, run_tools=False)  # type: ignore[arg-type]
    await engine.run(_context(), DastTarget(seed_url="http://127.0.0.1:9/", use_browser=False))
    assert recorder.calls == []


async def test_use_browser_true_calls_the_browser_crawler_with_the_gateways_proxy() -> None:
    recorder = _RecordingBrowserCrawler()
    engine = DastEngine(browser_crawler=recorder, run_tools=False)  # type: ignore[arg-type]
    target = DastTarget(seed_url="http://127.0.0.1:9/", use_browser=True)
    await engine.run(_context(), target)

    assert len(recorder.calls) == 1
    called_target, proxy_url = recorder.calls[0]
    assert called_target is target
    assert proxy_url.startswith("http://127.0.0.1:")


async def test_storage_state_is_forwarded_into_the_browser_context() -> None:
    """The whole of this module's "authenticated session" claim: whatever
    the operator supplies is handed to Playwright's own `new_context`
    unchanged."""

    captured: dict[str, object] = {}

    class _FakePage:
        url = "http://127.0.0.1:9/"

        async def goto(self, *args: object, **kwargs: object) -> None:
            return None

    class _FakeContext:
        async def new_page(self) -> _FakePage:
            return _FakePage()

    class _FakeBrowser:
        async def new_context(self, **kwargs: object) -> _FakeContext:
            captured.update(kwargs)
            return _FakeContext()

        async def close(self) -> None:
            return None

    class _FakePlaywright:
        async def stop(self) -> None:
            return None

    async def fake_launch(
        proxy_url: str, *, launch_kwargs: object = None
    ) -> tuple[_FakePlaywright, _FakeBrowser]:
        return _FakePlaywright(), _FakeBrowser()

    import app.core.dast.browser as browser_module

    original_launch = browser_module._launch
    browser_module._launch = fake_launch
    try:
        crawler = BrowserCrawler()
        storage = {"cookies": [{"name": "session", "value": "abc"}]}
        target = DastTarget(
            seed_url="http://127.0.0.1:9/", storage_state=storage, use_browser=True
        )
        # `goto` returns `None` above, so the loop records no page and exits
        # immediately after the one navigation attempt — enough to exercise
        # `new_context` without needing a reachable target.
        await crawler.crawl(_context(), target, proxy_url="http://127.0.0.1:1")
    finally:
        browser_module._launch = original_launch

    assert captured.get("storage_state") == storage
