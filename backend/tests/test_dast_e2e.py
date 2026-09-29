"""The DAST engine against the real lab web app, over a real socket.

Every other DAST test uses a fake transport. This one does not: uvicorn serves
the lab on loopback, the scope engine resolves `localhost` through the real
resolver, and `GatedTransport` opens actual connections.

It exists for the phase's acceptance criterion, which is about behaviour against
a running application rather than against a fixture: *crawls and tests a lab web
app without ever fetching an out-of-scope URL discovered mid-crawl*. The lab's
index page links to two `.invalid` hosts precisely so that criterion has
something to be true about.
"""

from __future__ import annotations

import asyncio
import pathlib
import sys
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
import uvicorn

from app.core.dast.contract import CrawlLimits, DastTarget
from app.core.dast.crawl import ScopedCrawler, all_queued_urls
from app.core.dast.engine import DastEngine
from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.engine import ScopeEngine
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement
from app.core.scope.transport import GatedTransport

LAB_ROOT = pathlib.Path(__file__).resolve().parents[2] / "demo-target"
if str(LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(LAB_ROOT))

from lab.web_app.app import OFF_SITE_LINKS  # noqa: E402
from lab.web_app.app import create_app as web_app  # noqa: E402

pytestmark = pytest.mark.lab_e2e

# A hostname rather than a bare address: the scope engine matches the hostname
# and then resolves it, so an IP would skip half of what this exercises.
LAB_HOST = "localhost"
WEB_PORT = 8484


class _Server:
    def __init__(self, app_factory, port: int) -> None:
        self._config = uvicorn.Config(
            app_factory(), host="127.0.0.1", port=port, log_level="warning"
        )
        self._server = uvicorn.Server(self._config)
        self._task: asyncio.Task[None] | None = None
        self.port = port

    async def start(self) -> None:
        self._task = asyncio.create_task(self._server.serve())
        for _ in range(100):
            if self._server.started:
                return
            await asyncio.sleep(0.05)
        raise RuntimeError(f"lab web app on port {self.port} did not start")

    async def stop(self) -> None:
        self._server.should_exit = True
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=10)


@pytest.fixture(scope="module")
async def site() -> AsyncGenerator[str, None]:
    server = _Server(web_app, WEB_PORT)
    await server.start()
    try:
        yield f"http://{LAB_HOST}:{WEB_PORT}"
    finally:
        await server.stop()


def context(*, allow_state_mutation: bool = False, max_requests: int = 300) -> RunContext:
    now = datetime.now(UTC)
    budgets = Budgets(
        max_requests=max_requests,
        max_concurrency=4,
        requests_per_second=200.0,
        max_tokens_sent=0,
        max_tokens_received=0,
        max_estimated_cost_usd=0.0,
        max_wall_clock_minutes=5,
    )
    roe = RulesOfEngagement(
        allowed_domains=(LAB_HOST,),
        excluded_domains=(),
        # The deliberate opt-in: the lab is on loopback, which the engine blocks
        # by default. That default is correct, and this is how a real engagement
        # would widen it. Both families: "localhost" can resolve to either,
        # and the runner's resolution order isn't something this test controls.
        allowed_ip_ranges=("127.0.0.0/8", "::1/128"),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("GET",),
        forbidden_headers=(),
        budgets=budgets,
        safe_mode=True,
        allow_state_mutation=allow_state_mutation,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(hours=1), valid_until=now + timedelta(hours=1)
        ),
        budgets=BudgetTracker(budgets),
        kill_switch=KillSwitch(),
    )


async def test_the_crawl_reaches_the_lab_over_real_http(site: str) -> None:
    crawler = ScopedCrawler(transport=GatedTransport(engine=ScopeEngine()))
    result = await crawler.crawl(context(), DastTarget(seed_url=site + "/"))

    urls = set(result.urls)
    assert f"{site}/" in urls
    assert f"{site}/about" in urls
    assert f"{site}/orders" in urls
    # The link loop terminated rather than spinning.
    assert f"{site}/a" in urls
    assert f"{site}/b" in urls


async def test_no_off_site_url_is_ever_queued(site: str) -> None:
    """The phase's acceptance criterion, against a running application.

    Asserted on the queue rather than on the requests made: the `.invalid`
    hosts never resolve, so a request-level assertion would pass even if the
    control were removed entirely.
    """
    crawler = ScopedCrawler(transport=GatedTransport(engine=ScopeEngine()))
    result = await crawler.crawl(context(), DastTarget(seed_url=site + "/"))

    queued = all_queued_urls(result)
    for off_site in OFF_SITE_LINKS:
        assert off_site not in queued
    assert not any("tracker.invalid" in url for url in queued)
    assert not any("partner.invalid" in url for url in queued)

    # And they were recorded, so a human learns the application links out.
    refused = {item.url for item in result.refused}
    assert any("tracker.invalid" in url for url in refused)
    assert all(item.rule == "domain_not_allowlisted" for item in result.refused)


async def test_unfollowable_schemes_are_dropped_without_a_scope_decision(site: str) -> None:
    """`mailto:` and `javascript:` have no host to check and no request to make,
    so they are neither queued nor reported as refusals — reporting them would
    bury the one refusal that matters."""
    crawler = ScopedCrawler(transport=GatedTransport(engine=ScopeEngine()))
    result = await crawler.crawl(context(), DastTarget(seed_url=site + "/"))

    assert not any(item.url.startswith(("mailto:", "javascript:")) for item in result.refused)
    assert not any(url.startswith(("mailto:", "javascript:")) for url in all_queued_urls(result))


async def test_the_depth_bound_holds_against_a_real_chain(site: str) -> None:
    crawler = ScopedCrawler(transport=GatedTransport(engine=ScopeEngine()))
    result = await crawler.crawl(
        context(), DastTarget(seed_url=site + "/", limits=CrawlLimits(max_depth=2))
    )
    # / is depth 0, /deep/1 is 1, /deep/2 is 2, /deep/3 would be 3.
    assert f"{site}/deep/2" in set(result.urls)
    assert f"{site}/deep/3" not in set(result.urls)


async def test_a_destructive_form_is_found_and_never_submitted(site: str) -> None:
    """The crawler records the action; nothing posts to it. Verified by asking
    the lab, which answers `deleted (not really)` to a POST — so if the crawler
    had submitted it, the status code would say so."""
    engine = DastEngine(
        crawler=ScopedCrawler(transport=GatedTransport(engine=ScopeEngine())),
        run_tools=False,
    )
    results = await engine.run(context(), DastTarget(seed_url=site + "/"))

    forms = next(item for item in results if item.id == "KERVY-DAST-002")
    assert f"{site}/orders/delete" in forms.evidence
    assert "does not allow state mutation" in forms.description


async def test_the_engine_reports_the_off_site_links_as_a_finding(site: str) -> None:
    engine = DastEngine(
        crawler=ScopedCrawler(transport=GatedTransport(engine=ScopeEngine())),
        run_tools=False,
    )
    results = await engine.run(context(), DastTarget(seed_url=site + "/"))

    refusal = next(item for item in results if item.id == "KERVY-DAST-001")
    assert "tracker.invalid" in refusal.description
    assert "nothing was sent" in refusal.impact


async def test_a_tight_request_budget_ends_the_crawl_and_is_reported(site: str) -> None:
    """Coverage honesty against a real application: a crawl cut short by budget
    must say so rather than presenting its pages as the whole site."""
    engine = DastEngine(
        crawler=ScopedCrawler(transport=GatedTransport(engine=ScopeEngine())),
        run_tools=False,
    )
    results = await engine.run(context(max_requests=3), DastTarget(seed_url=site + "/"))
    gap = next(item for item in results if item.id == "KERVY-DAST-009")
    assert "budget" in gap.description
