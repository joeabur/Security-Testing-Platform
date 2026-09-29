"""The DAST engine (docs/BUILD_SPEC.md §26 Phase 15, docs/dast.md).

The acceptance criterion is a negative: *"crawls and tests a lab web app without
ever fetching an out-of-scope URL discovered mid-crawl"*. The first test below
asserts something deliberately stronger — that such a URL is never even
**queued** — because an assertion about requests made would pass equally if the
check happened late, and the point of the design is that it happens early. See
`app/core/dast/crawl.py` for why.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.core.dast.contract import (
    CrawlLimits,
    CrawlOutcome,
    DastTarget,
)
from app.core.dast.crawl import (
    ScopedCrawler,
    all_queued_urls,
    extract_forms,
    extract_links,
    extract_title,
    normalize,
    refused_hosts,
    state_changing_forms,
)
from app.core.probes.models import Confidence
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import Observation
from tests.security.conftest import make_budgets, make_context, make_roe

HOST = "app.example.test"
SEED = f"https://{HOST}/"


class Resolver:
    """Resolves every name to one public address, so the IP rules pass and what
    is under test is the rest of the decision."""

    def __init__(self, address: str = "93.184.216.34") -> None:
        self._address = address

    async def resolve(self, hostname: str) -> list[object]:
        return [ipaddress.ip_address(self._address)]


class PageTransport:
    """Serves a fixed site map and records every URL actually requested."""

    def __init__(self, pages: dict[str, bytes]) -> None:
        self._pages = pages
        self.requested: list[str] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        url = str(kwargs.get("url"))
        self.requested.append(url)
        body = self._pages.get(url, b"<html><body>missing</body></html>")
        return Observation(
            method="GET",
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            elapsed_ms=1.0,
            body=body,
        )


def crawler(transport: PageTransport) -> ScopedCrawler:
    return ScopedCrawler(
        transport=transport,  # type: ignore[arg-type]
        engine=ScopeEngine(),
        dns_resolver=Resolver(),
    )


def context(**roe_overrides: object):
    defaults: dict[str, object] = {
        "allowed_domains": (HOST,),
        "allowed_methods": ("GET",),
        "budgets": make_budgets(max_requests=500),
    }
    defaults.update(roe_overrides)
    return make_context(roe=make_roe(**defaults))


# --- the acceptance criterion ------------------------------------------------


async def test_an_out_of_scope_url_discovered_mid_crawl_is_never_queued() -> None:
    """The phase's acceptance test, asserted on the queue rather than on the
    requests made — a request-level assertion passes even when the check happens
    too late to stop the URL becoming work."""
    transport = PageTransport(
        {
            SEED: (
                b"<html><body>"
                b'<a href="/about">about</a>'
                b'<a href="https://attacker.example/collect">tracker</a>'
                b'<a href="//evil.test/x">protocol relative</a>'
                b"</body></html>"
            ),
            f"https://{HOST}/about": b"<html><body>about</body></html>",
        }
    )
    result = await crawler(transport).crawl(context(), DastTarget(seed_url=SEED))

    queued = all_queued_urls(result)
    assert f"https://{HOST}/" in queued
    assert f"https://{HOST}/about" in queued
    # Never queued, therefore never requested, therefore never reachable by
    # anything that later iterates the crawl's own state.
    assert not any("attacker.example" in url for url in queued)
    assert not any("evil.test" in url for url in queued)
    assert not any("attacker.example" in url for url in transport.requested)
    assert not any("evil.test" in url for url in transport.requested)


async def test_a_refused_url_is_recorded_with_the_engine_s_own_rule() -> None:
    """Refusals are reported, not dropped: an application linking somewhere the
    engagement does not cover is worth a human's attention."""
    transport = PageTransport({SEED: b'<html><a href="https://attacker.example/c">x</a></html>'})
    result = await crawler(transport).crawl(context(), DastTarget(seed_url=SEED))

    assert len(result.refused) == 1
    refusal = result.refused[0]
    assert refusal.url == "https://attacker.example/c"
    # The engine's own rule name, so the record cannot drift from the decision.
    assert refusal.rule == "domain_not_allowlisted"
    assert refusal.discovered_on == SEED
    assert refused_hosts(result) == ("attacker.example",)


async def test_an_excluded_path_is_refused_even_on_an_allowed_host() -> None:
    transport = PageTransport(
        {
            SEED: b'<html><a href="/admin/users">admin</a><a href="/ok">ok</a></html>',
            f"https://{HOST}/ok": b"<html>ok</html>",
        }
    )
    result = await crawler(transport).crawl(
        context(excluded_paths=("/admin/*",)), DastTarget(seed_url=SEED)
    )
    queued = all_queued_urls(result)
    assert f"https://{HOST}/ok" in queued
    assert not any("/admin/" in url for url in queued)
    assert result.refused[0].rule == "excluded_path"


async def test_a_host_resolving_to_a_blocked_address_is_refused_before_queueing() -> None:
    """The pre-queue check uses the same engine, so the IP rules apply there
    too — a link to an allowlisted host that resolves internally never becomes
    work."""
    transport = PageTransport({SEED: b"<html>seed</html>"})
    crawl = ScopedCrawler(
        transport=transport,  # type: ignore[arg-type]
        engine=ScopeEngine(),
        dns_resolver=Resolver("169.254.169.254"),
    )
    result = await crawl.crawl(context(), DastTarget(seed_url=SEED))

    assert result.pages == []
    assert result.refused
    assert result.refused[0].rule == "blocked_ip"
    assert transport.requested == []


# --- bounds -------------------------------------------------------------------


async def test_the_page_limit_stops_the_crawl_and_is_reported() -> None:
    """A crawl that stopped at a bound has said nothing about the pages it did
    not reach, so the outcome and the unvisited list are part of the result."""
    pages = {
        f"https://{HOST}/p{index}": (f'<html><a href="/p{index + 1}">next</a></html>'.encode())
        for index in range(50)
    }
    pages[SEED] = b'<html><a href="/p0">start</a></html>'
    transport = PageTransport(pages)

    result = await crawler(transport).crawl(
        context(), DastTarget(seed_url=SEED, limits=CrawlLimits(max_pages=5))
    )
    assert result.outcome is CrawlOutcome.PAGE_LIMIT
    assert len(result.pages) == 5
    assert result.unvisited
    assert not result.complete()


async def test_the_depth_limit_bounds_a_chain_of_links() -> None:
    pages = {
        f"https://{HOST}/d{index}": (f'<html><a href="/d{index + 1}">next</a></html>'.encode())
        for index in range(20)
    }
    pages[SEED] = b'<html><a href="/d0">start</a></html>'
    transport = PageTransport(pages)

    result = await crawler(transport).crawl(
        context(), DastTarget(seed_url=SEED, limits=CrawlLimits(max_depth=2))
    )
    # seed(0) -> /d0(1) -> /d1(2); /d2 would be depth 3.
    assert sorted(result.urls) == sorted([SEED, f"https://{HOST}/d0", f"https://{HOST}/d1"])


async def test_links_per_page_are_bounded() -> None:
    body = (
        b"<html>"
        + b"".join(f'<a href="/l{index}">x</a>'.encode() for index in range(500))
        + b"</html>"
    )
    transport = PageTransport({SEED: body})
    result = await crawler(transport).crawl(
        context(), DastTarget(seed_url=SEED, limits=CrawlLimits(max_links_per_page=7))
    )
    assert len(result.pages[0].links) == 7


async def test_running_out_of_budget_ends_the_crawl_cleanly() -> None:
    """Budget exhaustion is a normal ending with a named outcome, not a failure."""
    pages = {
        f"https://{HOST}/b{index}": (f'<html><a href="/b{index + 1}">next</a></html>'.encode())
        for index in range(40)
    }
    pages[SEED] = b'<html><a href="/b0">start</a></html>'

    class BudgetedTransport(PageTransport):
        """Reserves budget the way the real transport does, so exhaustion is
        reached through the same accounting."""

        async def send(self, ctx, **kwargs):  # type: ignore[no-untyped-def]
            decision = await ScopeEngine().check(
                ctx, dns_resolver=Resolver(), method="GET", url=str(kwargs["url"])
            )
            if not decision.allowed:
                from app.core.scope.transport import ScopeBlockedError

                raise ScopeBlockedError(decision)
            return await super().send(ctx, **kwargs)

    budgeted = BudgetedTransport(pages)
    crawl = ScopedCrawler(
        transport=budgeted,  # type: ignore[arg-type]
        engine=ScopeEngine(),
        dns_resolver=Resolver(),
    )
    result = await crawl.crawl(
        make_context(
            roe=make_roe(
                allowed_domains=(HOST,),
                allowed_methods=("GET",),
                budgets=make_budgets(max_requests=4),
            )
        ),
        DastTarget(seed_url=SEED),
    )
    assert result.outcome is CrawlOutcome.BUDGET_EXHAUSTED
    # The in-scope pages it did not reach are named, not filed as refusals:
    # budget says "not now", scope says "not ever", and only the second is a
    # refusal about the engagement's boundary.
    assert result.unvisited
    assert result.refused == []
    assert not result.complete()
    # The in-scope pages it did not reach are named, not filed as refusals:
    # budget says "not now", scope says "not ever", and only the second is a
    # refusal.
    assert result.unvisited
    assert result.refused == []
    assert not result.complete()


async def test_a_tripped_kill_switch_halts_the_crawl() -> None:
    pages = {
        SEED: b'<html><a href="/a">a</a></html>',
        f"https://{HOST}/a": b"<html>a</html>",
    }
    transport = PageTransport(pages)
    ctx = context()
    ctx.kill_switch.trip()
    result = await crawler(transport).crawl(ctx, DastTarget(seed_url=SEED))
    assert result.outcome is CrawlOutcome.HALTED
    assert transport.requested == []
    # Not filed as a scope refusal: stopping is not a statement about scope.
    assert result.refused == []


# --- normalization ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/a", f"https://{HOST}/a"),
        ("/a#fragment", f"https://{HOST}/a"),
        ("a", f"https://{HOST}/a"),
        ("?q=1", f"https://{HOST}/?q=1"),
        ("HTTPS://APP.EXAMPLE.TEST/A", f"https://{HOST}/A"),
        ("mailto:someone@example.test", None),
        ("javascript:alert(1)", None),
        ("data:text/html,<b>x</b>", None),
        ("tel:+441234", None),
        ("/logo.png", None),
        ("/bundle.css", None),
        ("https://user:pass@app.example.test/x", None),
    ],
)
def test_normalization_drops_what_is_not_worth_following(raw: str, expected: str | None) -> None:
    assert normalize(SEED, raw) == expected


def test_two_links_differing_only_by_fragment_are_one_url() -> None:
    """Otherwise one page becomes several queue entries and several requests."""
    assert normalize(SEED, "/x#a") == normalize(SEED, "/x#b")


def test_link_extraction_deduplicates_and_keeps_document_order() -> None:
    body = b'<html><a href="/b">b</a><img src="/a.html"><a href="/b">again</a></html>'
    assert extract_links(SEED, body, limit=50) == [
        f"https://{HOST}/b",
        f"https://{HOST}/a.html",
    ]


def test_a_malformed_page_yields_no_links_rather_than_an_error() -> None:
    """The body is an adversarial response, so extraction must not raise."""
    for body in (b"", b"<a href=", b"<a href=\x00\xff>", b"<" * 5000):
        assert isinstance(extract_links(SEED, body, limit=10), list)


def test_title_extraction_is_bounded_and_collapses_whitespace() -> None:
    assert extract_title(b"<html><title>  Hello\n  World </title></html>") == "Hello World"
    assert extract_title(b"<html>no title</html>") == ""


# --- forms --------------------------------------------------------------------


def test_form_actions_are_recorded_but_this_module_never_submits_one() -> None:
    body = b'<html><form action="/delete" method="post"><input></form></html>'
    assert extract_forms(SEED, body, limit=10) == [f"https://{HOST}/delete"]


async def test_state_changing_forms_are_reported_for_review() -> None:
    """Their existence is useful to a reviewer; submitting one needs
    `allow_state_mutation`, and the crawler does not submit them even then."""
    transport = PageTransport(
        {SEED: b'<html><form action="/orders/delete" method="post"></form></html>'}
    )
    result = await crawler(transport).crawl(context(), DastTarget(seed_url=SEED))
    assert state_changing_forms(result) == (f"https://{HOST}/orders/delete",)
    # GET only: the crawler issued no POST.
    assert transport.requested == [SEED]


async def test_the_crawler_only_ever_issues_get() -> None:
    """Under the default `allow_state_mutation=False` — and in fact always, since
    this module has no code path that sends anything else."""
    import inspect

    from app.core.dast import crawl as crawl_module

    source = inspect.getsource(crawl_module)
    assert 'method="GET"' in source
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        assert f'method="{verb}"' not in source, verb


# --- extra seeds --------------------------------------------------------------


async def test_an_operator_supplied_seed_is_checked_like_a_discovered_one() -> None:
    """A deep link the operator supplied gets no privilege over a found one."""
    transport = PageTransport({SEED: b"<html>seed</html>"})
    result = await crawler(transport).crawl(
        context(),
        DastTarget(seed_url=SEED, extra_seeds=["https://attacker.example/deep"]),
    )
    assert not any("attacker.example" in url for url in all_queued_urls(result))
    assert result.refused[0].url == "https://attacker.example/deep"


async def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_pages"):
        CrawlLimits(max_pages=0)


# --- tool policy: the destructive-template control -----------------------------


def test_the_default_policy_excludes_every_mutating_tag() -> None:
    """The phase's second acceptance criterion: *destructive templates excluded
    unless `allow_state_mutation` is explicitly set*."""
    from app.core.dast.policy import MUTATING_TAGS, NEVER_TAGS, tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    assert policy.mode == "passive"
    for tag in MUTATING_TAGS:
        assert tag not in policy.include_tags, tag
        # Excluded as well as not included: a template can carry several tags,
        # and `exposure,intrusive` must not slip in on the first one.
        assert tag in policy.exclude_tags, tag
    for tag in NEVER_TAGS:
        assert tag in policy.exclude_tags, tag


def test_allowing_state_mutation_permits_the_intrusive_set() -> None:
    from app.core.dast.policy import MUTATING_TAGS, tool_policy

    policy = tool_policy(allow_state_mutation=True, allowed_methods=("GET", "POST"))
    assert policy.mode == "active"
    for tag in MUTATING_TAGS:
        assert tag in policy.include_tags, tag
        assert tag not in policy.exclude_tags, tag


def test_out_of_band_templates_are_excluded_even_with_state_mutation() -> None:
    """An out-of-band template makes the target contact a server the engagement
    never authorized. That is a separate decision from "may state change", and
    one this platform has not built the infrastructure for."""
    from app.core.dast.policy import NEVER_TAGS, tool_policy

    for allow in (False, True):
        policy = tool_policy(allow_state_mutation=allow, allowed_methods=("GET",))
        for tag in NEVER_TAGS:
            assert tag in policy.exclude_tags, (allow, tag)
            assert tag not in policy.include_tags, (allow, tag)


def test_nuclei_info_severity_is_not_reported() -> None:
    """A nuclei `info` template fires on almost every site and would bury the
    findings that matter."""
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    assert "info" not in policy.severities


# --- the nuclei command line is the control -----------------------------------


def test_the_nuclei_command_stays_offline_and_excludes_callbacks() -> None:
    """Asserted on the command line rather than through a mocked subprocess:
    these flags *are* the security property."""
    from app.core.dast.nuclei import command_for
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    command = command_for(policy, [SEED], rate=7)

    assert command[0] == "nuclei"
    # Offline: no template fetch, no version ping, so the run uses the reviewed
    # template set.
    assert "-disable-update-check" in command
    # Out-of-band client off entirely, on top of the tag exclusion.
    assert "-no-interactsh" in command
    # The rate the target's owner agreed to.
    assert "-rate-limit" in command
    assert command[command.index("-rate-limit") + 1] == "7"
    excluded = command[command.index("-exclude-tags") + 1]
    assert "intrusive" in excluded
    assert "oast" in excluded


def test_the_nuclei_command_bounds_how_many_targets_it_is_given() -> None:
    from app.core.dast.nuclei import MAX_TARGETS, command_for
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    command = command_for(policy, [f"https://{HOST}/{i}" for i in range(500)], rate=5)
    assert command.count("-target") == MAX_TARGETS


def test_a_nuclei_finding_without_a_template_id_is_dropped() -> None:
    """No rule id means nothing a reader can look up or verify."""
    from app.core.dast.nuclei import _finding
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    assert _finding({"matched-at": SEED, "info": {"name": "x"}}, policy) is None
    assert _finding({"template-id": "t", "info": {}}, policy) is None


def test_a_nuclei_finding_carries_only_verified_advisory_ids() -> None:
    from app.core.dast.nuclei import _finding
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    finding = _finding(
        {
            "template-id": "exposed-env",
            "matched-at": f"https://{HOST}/.env",
            "info": {
                "name": "Exposed .env",
                "severity": "high",
                "classification": {
                    "cve-id": ["CVE-2021-44228", "not-a-cve", "CVE-BOGUS"],
                    "cwe-id": ["CWE-200", "nonsense"],
                },
            },
        },
        policy,
    )
    assert finding is not None
    assert "CVE-2021-44228" in finding.frameworks
    # Dropped rather than repaired: an identifier we had to fix up is one the
    # tool did not actually report.
    assert "not-a-cve" not in finding.frameworks
    assert "CVE-BOGUS" not in finding.frameworks
    assert "CWE-200" in finding.frameworks
    assert "nonsense" not in finding.frameworks
    assert "passive" in finding.description


# --- zap ----------------------------------------------------------------------


def test_zap_runs_the_baseline_script_unless_state_mutation_is_allowed() -> None:
    """Two different binaries rather than a flag, so the active scan cannot be
    reached by a typo in an argument."""
    from app.core.dast.policy import tool_policy
    from app.core.dast.zap import binary_for

    passive = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    active = tool_policy(allow_state_mutation=True, allowed_methods=("GET", "POST"))
    assert binary_for(passive) == "zap-baseline.py"
    assert binary_for(active) == "zap-full-scan.py"


@pytest.mark.parametrize(
    ("domains", "expected"),
    [
        (("app.example.test",), "app.example.test"),
        (("app.example.test", "other.example.test"), None),
        (("*.example.test",), None),
        ((), None),
    ],
)
def test_zap_declines_unless_exactly_one_concrete_host_is_allowed(
    domains: tuple[str, ...], expected: str | None
) -> None:
    """ZAP spiders outside the scope engine's view, so it runs only where this
    platform can bound where it goes."""
    from app.core.dast.zap import single_allowed_host

    assert single_allowed_host(domains) == expected


async def test_zap_reports_a_visible_gap_rather_than_running_unbounded() -> None:
    from app.core.dast.policy import tool_policy
    from app.core.dast.zap import run_zap

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    results = await run_zap(SEED, policy, allowed_domains=(HOST, "other.test"))
    assert [item.id for item in results] == ["KERVY-APPSEC-000"]
    assert "exactly one concrete host" in results[0].evidence


def test_a_zap_alert_is_stripped_of_html_and_keeps_its_rule_id() -> None:
    from app.core.dast.policy import tool_policy
    from app.core.dast.zap import parse_report

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    findings = parse_report(
        {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10038",
                            "name": "Content Security Policy Header Not Set",
                            "riskdesc": "Medium (High)",
                            "confidence": "High",
                            "desc": "<p>No CSP header.</p>",
                            "solution": "<p>Set one.</p>",
                            "cweid": "693",
                            "instances": [{"uri": f"https://{HOST}/"}],
                        }
                    ]
                }
            ]
        },
        policy,
        SEED,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "KERVY-DAST-ZAP-10038"
    assert "<p>" not in finding.description
    assert "CWE-693" in finding.frameworks
    assert "baseline" in finding.description


# --- the engine ---------------------------------------------------------------


async def test_the_engine_reports_out_of_scope_links_as_a_finding() -> None:
    from app.core.dast.engine import DastEngine

    transport = PageTransport({SEED: b'<html><a href="https://tracker.example/px">t</a></html>'})
    engine = DastEngine(crawler=crawler(transport), run_tools=False)
    results = await engine.run(context(), DastTarget(seed_url=SEED))

    refusal = next(item for item in results if item.id == "KERVY-DAST-001")
    assert "tracker.example" in refusal.description
    # Nothing was sent, and the finding says so rather than implying a test.
    assert "nothing was sent" in refusal.impact


async def test_an_incomplete_crawl_is_reported_as_a_coverage_gap() -> None:
    """Otherwise three findings from five pages read as a whole-application
    assessment."""
    from app.core.dast.engine import DastEngine

    pages = {
        f"https://{HOST}/c{index}": (f'<html><a href="/c{index + 1}">next</a></html>'.encode())
        for index in range(30)
    }
    pages[SEED] = b'<html><a href="/c0">start</a></html>'
    engine = DastEngine(crawler=crawler(PageTransport(pages)), run_tools=False)
    results = await engine.run(
        context(), DastTarget(seed_url=SEED, limits=CrawlLimits(max_pages=3))
    )

    gap = next(item for item in results if item.id == "KERVY-DAST-009")
    assert "page limit" in gap.description
    assert gap.confidence is Confidence.DESIGN_REVIEW


async def test_a_complete_crawl_reports_no_coverage_gap() -> None:
    """The clean state has to be reachable, or the marker becomes noise."""
    from app.core.dast.engine import DastEngine

    transport = PageTransport({SEED: b"<html>only page</html>"})
    engine = DastEngine(crawler=crawler(transport), run_tools=False)
    results = await engine.run(context(), DastTarget(seed_url=SEED))
    assert [item.id for item in results] == []


async def test_state_changing_forms_are_reported_with_the_mode_that_applied() -> None:
    from app.core.dast.engine import DastEngine

    transport = PageTransport({SEED: b'<html><form action="/pay" method="post"></form></html>'})
    engine = DastEngine(crawler=crawler(transport), run_tools=False)
    results = await engine.run(context(), DastTarget(seed_url=SEED))
    forms = next(item for item in results if item.id == "KERVY-DAST-002")
    assert "does not allow state mutation" in forms.description


async def test_a_crawl_that_reached_nothing_says_the_tools_did_not_run() -> None:
    """Two silent adapters would read as two clean scans."""
    from app.core.dast.engine import DastEngine

    transport = PageTransport({})
    crawl = ScopedCrawler(
        transport=transport,  # type: ignore[arg-type]
        engine=ScopeEngine(),
        dns_resolver=Resolver("127.0.0.1"),
    )
    engine = DastEngine(crawler=crawl, run_tools=True)
    results = await engine.run(context(), DastTarget(seed_url=SEED))
    assert [item.id for item in results].count("KERVY-APPSEC-000") == 2


def test_the_dast_pillar_exists_so_coverage_can_name_it() -> None:
    from app.core.appsec.contract import Pillar

    assert Pillar.DAST.value == "dast"
