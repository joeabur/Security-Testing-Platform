"""Release-blocking scope-engine tests — docs/BUILD_SPEC.md §6.3.

This is the safety boundary the whole product depends on. Every case in the
mandated matrix has its own test; nothing here is combined or skipped, so a
regression in any single rule fails loudly and specifically.
"""

import asyncio

import pytest

from app.core.scope.engine import ScopeEngine
from app.core.scope.kill_switch import KillSwitch
from tests.security.conftest import (
    FakeClock,
    FakeDnsResolver,
    make_authorization,
    make_context,
    make_roe,
)


async def _check(
    engine: ScopeEngine, ctx, dns: FakeDnsResolver, *, url: str, method: str = "GET", **kw
):
    return await engine.check(ctx, dns_resolver=dns, method=method, url=url, **kw)


# --- domain scope ------------------------------------------------------


async def test_out_of_scope_domain_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()
    fake_dns.set("evil.test", ["203.0.113.9"])

    decision = await _check(engine, ctx, fake_dns, url="https://evil.test/api")

    assert decision.allowed is False
    assert decision.rule == "domain_not_allowlisted"


async def test_subdomain_not_covered_by_wildcard_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_domains=("ai.example.test",)))  # no wildcard
    fake_dns.set("evil.ai.example.test", ["10.20.0.7"])

    decision = await _check(engine, ctx, fake_dns, url="https://evil.ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "domain_not_allowlisted"


async def test_wildcard_allows_covered_subdomain(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_domains=("*.ai.example.test",)))

    decision = await _check(engine, ctx, fake_dns, url="https://sub.ai.example.test/api")

    assert decision.allowed is True


async def test_idn_punycode_homograph_of_allowed_domain_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_domains=("example.test",)))
    # Cyrillic е and а look identical to Latin e/a but IDNA-encode differently.
    homograph_host = "exаmplе.test"
    fake_dns.set(homograph_host, ["203.0.113.10"])

    decision = await _check(engine, ctx, fake_dns, url=f"https://{homograph_host}/api")

    assert decision.allowed is False
    assert decision.rule == "domain_not_allowlisted"


async def test_url_with_userinfo_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()

    decision = await _check(
        engine, ctx, fake_dns, url="https://user@ai.example.test/api", method="GET"
    )

    assert decision.allowed is False
    assert decision.rule == "userinfo_in_url"


async def test_exclusions_win_over_allowlist(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(
        roe=make_roe(
            allowed_domains=("*.ai.example.test",),
            excluded_domains=("admin.ai.example.test",),
        )
    )
    fake_dns.set("admin.ai.example.test", ["10.20.0.8"])

    decision = await _check(engine, ctx, fake_dns, url="https://admin.ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "excluded_domain"


# --- DNS / IP resolution -------------------------------------------------


async def test_dns_rebinding_host_allowed_ip_is_not_blocked(fake_dns: FakeDnsResolver) -> None:
    """The host is allowlisted, but it now resolves to a private IP — the
    kind of bait-and-switch DNS rebinding relies on. Re-resolving fresh on
    every check (rather than trusting a prior "this host looked fine"
    result) is what catches it."""
    engine = ScopeEngine()
    ctx = make_context()
    fake_dns.set("ai.example.test", ["203.0.113.5"])
    first = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert first.allowed is True

    fake_dns.set("ai.example.test", ["127.0.0.1"])
    second = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert second.allowed is False
    assert second.rule == "blocked_ip"
    # proves re-resolution actually happened rather than caching the first answer
    assert fake_dns.calls.count("ai.example.test") == 2


async def test_cloud_metadata_ip_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()
    fake_dns.set("ai.example.test", ["169.254.169.254"])

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "blocked_ip"


@pytest.mark.parametrize(
    "allowed_range",
    ["169.254.169.254/32", "169.254.0.0/16", "0.0.0.0/0"],
)
async def test_a_cloud_metadata_ip_cannot_be_allowlisted(
    fake_dns: FakeDnsResolver, allowed_range: str
) -> None:
    """The one address no configuration may permit.

    Private ranges are overridable on purpose — an internal staging host and
    the demo lab on its internal network both live there. The metadata endpoint
    is different in kind: it is not a target, it is what hands out the
    credentials of the machine this platform runs on. A tool that fetches an
    arbitrary URL for its caller is SSRF-shaped by design, and this is the one
    URL that turns that shape into a compromise of its own host — so one
    mistyped allowlist must not be the difference.
    """
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_ip_ranges=(allowed_range,)))
    fake_dns.set("ai.example.test", ["169.254.169.254"])

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "blocked_ip"


async def test_a_private_range_can_be_allowlisted_deliberately(
    fake_dns: FakeDnsResolver,
) -> None:
    """The counterpart, and the reason the metadata rule has to be separate:
    an operator scanning an internal host or the demo lab on its internal
    Docker network is doing something legitimate."""
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_ip_ranges=("172.20.0.0/16",)))
    fake_dns.set("ai.example.test", ["172.20.0.5"])

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert decision.allowed is True


@pytest.mark.parametrize(
    "blocked_ip",
    ["127.0.0.1", "10.1.2.3", "172.16.0.4", "192.168.1.1", "169.254.1.1", "::1", "fd00::1"],
)
async def test_rfc1918_loopback_link_local_blocked_by_default(
    fake_dns: FakeDnsResolver, blocked_ip: str
) -> None:
    engine = ScopeEngine()
    ctx = make_context()
    fake_dns.set("ai.example.test", [blocked_ip])

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "blocked_ip"


async def test_private_ip_allowed_when_explicitly_in_roe(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_ip_ranges=("10.20.0.0/24",)))
    fake_dns.set("ai.example.test", ["10.20.0.5"])

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert decision.allowed is True


# --- path / method / headers ---------------------------------------------


async def test_excluded_path_under_allowed_prefix_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_paths=("/api/*",), excluded_paths=("/api/admin/*",)))

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api/admin/users")

    assert decision.allowed is False
    assert decision.rule == "excluded_path"


async def test_path_not_covered_by_allowlist_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_paths=("/api/chat",)))

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api/other")

    assert decision.allowed is False
    assert decision.rule == "path_not_allowlisted"


async def test_method_not_in_allowed_methods_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(allowed_methods=("GET",)))

    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api", method="POST")

    assert decision.allowed is False
    assert decision.rule == "method_not_allowed"


async def test_forbidden_header_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(forbidden_headers=("X-Internal-Admin",)))

    decision = await _check(
        engine, ctx, fake_dns, url="https://ai.example.test/api", headers={"X-Internal-Admin": "1"}
    )

    assert decision.allowed is False
    assert decision.rule == "forbidden_header"


# --- budgets ---------------------------------------------------------------


async def test_request_budget_exceeded_blocks_and_halts_run(fake_dns: FakeDnsResolver) -> None:
    from tests.security.conftest import make_budgets

    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_requests=1)))

    first = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert first.allowed is True

    second = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert second.allowed is False
    assert second.rule == "budget_exceeded:requests"
    assert second.halted is True

    # The run stays halted — a request that would otherwise be fine is still blocked.
    third = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert third.allowed is False
    assert third.rule == "halted"


async def test_token_budget_exceeded_blocks_and_halts_run(fake_dns: FakeDnsResolver) -> None:
    from tests.security.conftest import make_budgets

    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_tokens_sent=100)))

    decision = await _check(
        engine, ctx, fake_dns, url="https://ai.example.test/api", estimated_tokens_sent=1000
    )

    assert decision.allowed is False
    assert decision.rule == "budget_exceeded:tokens_sent"
    assert decision.halted is True


async def test_received_token_budget_exceeded_blocks_and_halts_run(
    fake_dns: FakeDnsResolver,
) -> None:
    from tests.security.conftest import make_budgets

    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_tokens_received=100)))

    decision = await _check(
        engine, ctx, fake_dns, url="https://ai.example.test/api", estimated_tokens_received=1000
    )

    assert decision.allowed is False
    assert decision.rule == "budget_exceeded:tokens_received"
    assert decision.halted is True


async def test_cost_budget_exceeded_blocks_and_halts_run(fake_dns: FakeDnsResolver) -> None:
    from tests.security.conftest import make_budgets

    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_estimated_cost_usd=1.0)))

    decision = await _check(
        engine, ctx, fake_dns, url="https://ai.example.test/api", estimated_cost_usd=5.0
    )

    assert decision.allowed is False
    assert decision.rule == "budget_exceeded:cost"
    assert decision.halted is True


async def test_wall_clock_exceeded_blocks_and_halts_run(fake_dns: FakeDnsResolver) -> None:
    from tests.security.conftest import make_budgets

    clock = FakeClock()
    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_wall_clock_minutes=10)), clock=clock)

    clock.advance(minutes=11)
    decision = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "budget_exceeded:wall_clock"
    assert decision.halted is True


async def test_concurrency_cap_never_exceeded_under_load(fake_dns: FakeDnsResolver) -> None:
    from tests.security.conftest import make_budgets

    ctx = make_context(roe=make_roe(budgets=make_budgets(max_concurrency=2, max_requests=1000)))
    in_flight = 0
    max_observed = 0
    lock = asyncio.Lock()

    async def worker() -> None:
        nonlocal in_flight, max_observed
        async with ctx.budgets.acquire_concurrency():
            async with lock:
                in_flight += 1
                max_observed = max(max_observed, in_flight)
            await asyncio.sleep(0.01)
            async with lock:
                in_flight -= 1

    await asyncio.gather(*(worker() for _ in range(20)))

    assert max_observed <= 2


# --- authorization / RoE resolution ----------------------------------------


async def test_authorization_expired_mid_run_blocks_and_halts(fake_dns: FakeDnsResolver) -> None:
    clock = FakeClock()
    engine = ScopeEngine()
    auth = make_authorization(clock=clock)
    ctx = make_context(authorization=auth, clock=clock)

    first = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert first.allowed is True

    clock.advance(days=7)  # past valid_until (valid_from + 6 days)
    second = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")

    assert second.allowed is False
    assert second.rule == "authorization_expired"
    assert second.halted is True


async def test_authorization_not_yet_valid_blocked() -> None:
    from datetime import timedelta

    clock = FakeClock()
    engine = ScopeEngine()
    auth = make_authorization(
        clock=clock,
        valid_from=clock.now() + timedelta(days=1),
        valid_until=clock.now() + timedelta(days=8),
    )
    ctx = make_context(authorization=auth, clock=clock)
    dns = FakeDnsResolver({"ai.example.test": ["203.0.113.5"]})

    decision = await _check(engine, ctx, dns, url="https://ai.example.test/api")

    assert decision.allowed is False
    assert decision.rule == "authorization_expired"


async def test_blackout_window_blocks_during_window_only(fake_dns: FakeDnsResolver) -> None:
    from datetime import timedelta

    from app.core.scope.models import BlackoutWindow

    clock = FakeClock()
    engine = ScopeEngine()
    window = BlackoutWindow(starts_at=clock.now(), ends_at=clock.now() + timedelta(hours=1))
    from tests.security.conftest import make_budgets

    ctx = make_context(
        roe=make_roe(blackout_windows=(window,), budgets=make_budgets(max_wall_clock_minutes=600)),
        clock=clock,
    )

    during = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert during.allowed is False
    assert during.rule == "blackout_window"
    assert during.halted is False  # lifts on its own once the window passes

    clock.advance(hours=2)
    after = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert after.allowed is True


def test_authorization_absent_refuses_run() -> None:
    from app.core.scope.errors import AuthorizationRequiredError
    from app.core.scope.resolve import resolve_authorization

    with pytest.raises(AuthorizationRequiredError):
        resolve_authorization(None)


def test_roe_fails_schema_validation_refuses_run() -> None:
    from app.core.scope.errors import RoEValidationError
    from app.core.scope.resolve import resolve_rules_of_engagement

    with pytest.raises(RoEValidationError):
        resolve_rules_of_engagement({"allowed_domains": "not-a-list"})


# --- fail-closed on internal error ------------------------------------------


async def test_scope_engine_raises_internally_fails_closed(fake_dns: FakeDnsResolver) -> None:
    """An unexpected fault anywhere in the engine blocks and halts.

    The failure is injected into the budget tracker rather than into DNS: a
    hostname that will not resolve is an ordinary outcome with its own rule
    (below), and using it here would no longer exercise this path.
    """
    engine = ScopeEngine()
    ctx = make_context()

    class ExplodingBudgets:
        def __getattr__(self, name: str) -> object:
            raise RuntimeError("boom")

    ctx.budgets = ExplodingBudgets()  # type: ignore[assignment]

    decision = await engine.check(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "internal_error"
    assert decision.halted is True


async def test_a_host_that_does_not_resolve_is_blocked_but_does_not_halt_the_run() -> None:
    """Fail closed without an address — there is no way to prove the host is
    not internal — but do not treat it as an engine fault.

    A hostname that does not resolve says nothing about the rest of the run.
    Halting on it let one dead host abort an entire assessment, including the
    checks that read files and make no requests at all.
    """

    class ExplodingResolver:
        async def resolve(self, hostname: str) -> list:
            raise OSError("Name or service not known")

    engine = ScopeEngine()
    ctx = make_context()

    decision = await engine.check(
        ctx, dns_resolver=ExplodingResolver(), method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "dns_resolution_failed"
    assert decision.halted is False
    assert ctx.halted is False


async def test_a_host_resolving_to_no_addresses_is_blocked() -> None:
    class EmptyResolver:
        async def resolve(self, hostname: str) -> list:
            return []

    engine = ScopeEngine()
    ctx = make_context()

    decision = await engine.check(
        ctx, dns_resolver=EmptyResolver(), method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "dns_resolution_failed"


# --- kill switch -------------------------------------------------------------


async def test_kill_switch_blocks_all_subsequent_checks(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()

    first = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert first.allowed is True

    ctx.kill_switch.trip()

    second = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert second.allowed is False
    assert second.rule == "kill_switch"
    assert second.halted is True


async def test_kill_switch_sentinel_file_trips_switch(tmp_path) -> None:
    sentinel = tmp_path / "KILL"
    switch = KillSwitch(sentinel_path=sentinel)
    assert switch.tripped is False

    sentinel.write_text("stop")

    assert switch.tripped is True


# --- static: no ungated HTTP client construction ----------------------------


def test_no_ungated_httpx_client_construction_outside_transport() -> None:
    """Every direct `httpx.AsyncClient(`/`httpx.Client(` construction in the
    application must live in app/core/scope/transport.py — that module is
    the single choke point every outbound request passes through."""
    import pathlib
    import re

    app_root = pathlib.Path(__file__).resolve().parents[2] / "app"
    allowed_file = app_root / "core" / "scope" / "transport.py"
    pattern = re.compile(r"httpx\.(Async)?Client\(")

    offenders = []
    for path in app_root.rglob("*.py"):
        if path == allowed_file:
            continue
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path))

    assert offenders == [], (
        f"Found ungated httpx client construction outside transport.py: {offenders}"
    )


def test_smtplib_is_used_in_exactly_one_sanctioned_module() -> None:
    """The mail relay is the one destination that cannot travel through
    `GatedTransport`, because SMTP is not HTTP. That exception is confined to
    `app/core/integrations/send.py`, which asks the scope engine to adjudicate
    the relay host before opening a socket. Pinned here so a second
    socket-opening path cannot be added quietly."""
    import pathlib
    import re

    app_root = pathlib.Path(__file__).resolve().parents[2] / "app"
    allowed_file = app_root / "core" / "integrations" / "send.py"
    pattern = re.compile(r"\bimport smtplib\b|\bfrom smtplib\b|\bsocket\.socket\(")

    offenders = [
        str(path)
        for path in app_root.rglob("*.py")
        if path != allowed_file and pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"Found socket-level egress outside send.py: {offenders}"


def test_the_code_host_client_cannot_write_to_a_repository() -> None:
    """`app/core/vcs` reads a pull request, creates or updates a check run,
    and posts a review comment. It must never merge, push, update a ref or
    write a file — and the point of pinning it statically is that a future
    contributor adding such a call has to delete or rewrite this test to do
    it, rather than slipping past review.

    `PATCH` alone is no longer blanket-forbidden — `update_check_run`
    legitimately uses it — so this checks the narrower, still-absolute
    thing: every `PATCH` call in this package targets a `check-runs` path,
    checked line-by-line rather than by the mere presence of the word
    "PATCH" anywhere in the file, which the egress context's own
    exact-path allowlist (`egress.py`) is what actually enforces at
    runtime; this is the static belt alongside that brace.
    """
    import pathlib
    import re

    vcs_root = pathlib.Path(__file__).resolve().parents[2] / "app" / "core" / "vcs"
    forbidden_verb = re.compile(r'method\s*=\s*"(PUT|DELETE)"')
    patch_verb = re.compile(r'method\s*=\s*"PATCH"')
    paths = re.compile(r'"/repos/[^"]*/(merges|git/refs|git/commits|contents)')

    offenders = []
    for path in vcs_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if forbidden_verb.search(text) or paths.search(text):
            offenders.append(str(path))
            continue
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if patch_verb.search(line) and "check-runs" not in "\n".join(
                lines[index : index + 3]
            ):
                offenders.append(str(path))
                break

    assert offenders == [], f"Found repository-write calls in app/core/vcs: {offenders}"


def test_the_code_host_egress_context_never_permits_a_merge_or_a_push() -> None:
    """The static check above is belt; this is braces. Even if such a call were
    added, the scope engine would refuse its verb — `PUT` and `DELETE`
    (merge, delete-a-file) are never in the allowed set at all, and `PATCH`
    is admitted only together with an exact-path allowlist narrow enough to
    exclude the pull request resource itself (`egress.py`'s own docstring),
    never host-wide."""
    from app.core.vcs.contract import Destination, RepoRef, VcsProvider
    from app.core.vcs.egress import vcs_egress_context

    ctx = vcs_egress_context(
        Destination(
            provider=VcsProvider.GITHUB,
            host="api.github.com",
            api_base="https://api.github.com",
        ),
        RepoRef("o", "r"),
        1,
    )
    assert set(ctx.roe.allowed_methods) == {"GET", "POST", "PATCH"}
    assert "PUT" not in ctx.roe.allowed_methods
    assert "DELETE" not in ctx.roe.allowed_methods
    assert ctx.roe.allowed_paths  # PATCH's narrowing has teeth only if this is non-empty
    assert ctx.roe.allowed_domains == ("api.github.com",)
    assert ctx.roe.allowed_ip_ranges == ()


# --- scope explain / dry-run (docs/BUILD_SPEC.md §6.2, §18) -----------------


async def test_explain_matches_check_for_an_allowed_request(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()

    decision = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is True
    assert decision.rule == "allow"


async def test_explain_matches_check_for_a_blocked_domain(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()
    fake_dns.set("evil.test", ["203.0.113.9"])

    decision = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://evil.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "domain_not_allowlisted"


async def test_explain_reports_budget_exceeded_without_consuming_it(
    fake_dns: FakeDnsResolver,
) -> None:
    from tests.security.conftest import make_budgets

    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_requests=1)))

    preview_one = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )
    preview_two = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )
    assert preview_one.allowed is True
    assert preview_two.allowed is True  # explain never consumes budget, so this stays true
    assert ctx.halted is False

    # A real check() still sees the full budget, since explain() reserved nothing.
    real = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert real.allowed is True

    second_real = await _check(engine, ctx, fake_dns, url="https://ai.example.test/api")
    assert second_real.allowed is False
    assert second_real.rule == "budget_exceeded:requests"


async def test_explain_does_not_trip_kill_switch_or_halt(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()
    ctx.kill_switch.trip()

    decision = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "kill_switch"
    # explain() reports what check() *would* return; it must not itself set ctx.halted.
    assert ctx.halted is False


async def test_explain_reports_already_halted_run(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()
    ctx.halt("something halted this run earlier")

    decision = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "halted"


async def test_explain_reports_authorization_expired() -> None:
    clock = FakeClock()
    engine = ScopeEngine()
    auth = make_authorization(clock=clock)
    ctx = make_context(authorization=auth, clock=clock)
    dns = FakeDnsResolver({"ai.example.test": ["203.0.113.5"]})
    clock.advance(days=7)

    decision = await engine.explain(
        ctx, dns_resolver=dns, method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "authorization_expired"


async def test_explain_reports_blackout_window(fake_dns: FakeDnsResolver) -> None:
    from datetime import timedelta

    from app.core.scope.models import BlackoutWindow

    clock = FakeClock()
    engine = ScopeEngine()
    window = BlackoutWindow(starts_at=clock.now(), ends_at=clock.now() + timedelta(hours=1))
    ctx = make_context(roe=make_roe(blackout_windows=(window,)), clock=clock)

    decision = await engine.explain(
        ctx, dns_resolver=fake_dns, method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "blackout_window"


async def test_explain_reports_budget_exceeded(fake_dns: FakeDnsResolver) -> None:
    from tests.security.conftest import make_budgets

    engine = ScopeEngine()
    ctx = make_context(roe=make_roe(budgets=make_budgets(max_tokens_sent=10)))

    decision = await engine.explain(
        ctx,
        dns_resolver=fake_dns,
        method="GET",
        url="https://ai.example.test/api",
        estimated_tokens_sent=1000,
    )

    assert decision.allowed is False
    assert decision.rule == "budget_exceeded:tokens_sent"


async def test_explain_reports_an_unresolvable_host_without_halting() -> None:
    """`explain` is a preview, so it must never halt the run — and an
    unresolvable host is reported as exactly that rather than as a fault."""

    class ExplodingResolver:
        async def resolve(self, hostname: str) -> list:
            raise OSError("Name or service not known")

    engine = ScopeEngine()
    ctx = make_context()

    decision = await engine.explain(
        ctx, dns_resolver=ExplodingResolver(), method="GET", url="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "dns_resolution_failed"
    assert ctx.halted is False


async def test_unparseable_url_blocked(fake_dns: FakeDnsResolver) -> None:
    engine = ScopeEngine()
    ctx = make_context()

    decision = await _check(engine, ctx, fake_dns, url="not-a-url-at-all")

    assert decision.allowed is False
    assert decision.rule == "unparseable_url"


async def test_check_redirect_target_blocks_an_unresolvable_location() -> None:
    class ExplodingResolver:
        async def resolve(self, hostname: str) -> list:
            raise OSError("Name or service not known")

    engine = ScopeEngine()
    ctx = make_context()

    decision = await engine.check_redirect_target(
        ctx, dns_resolver=ExplodingResolver(), location="https://ai.example.test/api"
    )

    assert decision.allowed is False
    assert decision.rule == "dns_resolution_failed"
