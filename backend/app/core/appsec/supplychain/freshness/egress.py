"""Reaching four public package registries through the one gated transport.

Same fixed-host pattern `osv/egress.py` and `enrichment/egress.py` already
establish: a literal host with no parameter through which a caller could
substitute a different one, so a context can never become a way to reach a
target, an internal service, or the cloud metadata endpoint. All four
registries are public infrastructure the platform itself decided to call,
not something an operator configures per target.

**`requests_per_second` documents each vendor's own published rate guidance;
it is not an actively enforced throttle.** This codebase's `BudgetTracker`
(`app/core/scope/budgets.py`) only ever checks `max_requests`/
`max_wall_clock_minutes`/tokens/cost in `reserve()` — the same is already
true of `OSV_BUDGETS`'s own `requests_per_second=5.0` and the NVD/GHSA
budgets in `enrichment/egress.py`. A registry that starts returning
429/403 mid-run is handled the same way any other failed lookup is:
skipped, not crashed on.

**crates.io is the one registry here with a real, stated policy to
respect** (confirmed via research, not assumed): its API usage guidance
caps anonymous use at roughly one request per second and requires a
User-Agent that identifies the calling application with contact
information, rather than a bare HTTP-library default — a client naming
only its library risks being blocked outright. `crates_client.py`'s
requests carry such a header for this reason. npm's registry, PyPI's
Warehouse, and the Go module proxy (`proxy.golang.org`, designed for
exactly this kind of per-version metadata read) publish no comparably
strict anonymous-use policy.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

NPM_HOST = "registry.npmjs.org"
PYPI_HOST = "pypi.org"
GO_PROXY_HOST = "proxy.golang.org"
CRATES_HOST = "crates.io"
QUERY_WINDOW = timedelta(minutes=10)

#: Shared shape for the three registries with no stated anonymous-use
#: policy to narrow against. `max_requests` bounds the real worst case
#: regardless of `MAX_FRESHNESS_LOOKUPS` in `engine.py`.
_DEFAULT_BUDGETS = Budgets(
    max_requests=50,
    max_concurrency=1,
    requests_per_second=2.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=5,
)

NPM_BUDGETS = _DEFAULT_BUDGETS
PYPI_BUDGETS = _DEFAULT_BUDGETS
GO_PROXY_BUDGETS = _DEFAULT_BUDGETS

#: crates.io's own documented anonymous-use guidance: roughly 1 request
#: per second. See the module docstring for why this one registry gets a
#: narrower budget than the other three.
CRATES_BUDGETS = Budgets(
    max_requests=50,
    max_concurrency=1,
    requests_per_second=1.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=5,
)


def _egress_context(host: str, budgets: Budgets) -> RunContext:
    now = datetime.now(UTC)
    roe = RulesOfEngagement(
        allowed_domains=(host,),
        excluded_domains=(),
        allowed_ip_ranges=(),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("GET",),
        forbidden_headers=(),
        budgets=budgets,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1), valid_until=now + QUERY_WINDOW
        ),
        budgets=BudgetTracker(budgets),
        kill_switch=KillSwitch(),
    )


def npm_egress_context() -> RunContext:
    """A scope context permitting exactly `registry.npmjs.org`, GET only."""
    return _egress_context(NPM_HOST, NPM_BUDGETS)


def pypi_egress_context() -> RunContext:
    """A scope context permitting exactly `pypi.org`, GET only."""
    return _egress_context(PYPI_HOST, PYPI_BUDGETS)


def go_proxy_egress_context() -> RunContext:
    """A scope context permitting exactly `proxy.golang.org`, GET only."""
    return _egress_context(GO_PROXY_HOST, GO_PROXY_BUDGETS)


def crates_egress_context() -> RunContext:
    """A scope context permitting exactly `crates.io`, GET only."""
    return _egress_context(CRATES_HOST, CRATES_BUDGETS)
