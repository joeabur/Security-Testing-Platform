"""Reaching NVD and GHSA through the one gated transport.

Same fixed-host pattern `osv/egress.py` already establishes (itself the
fourth instance after `assistant/egress.py`, `integrations/egress.py`,
`vcs/egress.py`): a literal host with no parameter through which a
caller could substitute a different one, so this context can never
become a way to reach a target, an internal service, or the cloud
metadata endpoint. Both NVD and GHSA are public infrastructure the
platform itself decided to call, not something an operator configures
per target.

**`requests_per_second` here documents the vendor's own published rate
limit; it is not an actively enforced throttle.** This codebase's
`BudgetTracker` (`app/core/scope/budgets.py`) only ever checks
`max_requests`/`max_wall_clock_minutes`/tokens/cost in `reserve()` — the
same is already true of `OSV_BUDGETS`'s own `requests_per_second=5.0`.
A vendor that starts returning 429/403 mid-run is handled the same way
any other failed lookup is: skipped, not crashed on (see
`advisory_detail.py`) — correct because enrichment is additive to an
already-complete finding, never required for it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

NVD_HOST = "services.nvd.nist.gov"
GHSA_HOST = "api.github.com"
QUERY_WINDOW = timedelta(minutes=10)

#: NVD's own documented unauthenticated limit is 5 requests per 30
#: seconds. `max_requests` bounds the real worst case regardless; see the
#: module docstring for why `requests_per_second` itself isn't enforced.
NVD_BUDGETS = Budgets(
    max_requests=25,
    max_concurrency=1,
    requests_per_second=5 / 30,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=5,
)

#: Conservative against GitHub's unauthenticated REST budget (60/hour,
#: shared with everything else this process calls unauthenticated) —
#: deliberately well under what a single enrichment pass could need.
GHSA_BUDGETS = Budgets(
    max_requests=25,
    max_concurrency=1,
    requests_per_second=0.1,
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


def nvd_egress_context() -> RunContext:
    """A scope context permitting exactly `services.nvd.nist.gov`, GET only."""
    return _egress_context(NVD_HOST, NVD_BUDGETS)


def ghsa_egress_context() -> RunContext:
    """A scope context permitting exactly `api.github.com`, GET only."""
    return _egress_context(GHSA_HOST, GHSA_BUDGETS)
