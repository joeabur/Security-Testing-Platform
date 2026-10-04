"""Reaching osv.dev through the one gated transport.

Fourth instance of the pattern `assistant/egress.py`, `integrations/egress.py`
and `vcs/egress.py` already establish: a fixed, hardcoded host with no
parameter through which a caller could substitute a different one — so this
context can never become a way to reach a target, an internal service, or the
cloud metadata endpoint. `osv.dev` is public infrastructure the platform
itself decided to call, not something an operator configures per target, so
unlike `vcs_egress_context`/`platform_egress_context` there is no
configuration object to derive the host from either: it is a literal.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

OSV_HOST = "api.osv.dev"
QUERY_WINDOW = timedelta(minutes=10)

#: A batch query (one request) plus up to ~150 detail lookups (one request
#: each — OSV's batch endpoint intentionally omits details to keep its own
#: response small). Bounded so a large lockfile cannot turn one scan into an
#: unbounded number of outbound requests.
OSV_BUDGETS = Budgets(
    max_requests=200,
    max_concurrency=4,
    requests_per_second=5.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=5,
)


def osv_egress_context() -> RunContext:
    """A scope context permitting exactly `api.osv.dev`, GET and POST only."""
    now = datetime.now(UTC)
    roe = RulesOfEngagement(
        allowed_domains=(OSV_HOST,),
        excluded_domains=(),
        allowed_ip_ranges=(),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("GET", "POST"),
        forbidden_headers=(),
        budgets=OSV_BUDGETS,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1), valid_until=now + QUERY_WINDOW
        ),
        budgets=BudgetTracker(OSV_BUDGETS),
        kill_switch=KillSwitch(),
    )
