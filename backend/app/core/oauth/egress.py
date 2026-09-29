"""Reaching an OAuth provider's own token and profile endpoints through the
one gated transport.

Fourth instance of the `RunContext`-per-fixed-destination pattern
(`app/core/vcs/egress.py`, `app/core/assistant/egress.py`,
`app/core/integrations/egress.py`) — same reasoning each time: the allowlist
holds exactly the one host this call needs, built fresh per request rather
than accepted as a parameter, so an OAuth exchange can never be turned into a
way to reach anything else. `GET`+`POST` covers everything a token exchange
or a profile fetch needs; there is nothing here that ever writes to the
provider.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

#: One login round trip is at most a handful of requests: exchange the code,
#: fetch the profile, and — for GitHub, when the primary email is private —
#: one more call for the verified email list.
OAUTH_WINDOW = timedelta(minutes=5)

OAUTH_BUDGETS = Budgets(
    max_requests=10,
    max_concurrency=1,
    requests_per_second=5.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=2,
)


def oauth_egress_context(host: str) -> RunContext:
    """A scope context permitting one OAuth provider host, for the duration
    of a single login round trip."""
    now = datetime.now(UTC)
    roe = RulesOfEngagement(
        allowed_domains=(host,),
        excluded_domains=(),
        allowed_ip_ranges=(),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("GET", "POST"),
        forbidden_headers=(),
        budgets=OAUTH_BUDGETS,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1), valid_until=now + OAUTH_WINDOW
        ),
        budgets=BudgetTracker(OAUTH_BUDGETS),
        kill_switch=KillSwitch(),
    )
