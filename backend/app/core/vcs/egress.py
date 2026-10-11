"""Reaching a code host through the one gated transport.

Third instance of the same pattern (`assistant/egress.py`,
`integrations/egress.py`), and it earns its repetition: the allowlist is
derived from a `Destination` that `policy.resolve_destination` already checked,
holds that one API host, and cannot be widened by any caller. A code-host
connection therefore cannot be turned into a way to reach a target, an internal
service, or the cloud metadata endpoint.

`allowed_methods` is wider than the notification context's because the work is
read-then-write: `GET` to read a pull request's changed lines, `POST` to create
a check run and a review, `PATCH` to update one already created. It stops
short of `PUT` and `DELETE` entirely, and `PATCH` itself is scoped to
**exact, pre-computed paths** rather than the whole host — see
`allowed_paths` below for why that precision is load-bearing, not cosmetic.
Merging a pull request, updating a branch reference, deleting a file, or
editing the pull request resource itself (closing it, changing its base
branch — also a `PATCH`, on a different path) all stay refused, enforced by
the scope engine rather than asserted by this module.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement
from app.core.vcs.contract import Destination, RepoRef

PUBLISH_WINDOW = timedelta(minutes=10)

#: One publish is a handful of requests: read the diff (paginated), create or
#: update the check run, post a review. Bounded so a paging bug stops rather
#: than hammers someone's API quota.
PUBLISH_BUDGETS = Budgets(
    max_requests=30,
    max_concurrency=2,
    requests_per_second=5.0,
    max_tokens_sent=0,
    max_tokens_received=0,
    max_estimated_cost_usd=0.0,
    max_wall_clock_minutes=5,
)


def vcs_egress_context(
    destination: Destination, repo: RepoRef, pull_number: int, *, check_run_id: int | None = None
) -> RunContext:
    """A scope context permitting one already-checked code-host API host —
    and, for `PATCH`, only the exact check-run resource this publish may
    update.

    `repo` and `pull_number` are required, not defaulted, because the path
    allowlist below is built from them: there is no safe "unrestricted"
    fallback for a write method the way there is for `GET`. `check_run_id`
    is the one already created for this exact head SHA, when a prior publish
    already created it (`app/core/vcs/service.py::publish()` looks this up
    before building this context) — omitted entirely for a first publish,
    when there is nothing yet to update and `PATCH` has no legitimate target
    at all.

    **Why exact paths, not a wildcard prefix.** `path_matches`
    (`app/core/scope/hostmatch.py`) only supports a trailing `/*` prefix
    match, no mid-string wildcard — which is exactly why a pattern like
    `/repos/{owner}/{repo}/pulls/*` was not used here even though it would
    have covered today's two `pulls`-rooted calls (`.../files`,
    `.../reviews`) in one entry: that same prefix also matches
    `/repos/{owner}/{repo}/pulls/{number}` *bare* — GitHub's own `PATCH`
    endpoint for editing a pull request's title, body, state or base branch.
    Widening the path allowlist to make `PATCH` reachable at all, and then
    accidentally also making it reachable against the pull request resource
    itself, would be a far worse regression than the one this change fixes.
    Every path below is therefore the complete, exact string a real call
    constructs — the Enterprise `/api/v3` prefix (or its absence on
    github.com) derived from `destination.api_base`, `pull_number` and
    `check_run_id` interpolated directly, no pattern-matching left to do
    the narrowing.
    """
    now = datetime.now(UTC)
    # GitHub Enterprise Server serves its REST API under `/api/v3`
    # (`destination.api_base` already carries that, built once in
    # `policy.py::resolve_destination`); github.com's own `api_base` has no
    # path component at all. Deriving the prefix from `api_base` here,
    # rather than hardcoding `/repos/...`, is what keeps this allowlist
    # correct for both — a path check that only worked against github.com
    # would silently refuse every Enterprise connection's own publish.
    api_prefix = urlsplit(destination.api_base).path.rstrip("/")
    base = f"{api_prefix}/repos/{repo.owner}/{repo.name}"
    allowed_paths = (
        f"{base}/pulls/{pull_number}/files",
        f"{base}/pulls/{pull_number}/reviews",
        f"{base}/check-runs",
        *((f"{base}/check-runs/{check_run_id}",) if check_run_id is not None else ()),
    )
    roe = RulesOfEngagement(
        allowed_domains=(destination.host,),
        excluded_domains=(),
        # Empty on purpose: a self-hosted code host on an internal address is
        # exactly the case where an operator must widen the rules deliberately,
        # not one this context should quietly permit.
        allowed_ip_ranges=(),
        allowed_paths=allowed_paths,
        excluded_paths=(),
        # PUT and DELETE — merge, delete a file — stay refused outright.
        # PATCH is admitted only together with the exact-path allowlist
        # above; the engine ANDs the two checks, so PATCH against anything
        # not in that list (a ref, a file, the pull request resource itself)
        # is still refused, not merely avoided by this code.
        allowed_methods=("GET", "POST", "PATCH"),
        forbidden_headers=(),
        budgets=PUBLISH_BUDGETS,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1), valid_until=now + PUBLISH_WINDOW
        ),
        budgets=BudgetTracker(PUBLISH_BUDGETS),
        kill_switch=KillSwitch(),
    )
