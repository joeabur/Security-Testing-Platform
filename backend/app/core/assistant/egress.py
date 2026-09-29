"""Reaching a configured AI provider through the one gated transport
(docs/BUILD_SPEC.md §6.1, §28).

The provider endpoint is **infrastructure the operator configured**, not a
target under assessment. That distinction matters, but it is not a licence
to open a second way out of the process: §28 says every outbound request
goes through the scope-gated transport, in the API, a worker, the CLI or a
plugin, and an AI subsystem is the most likely place for an exception to be
introduced by accident.

So a provider call uses the same `GatedTransport`, under a context built
here, with three properties that make it safe to grant:

* **The allowlist is derived from the configuration, never from an
  argument.** It contains exactly the provider's host, plus whatever
  private/loopback CIDRs the operator explicitly authorized *for this
  provider* (`ProviderConfig.allowed_ip_ranges` — the same mechanism a
  target's own `RulesOfEngagement.allowed_ip_ranges` uses, so a self-hosted
  `openai_compatible` endpoint on an internal network is reachable without
  weakening the default-deny). There is no parameter through which a target
  hostname could be passed, so this context cannot be used to reach a
  target — which is what would turn it into the scope bypass §28 forbids.
* **It carries its own budget.** Provider calls do not spend an
  assessment's request or token budget, and an assessment cannot spend the
  provider's.
* **The blocked-IP, DNS-re-resolution and no-redirect rules still apply.**
  A provider endpoint pointed at the metadata service is refused exactly as
  a target would be.

The authorization window here records the operator's act of configuring a
provider. It is deliberately *not* a target authorization, and because the
allowlist holds only the provider host, it can never stand in for one.
"""

from datetime import UTC, datetime, timedelta

from app.core.assistant.provider import ProviderConfig
from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement

# Short-lived on purpose: a context is built per interaction, so a stale one
# cannot be reused later to make a call nobody asked for.
PROVIDER_CALL_WINDOW = timedelta(minutes=30)

# Bounds on one assistant interaction. Small: an assistant call is a handful
# of requests, and a runaway loop should stop rather than bill someone.
PROVIDER_BUDGETS = Budgets(
    max_requests=20,
    max_concurrency=2,
    requests_per_second=5.0,
    max_tokens_sent=200_000,
    max_tokens_received=100_000,
    max_estimated_cost_usd=5.0,
    max_wall_clock_minutes=10,
)


def platform_egress_context(config: ProviderConfig) -> RunContext:
    """A scope context that permits the configured provider host and nothing else."""
    host = config.host
    if not host:
        raise ValueError(f"provider endpoint {config.endpoint!r} has no host")

    now = datetime.now(UTC)
    roe = RulesOfEngagement(
        # Derived from the configuration. Not a parameter, so no caller can
        # widen it — this is what keeps the context from becoming a way to
        # reach a target without a target's authorization.
        allowed_domains=(host,),
        excluded_domains=(),
        allowed_ip_ranges=config.allowed_ip_ranges,
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("POST",),
        forbidden_headers=(),
        budgets=PROVIDER_BUDGETS,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1),
            valid_until=now + PROVIDER_CALL_WINDOW,
        ),
        budgets=BudgetTracker(PROVIDER_BUDGETS),
        kill_switch=KillSwitch(),
    )
