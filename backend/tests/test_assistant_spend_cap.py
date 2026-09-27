"""Cumulative AI spend, capped across calls (app/core/assistant/spend_cap.py,
app/core/assistant/pricing.py).

`PROVIDER_BUDGETS` (egress.py) only ever bounded one interaction, and until
`openai_compatible.py` was wired up here it did not even do that: every call
passed `estimated_cost_usd=0.0`, so the running total it checked against
never moved. These tests assert the two things that actually stop an
unbounded bill now: a per-call estimate that is never zero for a model with
real usage, and a counter that persists across separate calls and refuses
once the daily cap is reached.
"""

from __future__ import annotations

import uuid

import pytest

from app.core.assistant.pricing import (
    DEFAULT_USD_PER_1K_TOKENS,
    estimate_cost_usd,
    estimate_tokens,
    price_per_1k_tokens,
)
from app.core.assistant.spend_cap import (
    DailySpendCapExceeded,
    SpendCapTracker,
    _today_key,
)

# --- pricing ---------------------------------------------------------------


def test_a_nonempty_prompt_is_never_estimated_as_zero_tokens() -> None:
    assert estimate_tokens("x") >= 1
    assert estimate_tokens("a reasonably long prompt " * 10) > 1


def test_an_unrecognized_model_is_priced_at_the_conservative_default_not_free() -> None:
    """The failure this guards: `estimated_cost_usd=0.0` on every call, which
    is what `openai_compatible.py` did before pricing.py existed — not an
    estimate, an absent one, which is why the cost budget never moved."""
    assert price_per_1k_tokens("some-future-model-nobody-has-priced-yet") == (
        DEFAULT_USD_PER_1K_TOKENS
    )
    assert estimate_cost_usd("unknown-model-xyz", tokens_sent=1000, tokens_received=1000) > 0


def test_a_known_model_is_priced_from_the_table_not_the_default() -> None:
    cost = estimate_cost_usd("gpt-4o-mini", tokens_sent=1000, tokens_received=0)
    assert cost == pytest.approx(0.00026, rel=0.01)


def test_cost_scales_with_tokens() -> None:
    cheap = estimate_cost_usd("gpt-4o-mini", tokens_sent=100, tokens_received=100)
    expensive = estimate_cost_usd("gpt-4o-mini", tokens_sent=10_000, tokens_received=10_000)
    assert expensive > cheap


# --- cumulative cap ----------------------------------------------------


@pytest.fixture
async def tracker() -> SpendCapTracker:
    """A tracker against the real Redis this test suite already depends on
    (docs/revocation.md's store), cleaned up before and after so one test's
    spend never leaks into the next — the counter is keyed by calendar day,
    not by test, so without this two tests run on the same day would share
    a bucket."""
    instance = SpendCapTracker()
    client = instance._connect()  # noqa: SLF001 - test needs the raw client to reset state
    await client.delete(_today_key())
    yield instance
    await client.delete(_today_key())


async def test_spend_accumulates_across_separate_calls(tracker: SpendCapTracker) -> None:
    """The gap this closes: `platform_egress_context` rebuilds a fresh
    `BudgetTracker` every call, so nothing before this module persisted
    spend *across* interactions — only within one."""
    total_after_first = await tracker.reserve(2.00, cap_usd=10.0)
    total_after_second = await tracker.reserve(3.00, cap_usd=10.0)

    assert total_after_first == pytest.approx(2.00)
    assert total_after_second == pytest.approx(5.00)
    assert await tracker.spent_today() == pytest.approx(5.00)


async def test_a_call_that_would_exceed_the_cap_is_refused(tracker: SpendCapTracker) -> None:
    await tracker.reserve(8.00, cap_usd=10.0)

    with pytest.raises(DailySpendCapExceeded) as excinfo:
        await tracker.reserve(3.00, cap_usd=10.0)

    assert excinfo.value.cap_usd == 10.0
    # Refused, not partially charged: the total the next call is checked
    # against must not include a reservation that was never allowed.
    assert await tracker.spent_today() == pytest.approx(8.00)


async def test_a_call_that_exactly_fits_is_allowed(tracker: SpendCapTracker) -> None:
    await tracker.reserve(7.00, cap_usd=10.0)

    total = await tracker.reserve(3.00, cap_usd=10.0)

    assert total == pytest.approx(10.00)


async def test_two_organizations_share_one_platform_wide_counter(
    tracker: SpendCapTracker,
) -> None:
    """A deliberate scope decision (see spend_cap.py's docstring): this caps
    the operator's own provider bill, which is one bill regardless of which
    organization's assessment triggered the spend, not a per-tenant quota.
    The two calls below stand in for two different organizations' runs and
    are checked against the same total."""
    org_a_run = str(uuid.uuid4())
    org_b_run = str(uuid.uuid4())
    assert org_a_run != org_b_run  # just documents these are different runs

    await tracker.reserve(6.00, cap_usd=10.0)
    total = await tracker.reserve(4.00, cap_usd=10.0)

    assert total == pytest.approx(10.00)
