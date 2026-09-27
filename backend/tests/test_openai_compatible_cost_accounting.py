"""`OpenAICompatibleProvider` actually meters what it spends.

Before this wiring, `_complete` called `GatedTransport.send()` without
`estimated_tokens_sent`, `estimated_tokens_received`, or `estimated_cost_usd`
— every one defaulted to `0.0`/`0`, so `PROVIDER_BUDGETS.max_estimated_cost_
usd` (egress.py) never actually moved and the per-interaction cap it names
was cosmetic. These tests assert the estimate reaches the transport, that
the real per-interaction budget then reflects the call, and that the
cross-call daily cap (spend_cap.py) is consulted before every request and
actually stops one once the day's total is reached.
"""

from __future__ import annotations

import json

import pytest

from app.core.assistant.openai_compatible import OpenAICompatibleProvider
from app.core.assistant.provider import ProviderConfig, ProviderError
from app.core.assistant.spend_cap import DailySpendCapExceeded
from app.core.scope.transport import Observation

CONFIG = ProviderConfig(
    provider="openai_compatible",
    endpoint="https://api.example.test/v1/chat/completions",
    model="gpt-4o-mini",
    max_output_tokens=256,
)


class RecordingTransport:
    """Stands in for `GatedTransport`; records what it was asked to send and
    returns a canned OpenAI-shaped completion."""

    def __init__(self, tokens_sent: int = 40, tokens_received: int = 20) -> None:
        self.calls: list[dict[str, object]] = []
        self._tokens_sent = tokens_sent
        self._tokens_received = tokens_received

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append({"ctx": ctx, **kwargs})
        # The real `GatedTransport.send()` reserves the pre-flight estimate
        # against `ctx.budgets` before the request goes out (via the scope
        # engine's own check); `reconcile()` afterwards then adjusts that
        # reservation by the delta to the real usage. This double has to do
        # the same reservation, or `reconcile()` has nothing to adjust
        # *from* and its delta lands on a budget that still reads zero.
        await ctx.budgets.reserve(  # type: ignore[attr-defined]
            estimated_tokens_sent=int(kwargs.get("estimated_tokens_sent", 0)),  # type: ignore[arg-type]
            estimated_tokens_received=int(kwargs.get("estimated_tokens_received", 0)),  # type: ignore[arg-type]
            estimated_cost_usd=float(kwargs.get("estimated_cost_usd", 0.0)),  # type: ignore[arg-type]
        )
        body = json.dumps(
            {
                "model": "gpt-4o-mini",
                "choices": [{"message": {"content": "hello"}}],
                "usage": {
                    "prompt_tokens": self._tokens_sent,
                    "completion_tokens": self._tokens_received,
                },
            }
        ).encode()
        return Observation(
            method="POST",
            url=str(kwargs.get("url")),
            status_code=200,
            headers={},
            elapsed_ms=1.0,
            body=body,
        )


class _AlwaysAllowSpendCap:
    """A double that never refuses, for tests about the transport call
    shape rather than the cap itself."""

    async def reserve(self, cost_usd: float, *, cap_usd: float | None = None) -> float:
        return cost_usd


class _AlwaysRefuseSpendCap:
    async def reserve(self, cost_usd: float, *, cap_usd: float | None = None) -> float:
        raise DailySpendCapExceeded(cap_usd or 0.0, 999.0)


async def test_a_call_reaches_the_transport_with_a_nonzero_cost_estimate() -> None:
    transport = RecordingTransport()
    provider = OpenAICompatibleProvider(
        CONFIG, transport=transport, spend_cap=_AlwaysAllowSpendCap()
    )

    await provider.generate("summarize this finding")

    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["estimated_tokens_sent"] > 0
    assert call["estimated_tokens_received"] == CONFIG.max_output_tokens
    # The bug this closes: this used to always be 0.0.
    assert call["estimated_cost_usd"] > 0


async def test_the_per_interaction_budget_is_actually_charged() -> None:
    """`reconcile()` replaces the pre-flight estimate with the real usage
    the response reported — this proves that adjustment lands on the same
    `RunContext` the call was made under, not discarded."""
    transport = RecordingTransport(tokens_sent=1000, tokens_received=500)
    provider = OpenAICompatibleProvider(
        CONFIG, transport=transport, spend_cap=_AlwaysAllowSpendCap()
    )

    await provider.generate("summarize this finding")

    ctx = transport.calls[0]["ctx"]
    # Internal state, but the only way to observe that reconcile() actually
    # ran rather than the estimate being silently discarded after the call.
    assert ctx.budgets._tokens_sent == 1000  # noqa: SLF001
    assert ctx.budgets._tokens_received == 500  # noqa: SLF001
    assert ctx.budgets._cost_used_usd > 0  # noqa: SLF001


async def test_a_call_that_would_exceed_the_daily_cap_is_refused_before_sending() -> None:
    transport = RecordingTransport()
    provider = OpenAICompatibleProvider(
        CONFIG, transport=transport, spend_cap=_AlwaysRefuseSpendCap()
    )

    with pytest.raises(ProviderError, match="daily cap"):
        await provider.generate("summarize this finding")

    # Refused before the network call, not after: the transport never saw it.
    assert transport.calls == []
