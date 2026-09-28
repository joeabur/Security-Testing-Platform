"""The metering flow every `AIProvider` implementation in this package
shares: estimate cost, reserve the daily spend cap, send under
`platform_egress_context`, then reconcile the estimate against real usage.

Extracted once three near-identical copies of this flow existed
(`OpenAICompatibleProvider._complete`, and this package's Anthropic and
Gemini providers) rather than duplicated a third time. Only the wire
format — how a request is built and a response is parsed — is left to
each provider; this module owns the estimate/reserve/send/reconcile
bookkeeping all of them need identically.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass

from app.core.assistant.egress import platform_egress_context
from app.core.assistant.pricing import estimate_cost_usd, estimate_tokens
from app.core.assistant.provider import ProviderConfig, ProviderError
from app.core.assistant.spend_cap import (
    DailySpendCapExceeded,
    SpendCapStoreUnavailable,
    SpendCapTracker,
)
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, Observation, ScopeBlockedError


@dataclass
class MeteredCall:
    ctx: RunContext
    observation: Observation
    estimated_tokens_sent: int
    estimated_tokens_received: int
    estimated_cost_usd: float


async def send_metered(
    config: ProviderConfig,
    transport: GatedTransport,
    spend_cap: SpendCapTracker,
    *,
    url: str,
    headers: dict[str, str],
    body: bytes,
    prompt_text: str,
    system_text: str,
) -> MeteredCall:
    """Estimate, reserve the daily cap, then send under the provider's own
    egress-scoped context. Raises `ProviderError` for every failure mode a
    caller needs to surface — cap exceeded, cap store unreachable, scope
    refusal, transport failure, HTTP >=400 — so no provider implementation
    repeats that handling.
    """
    estimated_sent = estimate_tokens(prompt_text) + estimate_tokens(system_text)
    estimated_received = config.max_output_tokens
    estimated_cost = estimate_cost_usd(
        config.model, tokens_sent=estimated_sent, tokens_received=estimated_received
    )

    try:
        await spend_cap.reserve(estimated_cost)
    except DailySpendCapExceeded as exc:
        raise ProviderError(str(exc)) from exc
    except SpendCapStoreUnavailable as exc:
        # Fails closed, same reasoning as OpenAICompatibleProvider: an
        # unmetered call is the wrong default here.
        raise ProviderError(
            f"could not verify the AI daily spend cap: {exc}. Refusing the call "
            "rather than sending it unmetered."
        ) from exc

    ctx = platform_egress_context(config)
    try:
        observation = await transport.send(
            ctx,
            method="POST",
            url=url,
            headers=headers,
            content=body,
            timeout_seconds=config.timeout_seconds,
            estimated_tokens_sent=estimated_sent,
            estimated_tokens_received=estimated_received,
            estimated_cost_usd=estimated_cost,
        )
    except ScopeBlockedError as exc:
        raise ProviderError(
            f"provider endpoint refused by the scope engine: {exc.decision.reason}"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - surfaced as a provider error
        raise ProviderError(f"provider request failed: {exc}") from exc

    if observation.status_code >= 400:
        raise ProviderError(
            f"provider returned HTTP {observation.status_code}: "
            f"{observation.body[:300].decode('utf-8', errors='replace')}"
        )

    return MeteredCall(ctx, observation, estimated_sent, estimated_received, estimated_cost)


async def reconcile_metered_call(
    call: MeteredCall,
    spend_cap: SpendCapTracker,
    *,
    model: str,
    tokens_sent: int,
    tokens_received: int,
) -> None:
    """Replace the pre-flight estimate with the real usage the response
    reported, in both this interaction's own budget and the cross-call
    daily cap — mirrors `OpenAICompatibleProvider._complete`'s tail."""
    actual_cost = estimate_cost_usd(model, tokens_sent=tokens_sent, tokens_received=tokens_received)
    await call.ctx.budgets.reconcile(
        estimated_tokens_sent=call.estimated_tokens_sent,
        actual_tokens_sent=tokens_sent,
        estimated_tokens_received=call.estimated_tokens_received,
        actual_tokens_received=tokens_received,
        estimated_cost_usd=call.estimated_cost_usd,
        actual_cost_usd=actual_cost,
    )
    cost_delta = actual_cost - call.estimated_cost_usd
    if cost_delta > 0:
        # The call already happened and cannot be unsent; a reconciliation
        # shortfall is best-effort so the caller does not see an error for a
        # response it already has. The next call's own reservation is still
        # checked against the true total.
        with contextlib.suppress(DailySpendCapExceeded, SpendCapStoreUnavailable):
            await spend_cap.reserve(cost_delta)
