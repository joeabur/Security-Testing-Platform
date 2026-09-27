"""An OpenAI-compatible chat-completions provider
(Implementation Specification §9).

Speaks the shape that OpenAI, Azure OpenAI, vLLM, Ollama, llama.cpp and most
gateways all implement, which is why it is the one wire format worth
supporting: it covers hosted and self-hosted without a vendor SDK.

Every request goes through `GatedTransport` under `platform_egress_context`,
so the provider host is the only host this can reach.
"""

import contextlib
import json
from typing import Any

from app.core.assistant.egress import platform_egress_context
from app.core.assistant.pricing import estimate_cost_usd, estimate_tokens
from app.core.assistant.provider import (
    Completion,
    ProviderConfig,
    ProviderError,
    parse_structured,
)
from app.core.assistant.spend_cap import (
    DailySpendCapExceeded,
    SpendCapStoreUnavailable,
    SpendCapTracker,
)
from app.core.scope.transport import GatedTransport, ScopeBlockedError


class OpenAICompatibleProvider:
    """Chat completions over the OpenAI-compatible wire format."""

    def __init__(
        self,
        config: ProviderConfig,
        transport: GatedTransport | None = None,
        *,
        api_key: str | None = None,
        spend_cap: SpendCapTracker | None = None,
    ) -> None:
        self._config = config
        self._transport = transport or GatedTransport()
        # Resolved once, held in memory only, never written anywhere.
        self._api_key = api_key if api_key is not None else config.resolve_key()
        self.name = config.provider
        self.model = config.model
        # Cross-call cumulative cap (app/core/assistant/spend_cap.py); a
        # single tracker per provider instance rather than per call, so a
        # test double injected at construction is honoured on every call.
        self._spend_cap = spend_cap or SpendCapTracker()

    async def generate(self, prompt: str, *, system: str | None = None) -> Completion:
        return await self._complete(prompt, system=system)

    async def structured_output(
        self, prompt: str, *, schema: dict[str, Any], system: str | None = None
    ) -> tuple[dict[str, Any], Completion]:
        instruction = (
            "Reply with a single JSON object and nothing else. Required fields: "
            + ", ".join(schema.get("required", []))
        )
        completion = await self._complete(
            prompt, system=f"{system}\n\n{instruction}" if system else instruction
        )
        return parse_structured(completion.text, schema), completion

    async def _complete(self, prompt: str, *, system: str | None) -> Completion:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        body = json.dumps(
            {
                "model": self._config.model,
                "messages": messages,
                "max_tokens": self._config.max_output_tokens,
                "temperature": self._config.temperature,
            }
        ).encode("utf-8")

        # A pre-flight estimate, not a measurement: this is what makes the
        # per-interaction `max_estimated_cost_usd` budget (egress.py) and
        # the cross-call daily cap (spend_cap.py) mean something, since
        # neither has the real token counts until the provider responds.
        estimated_sent = estimate_tokens(prompt) + estimate_tokens(system or "")
        estimated_received = self._config.max_output_tokens
        estimated_cost = estimate_cost_usd(
            self._config.model, tokens_sent=estimated_sent, tokens_received=estimated_received
        )

        try:
            await self._spend_cap.reserve(estimated_cost)
        except DailySpendCapExceeded as exc:
            raise ProviderError(str(exc)) from exc
        except SpendCapStoreUnavailable as exc:
            # Fails closed: see spend_cap.py's docstring for why an
            # unmetered provider call is the wrong default here, unlike the
            # rate limiter's fail-open choice for a login attempt.
            raise ProviderError(
                f"could not verify the AI daily spend cap: {exc}. Refusing the call "
                "rather than sending it unmetered."
            ) from exc

        ctx = platform_egress_context(self._config)
        try:
            observation = await self._transport.send(
                ctx,
                method="POST",
                url=self._config.endpoint,
                headers=headers,
                content=body,
                timeout_seconds=self._config.timeout_seconds,
                estimated_tokens_sent=estimated_sent,
                estimated_tokens_received=estimated_received,
                estimated_cost_usd=estimated_cost,
            )
        except ScopeBlockedError as exc:
            # The provider endpoint failed the same checks a target would.
            # Reported rather than worked around: an endpoint resolving to a
            # blocked address is a configuration problem worth seeing.
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

        completion = self._parse(observation.body)

        # Now that the real usage is known, replace the pre-flight
        # estimates with it — both in this interaction's own budget
        # (`reconcile`, which adjusts the running total by the delta rather
        # than re-validating a call that already happened) and in the
        # cross-call daily counter, whose reservation above was necessarily
        # the estimate too.
        actual_cost = estimate_cost_usd(
            self._config.model,
            tokens_sent=completion.tokens_sent,
            tokens_received=completion.tokens_received,
        )
        await ctx.budgets.reconcile(
            estimated_tokens_sent=estimated_sent,
            actual_tokens_sent=completion.tokens_sent,
            estimated_tokens_received=estimated_received,
            actual_tokens_received=completion.tokens_received,
            estimated_cost_usd=estimated_cost,
            actual_cost_usd=actual_cost,
        )
        cost_delta = actual_cost - estimated_cost
        if cost_delta > 0:
            # The call already happened and cannot be unsent; a
            # reconciliation shortfall here is recorded as best-effort
            # rather than raised, so the caller does not see an error for a
            # response it already has. The next call's pre-flight
            # reservation is still checked against the true total.
            with contextlib.suppress(DailySpendCapExceeded, SpendCapStoreUnavailable):
                await self._spend_cap.reserve(cost_delta)

        return completion

    def _parse(self, raw: bytes) -> Completion:
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise ProviderError(f"provider response was not JSON: {exc}") from exc

        choices = payload.get("choices") or []
        if not choices:
            raise ProviderError("provider response contained no choices")
        text = str(choices[0].get("message", {}).get("content", ""))

        usage = payload.get("usage") or {}
        return Completion(
            text=text,
            model=str(payload.get("model", self._config.model)),
            tokens_sent=int(usage.get("prompt_tokens", 0) or 0),
            tokens_received=int(usage.get("completion_tokens", 0) or 0),
            # Cost is reported only where the provider reports it. An
            # estimate presented as a measurement is the kind of number that
            # ends up in a budget review as though it were real.
            cost_usd=None,
        )
