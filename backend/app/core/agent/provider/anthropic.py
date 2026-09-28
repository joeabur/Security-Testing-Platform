"""An Anthropic Messages API provider (native, not OpenAI-compatible).

Same metering/egress discipline as every provider in this codebase
(`app/core/agent/provider/metering.py`) — only the wire format differs:
Anthropic's Messages API takes `system` as a top-level field rather than a
message with role "system", authenticates via the `x-api-key` header
(never a query parameter — this codebase never puts a credential where it
could end up in a logged URL), and reports usage as `input_tokens`/
`output_tokens` rather than `prompt_tokens`/`completion_tokens`.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.agent.provider.metering import reconcile_metered_call, send_metered
from app.core.assistant.provider import (
    Completion,
    ProviderConfig,
    ProviderError,
    parse_structured,
)
from app.core.assistant.spend_cap import SpendCapTracker
from app.core.scope.transport import GatedTransport

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider:
    """Chat completions over Anthropic's native Messages API."""

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
        headers = {"Content-Type": "application/json", "anthropic-version": ANTHROPIC_VERSION}
        if self._api_key:
            headers["x-api-key"] = self._api_key

        payload: dict[str, Any] = {
            "model": self._config.model,
            "max_tokens": self._config.max_output_tokens,
            "temperature": self._config.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system
        body = json.dumps(payload).encode("utf-8")

        call = await send_metered(
            self._config,
            self._transport,
            self._spend_cap,
            url=self._config.endpoint,
            headers=headers,
            body=body,
            prompt_text=prompt,
            system_text=system or "",
        )
        completion = self._parse(call.observation.body)
        await reconcile_metered_call(
            call,
            self._spend_cap,
            model=self._config.model,
            tokens_sent=completion.tokens_sent,
            tokens_received=completion.tokens_received,
        )
        return completion

    def _parse(self, raw: bytes) -> Completion:
        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise ProviderError(f"provider response was not JSON: {exc}") from exc

        blocks = payload.get("content") or []
        text = "".join(
            str(block.get("text", ""))
            for block in blocks
            if isinstance(block, dict) and block.get("type") == "text"
        )
        if not blocks:
            raise ProviderError("provider response contained no content")

        usage = payload.get("usage") or {}
        return Completion(
            text=text,
            model=str(payload.get("model", self._config.model)),
            tokens_sent=int(usage.get("input_tokens", 0) or 0),
            tokens_received=int(usage.get("output_tokens", 0) or 0),
            # Cost is reported only where the provider reports it — never
            # estimated and presented as measured.
            cost_usd=None,
        )
