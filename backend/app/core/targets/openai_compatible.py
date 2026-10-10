"""`openai_compatible` — targets speaking the `/v1/chat/completions` or
`/v1/responses` shapes (docs/BUILD_SPEC.md §8).

The reason this is a distinct adapter rather than a `chat_http` template is
token accounting: these APIs report real usage, and §6.2 requires budgets to
use provider-reported usage when it is available instead of an estimate.
This adapter feeds that number straight back into the run's
`BudgetTracker.reconcile()`, so the pre-flight estimate is replaced by the
truth before the next request is checked.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urljoin

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport
from app.core.targets import jsonpath
from app.core.targets.models import Capabilities, TargetResponse, TokenUsage, Turn
from app.core.targets.tokens import estimate_tokens

Shape = Literal["chat_completions", "responses"]

_DEFAULTS: dict[Shape, tuple[str, str]] = {
    # shape -> (default endpoint, default extraction path)
    "chat_completions": ("/v1/chat/completions", "$.choices[0].message.content"),
    "responses": ("/v1/responses", "$.output[0].content[0].text"),
}


@dataclass(frozen=True)
class OpenAiCompatibleConfig:
    base_url: str
    model: str
    shape: Shape = "chat_completions"
    endpoint: str | None = None
    system_prompt: str | None = None
    temperature: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    response_path: str | None = None

    def resolved_endpoint(self) -> str:
        return self.endpoint or _DEFAULTS[self.shape][0]

    def resolved_response_path(self) -> str:
        return self.response_path or _DEFAULTS[self.shape][1]

    def __post_init__(self) -> None:
        if self.shape not in _DEFAULTS:
            raise ValueError(f"unknown shape {self.shape!r}")
        jsonpath.validate_path(self.resolved_response_path())


class OpenAiCompatibleAdapter:
    id = "openai_compatible"

    def __init__(
        self, config: OpenAiCompatibleConfig, transport: GatedTransport | None = None
    ) -> None:
        self._config = config
        self._transport = transport or GatedTransport()

    async def capabilities(self) -> Capabilities:
        return Capabilities(
            streaming=True,
            tools=self._config.shape == "chat_completions",
            multi_turn=True,
            system_prompt_control=True,
        )

    async def reset(self) -> None:
        return None

    async def send(
        self, turn: Turn, ctx: RunContext, *, extra_headers: Mapping[str, str] | None = None
    ) -> TargetResponse:
        url = urljoin(self._config.base_url, self._config.resolved_endpoint())
        body = self._build_body(turn)
        payload = json.dumps(body).encode("utf-8")

        estimated_sent = estimate_tokens(turn.content) + estimate_tokens(
            self._config.system_prompt or ""
        )
        observation = await self._transport.send(
            ctx,
            method="POST",
            url=url,
            headers={
                "Content-Type": "application/json",
                **self._config.headers,
                **(extra_headers or {}),
            },
            content=payload,
            estimated_tokens_sent=estimated_sent,
        )

        parsed = _parse_json(observation.body)
        text = None
        usage = None
        if parsed is not None:
            value = jsonpath.extract(parsed, self._config.resolved_response_path())
            text = value if isinstance(value, str) else None
            usage = _parse_usage(parsed)

        if usage is not None:
            # Replace the pre-flight estimate with what the provider actually
            # charged, so the next budget check is made against real numbers.
            await ctx.budgets.reconcile(
                estimated_tokens_sent=estimated_sent,
                actual_tokens_sent=usage.tokens_sent,
                estimated_tokens_received=0,
                actual_tokens_received=usage.tokens_received,
            )

        return TargetResponse(observation=observation, text=text, usage=usage)

    def _build_body(self, turn: Turn) -> dict[str, Any]:
        if self._config.shape == "responses":
            body: dict[str, Any] = {"model": self._config.model, "input": turn.content}
            if self._config.system_prompt:
                body["instructions"] = self._config.system_prompt
        else:
            messages: list[dict[str, str]] = []
            if self._config.system_prompt:
                messages.append({"role": "system", "content": self._config.system_prompt})
            messages.append({"role": turn.role, "content": turn.content})
            body = {"model": self._config.model, "messages": messages}

        if self._config.temperature is not None:
            body["temperature"] = self._config.temperature
        return body


def _parse_json(body: bytes) -> Any | None:
    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _parse_usage(parsed: Any) -> TokenUsage | None:
    """Read the `usage` block from either API shape.

    `chat/completions` reports `prompt_tokens`/`completion_tokens`;  # pragma: allowlist secret
    `responses` reports `input_tokens`/`output_tokens`. Both are accepted
    regardless of configured shape, since self-hosted "OpenAI-compatible"
    servers are inconsistent about which they emit.
    """
    if not isinstance(parsed, dict):
        return None
    usage = parsed.get("usage")
    if not isinstance(usage, dict):
        return None

    sent = usage.get("prompt_tokens", usage.get("input_tokens"))
    received = usage.get("completion_tokens", usage.get("output_tokens"))
    if not isinstance(sent, int) or not isinstance(received, int):
        return None
    return TokenUsage(tokens_sent=sent, tokens_received=received)
