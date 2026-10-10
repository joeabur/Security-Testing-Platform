"""`chat_http` — an arbitrary HTTP chat endpoint described by a JSON request
template and a JSONPath response extractor (docs/BUILD_SPEC.md §8).

This is the adapter most operators will reach for first, because it makes no
assumptions about the target's wire format beyond "it speaks JSON over HTTP".
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport
from app.core.targets import jsonpath
from app.core.targets.models import Capabilities, TargetResponse, Turn
from app.core.targets.tokens import estimate_tokens

PROMPT_PLACEHOLDER = "{{prompt}}"


@dataclass(frozen=True)
class ChatHttpConfig:
    base_url: str
    endpoint: str = "/api/chat"
    method: str = "POST"
    request_template: dict[str, Any] = field(
        default_factory=lambda: {"message": PROMPT_PLACEHOLDER}
    )
    response_path: str = "$.message.content"
    headers: dict[str, str] = field(default_factory=dict)
    multi_turn: bool = False

    def __post_init__(self) -> None:
        # Fail at configuration time, not mid-scan.
        jsonpath.validate_path(self.response_path)
        if PROMPT_PLACEHOLDER not in json.dumps(self.request_template):
            raise ValueError(
                f"request_template must contain the {PROMPT_PLACEHOLDER} placeholder somewhere"
            )


def render_template(template: Any, prompt: str) -> Any:
    """Substitute the prompt into every string in the template.

    Substitution happens on the already-parsed JSON structure rather than on
    raw template text, so a prompt containing quotes or braces cannot break
    out of its string and alter the request's shape — the adversarial inputs
    this tool sends are exactly the kind that would.
    """
    if isinstance(template, str):
        return template.replace(PROMPT_PLACEHOLDER, prompt)
    if isinstance(template, dict):
        return {key: render_template(value, prompt) for key, value in template.items()}
    if isinstance(template, list):
        return [render_template(item, prompt) for item in template]
    return template


class ChatHttpAdapter:
    id = "chat_http"

    def __init__(self, config: ChatHttpConfig, transport: GatedTransport | None = None) -> None:
        self._config = config
        self._transport = transport or GatedTransport()

    async def capabilities(self) -> Capabilities:
        return Capabilities(
            streaming=False,
            tools=False,
            multi_turn=self._config.multi_turn,
            system_prompt_control=False,
        )

    async def reset(self) -> None:
        """No conversation state is held: each `send` is an independent
        request. Targets that keep server-side session state need that state
        cleared by the operator's own means, which is recorded as a
        limitation rather than silently assumed away."""
        return None

    async def send(
        self, turn: Turn, ctx: RunContext, *, extra_headers: Mapping[str, str] | None = None
    ) -> TargetResponse:
        url = urljoin(self._config.base_url, self._config.endpoint)
        body = render_template(self._config.request_template, turn.content)
        payload = json.dumps(body).encode("utf-8")

        estimated_sent = estimate_tokens(turn.content)
        observation = await self._transport.send(
            ctx,
            method=self._config.method,
            url=url,
            headers={
                "Content-Type": "application/json",
                **self._config.headers,
                **(extra_headers or {}),
            },
            content=payload,
            estimated_tokens_sent=estimated_sent,
        )

        text = _extract_text(observation.body, self._config.response_path)
        return TargetResponse(observation=observation, text=text)


def _extract_text(body: bytes, response_path: str) -> str | None:
    if not body:
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    value = jsonpath.extract(parsed, response_path)
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value)
