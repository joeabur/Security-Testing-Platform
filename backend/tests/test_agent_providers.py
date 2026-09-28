"""`app.core.agent.provider` — the Anthropic and Gemini `AIProvider`
implementations, and the factory that picks one from an `AgentProvider` row.

Mirrors `test_openai_compatible_cost_accounting.py`'s doubles: a
`RecordingTransport` standing in for `GatedTransport` so these tests prove
what reached the transport (headers, body shape, metering) without a real
network call, and an always-allow spend cap so the tests are about the
wire format and metering wiring, not the cap itself.
"""

from __future__ import annotations

import json

import pytest

from app.core.agent.provider.anthropic import AnthropicProvider
from app.core.agent.provider.factory import build_provider
from app.core.agent.provider.gemini import GeminiProvider
from app.core.assistant.openai_compatible import OpenAICompatibleProvider
from app.core.assistant.provider import ProviderConfig, ProviderError
from app.core.scope.transport import Observation
from app.models.agent import AgentProvider, AgentProviderKind

ANTHROPIC_CONFIG = ProviderConfig(
    provider="anthropic",
    endpoint="https://api.anthropic.test/v1/messages",
    model="claude-sonnet",
    max_output_tokens=256,
)
GEMINI_CONFIG = ProviderConfig(
    provider="gemini",
    endpoint="https://generativelanguage.googleapis.test/v1beta/models/gemini:generateContent",
    model="gemini",
    max_output_tokens=256,
)


class RecordingTransport:
    """Stands in for `GatedTransport`; records what it was asked to send and
    returns a canned response built by the test."""

    def __init__(self, body: bytes, *, status_code: int = 200) -> None:
        self.calls: list[dict[str, object]] = []
        self._body = body
        self._status_code = status_code

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append({"ctx": ctx, **kwargs})
        await ctx.budgets.reserve(  # type: ignore[attr-defined]
            estimated_tokens_sent=int(kwargs.get("estimated_tokens_sent", 0)),  # type: ignore[arg-type]
            estimated_tokens_received=int(kwargs.get("estimated_tokens_received", 0)),  # type: ignore[arg-type]
            estimated_cost_usd=float(kwargs.get("estimated_cost_usd", 0.0)),  # type: ignore[arg-type]
        )
        return Observation(
            method="POST",
            url=str(kwargs.get("url")),
            status_code=self._status_code,
            headers={},
            elapsed_ms=1.0,
            body=self._body,
        )


class _AlwaysAllowSpendCap:
    async def reserve(self, cost_usd: float, *, cap_usd: float | None = None) -> float:
        return cost_usd


def _anthropic_body(text: str = "hello") -> bytes:
    return json.dumps(
        {
            "model": "claude-sonnet",
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 40, "output_tokens": 20},
        }
    ).encode()


def _gemini_body(text: str = "hello") -> bytes:
    return json.dumps(
        {
            "candidates": [{"content": {"parts": [{"text": text}]}}],
            "usageMetadata": {"promptTokenCount": 40, "candidatesTokenCount": 20},
        }
    ).encode()


# --- Anthropic ---------------------------------------------------------


async def test_anthropic_sends_the_native_messages_shape_and_x_api_key_header() -> None:
    transport = RecordingTransport(_anthropic_body())
    provider = AnthropicProvider(
        ANTHROPIC_CONFIG, transport=transport, api_key="sk-test", spend_cap=_AlwaysAllowSpendCap()
    )

    completion = await provider.generate("explain this finding", system="be concise")

    assert completion.text == "hello"
    assert completion.tokens_sent == 40
    assert completion.tokens_received == 20
    call = transport.calls[0]
    assert call["headers"]["x-api-key"] == "sk-test"  # type: ignore[index]
    assert "Authorization" not in call["headers"]  # type: ignore[operator]
    body = json.loads(call["content"])  # type: ignore[arg-type]
    assert body["system"] == "be concise"
    assert body["messages"] == [{"role": "user", "content": "explain this finding"}]
    # The key never ends up in the URL — never a query parameter.
    assert "sk-test" not in str(call["url"])


async def test_anthropic_raises_on_an_http_error_status() -> None:
    transport = RecordingTransport(b'{"error": "nope"}', status_code=401)
    provider = AnthropicProvider(
        ANTHROPIC_CONFIG, transport=transport, api_key="sk-test", spend_cap=_AlwaysAllowSpendCap()
    )

    with pytest.raises(ProviderError, match="401"):
        await provider.generate("hello")


async def test_anthropic_structured_output_parses_json() -> None:
    transport = RecordingTransport(_anthropic_body('{"summary": "ok"}'))
    provider = AnthropicProvider(
        ANTHROPIC_CONFIG, transport=transport, api_key="sk-test", spend_cap=_AlwaysAllowSpendCap()
    )

    parsed, completion = await provider.structured_output(
        "summarize", schema={"required": ["summary"]}
    )

    assert parsed == {"summary": "ok"}
    assert completion.text == '{"summary": "ok"}'


# --- Gemini --------------------------------------------------------------


async def test_gemini_sends_the_native_generatecontent_shape_and_header_key() -> None:
    transport = RecordingTransport(_gemini_body())
    provider = GeminiProvider(
        GEMINI_CONFIG, transport=transport, api_key="AIza-test", spend_cap=_AlwaysAllowSpendCap()
    )

    completion = await provider.generate("explain this finding", system="be concise")

    assert completion.text == "hello"
    assert completion.tokens_sent == 40
    assert completion.tokens_received == 20
    call = transport.calls[0]
    assert call["headers"]["x-goog-api-key"] == "AIza-test"  # type: ignore[index]
    body = json.loads(call["content"])  # type: ignore[arg-type]
    assert body["contents"] == [{"role": "user", "parts": [{"text": "explain this finding"}]}]
    assert body["systemInstruction"] == {"parts": [{"text": "be concise"}]}
    # The key never ends up in the URL — never the `?key=` query-param form.
    assert "AIza-test" not in str(call["url"])


async def test_gemini_raises_when_there_are_no_candidates() -> None:
    transport = RecordingTransport(json.dumps({"candidates": []}).encode())
    provider = GeminiProvider(
        GEMINI_CONFIG, transport=transport, api_key="AIza-test", spend_cap=_AlwaysAllowSpendCap()
    )

    with pytest.raises(ProviderError, match="no candidates"):
        await provider.generate("hello")


# --- factory ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "expected_type"),
    [
        (AgentProviderKind.ANTHROPIC, AnthropicProvider),
        (AgentProviderKind.GEMINI, GeminiProvider),
        (AgentProviderKind.OPENAI, OpenAICompatibleProvider),
        (AgentProviderKind.OPENAI_COMPATIBLE, OpenAICompatibleProvider),
    ],
)
def test_build_provider_dispatches_on_kind(kind: AgentProviderKind, expected_type: type) -> None:
    row = AgentProvider(
        organization_id=None,
        name="test",
        kind=kind,
        endpoint="https://provider.example.test/v1",
        model="some-model",
        api_key_env_var=None,
    )

    provider = build_provider(row)

    assert isinstance(provider, expected_type)
    assert provider.model == "some-model"
