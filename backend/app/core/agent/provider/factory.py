"""Building a concrete `AIProvider` from an `AgentProvider` database row.

Unlike `app.core.assistant.factory` (one provider, chosen from a global
setting), this picks per-call from an organization's own configured
`AgentProvider` rows — the mechanism behind "support multiple AI
providers... do not tightly couple the platform to one provider."
"""

from __future__ import annotations

from collections.abc import Callable

from app.core.agent.provider.anthropic import AnthropicProvider
from app.core.agent.provider.gemini import GeminiProvider
from app.core.assistant.openai_compatible import OpenAICompatibleProvider
from app.core.assistant.provider import AIProvider, ProviderConfig
from app.models.agent import AgentProvider, AgentProviderKind

_BUILDERS: dict[AgentProviderKind, Callable[[ProviderConfig], AIProvider]] = {
    AgentProviderKind.ANTHROPIC: AnthropicProvider,
    AgentProviderKind.GEMINI: GeminiProvider,
    # OpenAI's own chat-completions API is itself OpenAI-compatible by
    # definition, so both kinds share the one existing wire-format
    # implementation rather than a duplicate.
    AgentProviderKind.OPENAI: OpenAICompatibleProvider,
    AgentProviderKind.OPENAI_COMPATIBLE: OpenAICompatibleProvider,
}


def build_provider(row: AgentProvider) -> AIProvider:
    config = ProviderConfig(
        provider=row.kind.value,
        endpoint=row.endpoint,
        model=row.model,
        api_key_env_var=row.api_key_env_var,
    )
    builder = _BUILDERS[row.kind]
    return builder(config)
