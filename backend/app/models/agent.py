"""The native AI agent's own configuration and usage records — never its
conversations, prompts, or tool output.

This module is intentionally the **entire**, closed set of tables the agent
subsystem may ever persist: `Agent`, `AgentProvider` here, plus `AgentTool`,
`AgentConfiguration`, `AgentUsageMetadata` added in later phases. Every one
holds configuration or non-content metrics only — never a conversation,
prompt, response, or tool-output value.
`tests/security/test_agent_boundary.py` pins this table set (and grep-checks
every column name) so a future table cannot silently widen it into an AI
memory store.
"""

import enum
import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AgentProviderKind(enum.StrEnum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"
    # Also what a local/self-hosted endpoint (vLLM, Ollama, llama.cpp) uses —
    # they already speak this wire format, so no separate "local" kind exists.
    OPENAI_COMPATIBLE = "openai_compatible"


class AgentProvider(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An organization-configured AI provider the agent may call.

    Multiple rows let an organization use more than one provider, and —
    critically — let an admin point at a local/self-hosted endpoint so
    sensitive data never leaves their own environment: `kind=openai_compatible`
    already covers that case, so "support local models" needs no extra code,
    only this row. `api_key_env_var` is a variable **name**, never a secret
    value — identical discipline to every other credential reference in this
    codebase (`ProviderConfig.api_key_env_var`, a channel's webhook secret).
    """

    __tablename__ = "agent_providers"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[AgentProviderKind] = mapped_column(
        Enum(AgentProviderKind, name="agent_provider_kind_enum"), nullable=False
    )
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    model: Mapped[str] = mapped_column(String(200), nullable=False)
    api_key_env_var: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Agent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One row per organization: whether the native agent is enabled here,
    its default provider, and its default autonomy mode. Never a session,
    a conversation, or anything a user said to it — see this module's
    docstring.
    """

    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_agent_organization"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    default_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_providers.id", ondelete="SET NULL"), nullable=True
    )
    # A string, parsed through the existing `AutonomyMode.parse()` at use
    # time — the same way the platform-wide `ai_autonomy_mode` setting
    # already is, rather than a second DB enum type for the same ladder. An
    # unreadable value is read as OFF, never as a default, matching that
    # setting's own rule.
    autonomy_mode: Mapped[str] = mapped_column(String(30), nullable=False, default="assist")
