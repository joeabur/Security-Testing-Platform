"""The native AI agent's own configuration and usage records — never its
conversations, prompts, or tool output.

This module is intentionally the **entire**, closed set of tables the agent
subsystem may ever persist: `Agent`, `AgentProvider`, `AgentTool`,
`AgentConfiguration`, `AgentUsageMetadata`. Every one holds configuration or
non-content metrics only — never a conversation, prompt, response, or
tool-output value.
`tests/security/test_agent_boundary.py` pins this table set (and grep-checks
every column name) so a future table cannot silently widen it into an AI
memory store.
"""

import enum
import uuid
from typing import Any

from sqlalchemy import JSON, Boolean, Enum, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AgentTool(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Per-organization enable/disable (and, optionally, a tighter role
    requirement) for a tool the *code* registry
    (`app/core/agent/tools/registry.py`) defines. Code is the source of
    truth for a tool's input/output schema, risk level, and logic — this
    table is configuration only, the same relationship `Workflow.enabled`
    has to the workflow engine's own fixed `ActionKind` set.

    `minimum_role_override` is inert until the permission check that will
    read it exists (a later phase); when it does, it may only ever raise a
    tool's effective minimum role above the code default, never lower it.
    """

    __tablename__ = "agent_tools"
    __table_args__ = (
        UniqueConstraint("organization_id", "tool_name", name="uq_agent_tool_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    minimum_role_override: Mapped[str | None] = mapped_column(String(30), nullable=True)


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


class AgentConfiguration(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Fine-grained runtime policy for one `Agent`: which tools it may use
    and any per-tool rate-limit override — configuration only, read by
    `permissions.py` and the future planner, never written to from a tool
    call or a conversation.

    `settings` is a small, schema-validated JSON document
    (`AgentConfigurationSettings` in a later phase), not free text — it
    holds structured policy, the same way `Workflow.gate_config` holds a
    structured gate rather than a prose description of one.
    """

    __tablename__ = "agent_configurations"
    __table_args__ = (UniqueConstraint("agent_id", name="uq_agent_configuration_agent"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class AgentUsageMetadata(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One append-only row per tool call: what ran, how long it took, what
    it cost, and whether it succeeded — the observability requirement.

    No `content`/`text`-shaped column exists on this model, and none may
    ever be added — `tests/security/test_agent_boundary.py`'s
    column-allowlist test enforces that deliberately, on this table
    specifically, because a metrics table is exactly where a well-meaning
    "let's also log the response for debugging" column tends to appear.
    """

    __tablename__ = "agent_usage_metadata"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"), nullable=True
    )
    tool_name: Mapped[str] = mapped_column(String(120), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(60), nullable=True)
    model: Mapped[str | None] = mapped_column(String(200), nullable=True)
    tokens_sent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tokens_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    request_id: Mapped[str] = mapped_column(String(80), nullable=False)
