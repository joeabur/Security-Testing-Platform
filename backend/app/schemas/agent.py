"""Native AI agent API shapes.

`InvestigationRead` is the one response shape both `POST .../investigate`
and `POST .../investigate/{id}/approve` return — a caller does not need to
know which endpoint it came from to render it, and there is only one
"what does an investigation look like" answer to keep consistent.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.agent import AgentProviderKind


def _validated_cidrs(value: list[str]) -> list[str]:
    for cidr in value:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"{cidr!r} is not a valid CIDR range") from exc
    return value


class InvestigateRequest(BaseModel):
    request: str = Field(min_length=1, max_length=4000)


class ApproveRequest(BaseModel):
    """Empty today — the pending tool and its arguments are already fixed
    by the plan that paused (see `session_store.py`). A body exists so the
    endpoint can grow an optional field (a reviewer's note) without a
    breaking change."""

    model_config = ConfigDict(extra="forbid")


class CallToolRequest(BaseModel):
    """The body for `POST .../tools/{tool_name}/call` — the direct,
    single-tool surface `backend/mcp_server/` calls. `params` is validated
    against that specific tool's own input model inside `Tool.invoke`, not
    here, so this schema stays the same for every tool."""

    model_config = ConfigDict(extra="forbid")

    params: dict[str, Any] = Field(default_factory=dict)


class ToolCatalogEntry(BaseModel):
    name: str
    description: str
    risk_level: Literal["read_only", "standard", "sensitive"]
    minimum_role: str
    input_schema: dict[str, Any] = Field(default_factory=dict)


class PendingApprovalRead(BaseModel):
    tool_name: str
    risk_level: Literal["read_only", "standard", "sensitive"]
    description: str


class StepOutcomeRead(BaseModel):
    tool_name: str
    status: Literal[
        "ok", "tool_not_found", "permission_denied", "approval_required", "execution_error"
    ]
    result: dict[str, Any] | None = None
    error: str | None = None
    duration_ms: int = 0


class InvestigationRead(BaseModel):
    investigation_id: uuid.UUID
    status: Literal["running", "awaiting_approval", "completed", "cancelled", "failed"]
    outcomes: list[StepOutcomeRead] = Field(default_factory=list)
    summary: str | None = None
    pending_approval: PendingApprovalRead | None = None


class AgentProviderCreate(BaseModel):
    """`api_key_env_var` is the *name* of an environment variable the
    deployment operator has set on the backend/worker process — never a
    key value. This body never carries a secret."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    kind: AgentProviderKind
    endpoint: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=200)
    api_key_env_var: str | None = Field(default=None, max_length=128)
    # CIDR strings this provider's endpoint is explicitly authorized to
    # resolve to if it is a private/loopback address — required for a
    # self-hosted `openai_compatible` endpoint (Ollama, vLLM, llama.cpp),
    # which almost always lives at exactly such an address. See
    # app/core/assistant/egress.py::platform_egress_context.
    allowed_ip_ranges: list[str] = Field(default_factory=list)
    # True by default: creating an organization's first provider should not
    # need a second call just to make the agent usable — this is what
    # closes the "agent is fully built but nothing can ever configure it"
    # gap. Set false to add a provider without disturbing the current
    # default.
    is_default: bool = True

    @field_validator("allowed_ip_ranges")
    @classmethod
    def _validate_cidrs(cls, value: list[str]) -> list[str]:
        return _validated_cidrs(value)


class AgentProviderUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    endpoint: str | None = Field(default=None, min_length=1, max_length=2048)
    model: str | None = Field(default=None, min_length=1, max_length=200)
    api_key_env_var: str | None = Field(default=None, max_length=128)
    allowed_ip_ranges: list[str] | None = None
    enabled: bool | None = None
    is_default: bool | None = None

    @field_validator("allowed_ip_ranges")
    @classmethod
    def _validate_cidrs(cls, value: list[str] | None) -> list[str] | None:
        return value if value is None else _validated_cidrs(value)


class AgentProviderRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: AgentProviderKind
    endpoint: str
    model: str
    api_key_env_var: str | None
    allowed_ip_ranges: list[str]
    is_default: bool
    enabled: bool


class AgentUpdate(BaseModel):
    """Enable/disable the native agent for an organization and choose its
    default provider and autonomy mode. Idempotent: `PUT .../agent` creates
    the organization's one `Agent` row if it does not exist yet, or updates
    it if it does — there is exactly one per organization
    (`uq_agent_organization`)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    default_provider_id: uuid.UUID | None = None
    # Validated against the real `AutonomyMode.parse()` in the router
    # (`app/api/v1/routers/agent.py`), not here: `app/core/assistant` is
    # off limits to every module outside `app/core/assistant/`, `app/core/
    # agent/`, and `app/api/` (tests/security/test_assistant_boundary.py),
    # and this schema module is none of those.
    autonomy_mode: str = "assist"


class AgentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    enabled: bool
    default_provider_id: uuid.UUID | None
    autonomy_mode: str
