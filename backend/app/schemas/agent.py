"""Native AI agent API shapes.

`InvestigationRead` is the one response shape both `POST .../investigate`
and `POST .../investigate/{id}/approve` return — a caller does not need to
know which endpoint it came from to render it, and there is only one
"what does an investigation look like" answer to keep consistent.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


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
