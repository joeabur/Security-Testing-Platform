"""Workflow API shapes (docs/BUILD_SPEC.md §26 Phase 17).

The gate configuration is the only field here that carries real risk, and it is
handled the way the CLI gate handles it: validated on write through
`load_config`, so a malformed gate is rejected at the point somebody typed it
rather than at the point it was supposed to block a release. A gate that cannot
be parsed must never be read as "no gate".
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.gate.model import GateConfigError
from app.core.workflow.contract import TriggerKind

#: A schedule tighter than this would mean unattended, repeated scanning of
#: a live target every few minutes — a stated, explicit safety rail, not an
#: arbitrary number. Matches the reasoning behind every other minimum this
#: platform enforces on an automated, target-touching capability.
MIN_SCHEDULE_INTERVAL_MINUTES = 60


class WorkflowCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target_id: uuid.UUID
    trigger_kind: TriggerKind = TriggerKind.REPOSITORY_CHANGE
    enabled: bool = True
    gate_config: dict[str, Any] | None = None
    #: Only meaningful when `trigger_kind == "schedule"`. Left `None` (the
    #: default), this workflow is simply never picked up by
    #: `dispatch_scheduled_workflows` — silence is the inert state, not a
    #: rejected configuration, the same rule `PentestScope`'s own absence
    #: already follows.
    schedule_interval_minutes: int | None = Field(default=None, ge=MIN_SCHEDULE_INTERVAL_MINUTES)

    @field_validator("gate_config")
    @classmethod
    def _gate_config_must_parse(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        from app.core.gate.evaluate import load_config

        try:
            load_config(json.dumps(value))
        except GateConfigError as exc:
            raise ValueError(f"gate configuration is invalid: {exc}") from exc
        return value


class WorkflowUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    gate_config: dict[str, Any] | None = None
    schedule_interval_minutes: int | None = Field(default=None, ge=MIN_SCHEDULE_INTERVAL_MINUTES)

    _gate_config_must_parse = field_validator("gate_config")(
        WorkflowCreate._gate_config_must_parse.__func__  # type: ignore[attr-defined]
    )


class WorkflowWebhookSecretRead(BaseModel):
    """The plaintext secret, shown exactly once, at generation time — never
    again afterward. `WorkflowRead` never includes it."""

    secret: str
    webhook_url: str


class WorkflowRunApprovalRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


class WorkflowRunRejectionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


class InboundWebhookTrigger(BaseModel):
    """The inbound webhook's own minimal, platform-defined body
    (`app/api/v1/routers/webhooks.py`) — restricted to the two trigger
    kinds an external event can legitimately carry. `SCHEDULE`/`MANUAL`
    are refused here at the schema level, before any signature or replay
    check even runs.
    """

    kind: TriggerKind
    ref: str | None = Field(default=None, max_length=300)
    commit: str | None = Field(default=None, max_length=100)
    pull_number: int | None = Field(default=None, ge=1)

    @field_validator("kind")
    @classmethod
    def _kind_must_be_inbound_capable(cls, value: TriggerKind) -> TriggerKind:
        if value not in (TriggerKind.REPOSITORY_CHANGE, TriggerKind.PULL_REQUEST):
            raise ValueError(
                f"{value.value} is not a kind an inbound webhook may carry; "
                "use repository_change or pull_request"
            )
        return value


class WorkflowRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    target_id: uuid.UUID
    name: str
    trigger_kind: str
    enabled: bool
    gate_config: dict[str, Any] | None
    schedule_interval_minutes: int | None
    next_run_at: datetime | None
    #: Never the secret itself — only whether inbound acceptance is on.
    webhook_enabled: bool
    created_at: datetime


class WorkflowRunRequest(BaseModel):
    """What a caller may say about a trigger.

    Deliberately narrow. A caller cannot choose the plan, the actions, or the
    gate — those are derived from the workflow and the target's configuration,
    which is what makes the stored plan digest mean anything.
    """

    ref: str | None = Field(default=None, max_length=300)
    commit: str | None = Field(default=None, max_length=100)
    pull_number: int | None = Field(default=None, ge=1)


class WorkflowRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workflow_id: uuid.UUID
    assessment_run_id: uuid.UUID | None
    status: str
    trigger: dict[str, Any]
    plan: dict[str, Any]
    plan_digest: str
    stages: list[dict[str, Any]]
    evidence_refs: list[str]
    gate_passed: bool | None
    gate_exit_code: int | None
    gate_reasons: list[str]
    gate_counts: dict[str, Any]
    started_at: datetime | None
    finished_at: datetime | None
    detail: str | None
    approved_by_user_id: uuid.UUID | None
    approved_at: datetime | None
    created_at: datetime
