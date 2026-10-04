"""Remediation and retest request/response shapes (docs/BUILD_SPEC.md §26
Phase 9)."""

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.measure.asr import asr_delta
from app.core.probes.models import Severity
from app.models.finding import FindingStatus
from app.models.retest import RetestVerdict


class RemediationUpsert(BaseModel):
    """Everything a person decides about the work.

    Note what is absent: a state. The finding's lifecycle is the single
    source of truth for security state, and a second one here would drift
    from it. Use the finding's status endpoint to move it.
    """

    summary: str | None = Field(default=None, max_length=300)
    assignee_user_id: uuid.UUID | None = None
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=4000)


class RemediationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    summary: str
    assignee_user_id: uuid.UUID | None
    due_date: date | None
    notes: str | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class RemediationBoardRow(BaseModel):
    """A board row: the work, plus the finding facts needed to prioritise it.

    Denormalized into the response rather than left to the client to join,
    because a board that shows a task without its severity invites someone to
    work the top of the list instead of the top of the risk.
    """

    task: RemediationRead
    finding_id: uuid.UUID
    title: str
    severity: Severity
    risk_score: float
    status: FindingStatus
    retest_result: str | None


class RetestCreate(BaseModel):
    target_id: uuid.UUID
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    # A retest reaches the target, so it needs the same explicit
    # authorization confirmation a new assessment does. There is no path that
    # treats "we already ran this once" as standing permission.
    authorization_confirmed: bool = False
    profile: str = "full"
    safe_mode: bool = True


class RetestResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_id: uuid.UUID
    finding_id: uuid.UUID
    fingerprint: str
    verdict: RetestVerdict
    before_evidence_ref: str | None
    after_evidence_ref: str | None
    before_attack_success_rate: dict[str, Any] | None
    after_attack_success_rate: dict[str, Any] | None
    # Computed on read rather than stored, so the comparison logic in
    # `asr_delta` can evolve without a migration touching every past row.
    # `None` whenever either side has no rate — see `asr_delta`'s own
    # docstring for why that is never filled in with a guess.
    attack_success_rate_delta: dict[str, Any] | None = None
    detail: str
    created_at: datetime

    @model_validator(mode="after")
    def _compute_asr_delta(self) -> "RetestResultRead":
        self.attack_success_rate_delta = asr_delta(
            self.before_attack_success_rate, self.after_attack_success_rate
        )
        return self
