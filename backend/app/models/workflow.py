"""Workflows and their runs (docs/BUILD_SPEC.md §26 Phase 17).

Persisted in the existing database rather than in a workflow product, because
the thing being stored is small: a trigger, a derived plan, five stage records,
and a gate decision. Introducing an engine with its own state store to hold that
would be a second source of truth about what ran.

`WorkflowRun.plan_digest` is what makes a stored plan useful: two runs whose
digests match would have done the same things, so "did the plan change between
these commits?" is a comparison rather than an investigation.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Workflow(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "workflows"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_workflow_org_name"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    trigger_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    #: The gate this workflow judges by, in the same shape `load_config` reads.
    #: Null means the default, so a workflow created without one is not
    #: ungated — it uses the documented default.
    gate_config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    #: Only meaningful when `trigger_kind == "schedule"`. Null means this
    #: workflow is never picked up by `dispatch_scheduled_workflows` — the
    #: same "silence is the inert state, not an error" rule
    #: `PentestScope`'s own absence already follows.
    schedule_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Server-computed and advanced by the dispatcher; never client-settable
    #: beyond the initial value set when a schedule is first configured.
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Inbound webhook acceptance (pentest-module Phase 8). Opt-in — a
    #: secure default, matching every other "opt in to a new capability"
    #: column in this codebase.
    webhook_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: AES-256-GCM ciphertext (nonce-prefixed), never plaintext — see
    #: `app/core/workflow/webhook_secret.py`. Shown to the operator once, at
    #: generation time, the same way an API key's token is.
    webhook_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)


class WorkflowRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "workflow_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workflows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: The assessment this workflow drove, where it started one. Null when every
    #: scan action was skipped — a workflow can legitimately do nothing but
    #: re-gate what is already known.
    assessment_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="SET NULL"), nullable=True
    )

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    trigger: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    #: The full plan, including the actions that were skipped and why.
    plan: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    plan_digest: Mapped[str] = mapped_column(String(80), nullable=False, default="", index=True)
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    #: The gate's verdict, stored verbatim. Never edited by a later stage, and
    #: never derived from an AI draft — see `app/core/workflow/result.py`.
    gate_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    gate_exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gate_reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    gate_counts: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detail: Mapped[str | None] = mapped_column(String(500), nullable=True)

    #: Set only by `approve()`, only on a run that was `awaiting_approval` —
    #: the human who supplied the `user_id` `queue_scan_for_workflow_run`
    #: attributes the resulting scan to. A rejected run is recorded via the
    #: existing `status`/`detail` columns above, not a new pair of columns.
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
