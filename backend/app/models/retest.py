"""Retest results (docs/BUILD_SPEC.md §26 Phase 9).

This table exists to record an **absence**, which is the one thing an
ordinary scan cannot express. A run that no longer produces a finding looks
exactly like a run whose probe never got to try: both are silence. So a
retest names the findings it set out to check, and each one gets a verdict —
reproduced, not reproduced, or not tested — with the evidence digest from
before and the one from after.

`NOT_TESTED` matters as much as the other two. Without it, a retest whose
probe was skipped by safe mode, refused by scope, or cut short by a budget
would read as a fix.
"""

import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RetestVerdict(StrEnum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    NOT_TESTED = "not_tested"


class RetestResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "retest_results"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    # Kept alongside the foreign key on purpose: the fingerprint is what the
    # comparison was actually made on, and a reader checking the verdict
    # months later should not have to trust that the finding row still
    # carries the same one.
    fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    verdict: Mapped[RetestVerdict] = mapped_column(
        Enum(RetestVerdict, name="retest_verdict_enum"), nullable=False
    )
    # The before/after pair §26 Phase 9 asks for. Either may be null: a
    # finding promoted before evidence bundles existed has no "before", and a
    # weakness that is genuinely gone has no "after".
    before_evidence_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    after_evidence_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # §7.1's attack-success-rate measurement, carried across the same
    # before/after boundary as the evidence refs above. Null on either side
    # for exactly the same reason the evidence refs can be null: a finding
    # whose probe never ran under the trial driver has no rate to report,
    # and a retest that found nothing new has no "after" measurement —
    # never a fabricated one. `app.core.measure.asr.asr_delta` is what
    # turns this pair into a direction and a significance verdict.
    before_attack_success_rate: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    after_attack_success_rate: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
