"""The stored Finding (docs/BUILD_SPEC.md §11).

Distinct from `ScanResultRecord`, which is the raw §11.1 wire shape a probe
emitted. A finding is what that becomes once the findings service has added
identity, measurement, risk and lifecycle — and keeping the two apart means
the promotion can be re-run and corrected without re-scanning a target.

Two columns are load-bearing:

* `fingerprint` is the identity across runs. It is unique per organization,
  so the same unfixed weakness seen in ten runs is one finding with ten
  sightings rather than ten findings.
* `severity_rationale` is **required**, and generated with the score in the
  same call (§12). A finding cannot exist here carrying a number nobody can
  account for.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.probes.models import Category, Confidence, Severity
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.remediation import RemediationTask


class FindingStatus(StrEnum):
    """§11 lifecycle. `RETEST_REQUIRED` exists because a remediation is a
    claim until something checks it."""

    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    IN_REMEDIATION = "in_remediation"
    REMEDIATED = "remediated"
    RETEST_REQUIRED = "retest_required"
    CLOSED = "closed"


class Stability(StrEnum):
    DETERMINISTIC = "deterministic"
    PROBABILISTIC = "probabilistic"
    SINGLE_SHOT = "single_shot"


# Transitions a human may make. Deliberately restrictive: a finding cannot
# jump from `new` to `closed` without passing through a state that records
# *why*, which is what makes a closed finding auditable later.
ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.NEW: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.IN_REMEDIATION,
        }
    ),
    FindingStatus.CONFIRMED: frozenset(
        {
            FindingStatus.IN_REMEDIATION,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.FALSE_POSITIVE,
        }
    ),
    FindingStatus.IN_REMEDIATION: frozenset(
        {FindingStatus.REMEDIATED, FindingStatus.ACCEPTED_RISK, FindingStatus.CONFIRMED}
    ),
    # A remediation is a claim until a retest checks it, so the only way on
    # from here is through one.
    FindingStatus.REMEDIATED: frozenset({FindingStatus.RETEST_REQUIRED}),
    FindingStatus.RETEST_REQUIRED: frozenset({FindingStatus.CLOSED, FindingStatus.CONFIRMED}),
    FindingStatus.ACCEPTED_RISK: frozenset({FindingStatus.CONFIRMED, FindingStatus.CLOSED}),
    FindingStatus.FALSE_POSITIVE: frozenset({FindingStatus.CONFIRMED, FindingStatus.CLOSED}),
    FindingStatus.CLOSED: frozenset({FindingStatus.CONFIRMED}),
}


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint", name="uq_finding_org_fingerprint"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[Category] = mapped_column(
        Enum(Category, name="finding_category_enum"), nullable=False
    )
    probe_id: Mapped[str] = mapped_column(String(200), nullable=False)
    probe_version: Mapped[str] = mapped_column(String(50), nullable=False)
    surface: Mapped[str] = mapped_column(String(2048), nullable=False)

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="finding_severity_enum"), nullable=False
    )
    # Required by §11, generated with the score so the two always agree.
    severity_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence, name="finding_confidence_enum"), nullable=False
    )
    stability: Mapped[Stability] = mapped_column(
        Enum(Stability, name="finding_stability_enum"), nullable=False
    )

    risk_model: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_inputs: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    # Kept in their own columns and never averaged into risk_score (§12).
    attack_success_rate: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    control_success_rate: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    cvss_v4: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    aivss: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(String(80), nullable=True)
    reproduction: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)

    mappings: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    mapping_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status_enum"),
        nullable=False,
        default=FindingStatus.NEW,
    )
    status_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_changed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # How many runs have seen it. A finding seen once and a finding seen in
    # every run for three months are different conversations.
    times_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="SET NULL"), nullable=True
    )
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="SET NULL"), nullable=True
    )

    # §11's `retest_result`, denormalized onto the finding so a board can
    # show "was this actually fixed?" without a join. `retest_results` holds
    # the full history; this is the latest verdict.
    retest_result: Mapped[str | None] = mapped_column(String(30), nullable=True)
    last_retest_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment_runs.id", ondelete="SET NULL"), nullable=True
    )

    # A human-verified statement that this finding and another describe the
    # same underlying defect — the same weakness a SAST scan of a repo and a
    # DAST scan of the deployed app can both surface with different
    # `probe_id` prefixes and therefore different fingerprints. Deliberately
    # not an automatic heuristic: `docs/roadmap.md`'s own Phase 14 note is
    # explicit that "faking a correlation heuristic would be worse than the
    # honest gap," so this is only ever set by `link_duplicate`
    # (`app/core/findings/service.py`) at a human's explicit say-so, the
    # same way `AIService.correlate_findings()`'s own output is a read-only
    # recommendation, never a write to this column. Two-level only, by
    # construction: a finding that is itself a duplicate cannot become a
    # primary, and a primary with existing duplicates cannot become one —
    # `link_duplicate` enforces both, so there is never a chain to walk.
    duplicate_of_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    duplicate_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    duplicate_linked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    duplicate_linked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    organization: Mapped["Organization"] = relationship()
    # §11's `remediation_task_id`, as a relationship rather than a duplicated
    # column: the task already carries a unique `finding_id`, and a second
    # copy of the same edge is a second thing that can be wrong.
    remediation_task: Mapped["RemediationTask | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
