import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.probes.models import Category, Confidence, Severity
from app.models.finding import FindingStatus, Stability


class FindingRead(BaseModel):
    """The §11 finding as stored.

    `severity_rationale` is never optional: a severity a reader cannot
    account for is worse than no severity at all.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    target_id: uuid.UUID | None
    fingerprint: str

    title: str
    category: Category
    probe_id: str
    probe_version: str
    surface: str

    severity: Severity
    severity_rationale: str
    confidence: Confidence
    stability: Stability

    risk_model: str
    risk_score: float
    risk_inputs: dict[str, Any]

    # Separate fields, never averaged together (§12).
    attack_success_rate: dict[str, Any] | None
    control_success_rate: dict[str, Any] | None
    cvss_v4: dict[str, Any] | None
    aivss: dict[str, Any] | None

    description: str
    impact: str
    remediation: str
    reproduction: list[str]
    mappings: dict[str, Any]
    mapping_versions: dict[str, Any]

    # The digest of the bundle in the evidence store, where the run stored
    # one. Null rather than absent: a design-review finding has no exchange
    # behind it, and that is worth saying.
    evidence_ref: str | None

    # The latest retest verdict, so a board can show "was this actually
    # fixed?" without a second request. Null until a retest has looked.
    retest_result: str | None
    last_retest_run_id: uuid.UUID | None

    status: FindingStatus
    status_note: str | None
    first_seen: datetime
    last_seen: datetime
    times_seen: int

    # Null unless a human has explicitly linked this finding as the same
    # underlying defect as another (see `app.core.findings.service.
    # link_duplicate`) — never inferred, only recorded.
    duplicate_of_finding_id: uuid.UUID | None
    duplicate_note: str | None


class FindingTransition(BaseModel):
    status: FindingStatus
    note: str | None = Field(default=None, max_length=2000)


class FindingDuplicateLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    duplicate_of_finding_id: uuid.UUID
    note: str | None = Field(default=None, max_length=1000)
