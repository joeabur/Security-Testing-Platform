"""The security-operations dashboard's one response shape (pentest module,
Phase 10).

Every field here is backed by a real query in `app/core/dashboard/queries.py`
— no field is computed inline in this module, so there is exactly one place
that knows how each number is derived.
"""

import uuid
from datetime import date, datetime

from pydantic import BaseModel

from app.core.probes.models import Severity
from app.models.assessment_run import RunStatus
from app.models.finding import FindingStatus


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class PillarCoverageEntry(BaseModel):
    pillar: str
    tested: bool


class RemediationSummaryRead(BaseModel):
    open: int
    overdue: int


class DashboardRunRead(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    status: RunStatus
    profile: str
    findings_reported: int
    created_at: datetime


class DashboardWorkflowRunRead(BaseModel):
    id: uuid.UUID
    workflow_id: uuid.UUID
    workflow_name: str
    status: str
    gate_passed: bool | None
    created_at: datetime


class DashboardFindingRead(BaseModel):
    id: uuid.UUID
    title: str
    severity: Severity
    risk_score: float
    status: FindingStatus
    target_id: uuid.UUID | None
    target_name: str | None
    last_seen: datetime


class TrendPointRead(BaseModel):
    day: date
    severity: Severity
    count: int


class FindingsTrendRead(BaseModel):
    days: int
    points: list[TrendPointRead]


class DashboardSummary(BaseModel):
    targets: int
    open_findings: int
    open_findings_by_severity: SeverityCounts

    runs_last_7_days: int
    failed_runs_last_7_days: int
    workflows: int
    failing_gates_last_7_days: int
    undelivered_notifications: int

    remediation: RemediationSummaryRead
    pending_retests: int

    pillar_coverage: list[PillarCoverageEntry]
    recent_runs: list[DashboardRunRead]
    recent_workflow_runs: list[DashboardWorkflowRunRead]
    top_findings: list[DashboardFindingRead]
