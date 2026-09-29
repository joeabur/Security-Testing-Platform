"""Security-operations dashboard (pentest module, Phase 10).

One read-only, organization-wide summary endpoint. Every number it returns
comes from `app/core/dashboard/queries.py` — the same module the Phase 17
Jinja2 dashboard calls — so a count shown here and a count shown there can
never quietly drift apart into two different answers to the same question.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.auth.dependencies import DbSession, require_membership
from app.core.dashboard import queries
from app.models.organization import Membership, Role
from app.models.target import Target
from app.models.workflow import Workflow
from app.schemas.dashboard import (
    DashboardFindingRead,
    DashboardRunRead,
    DashboardSummary,
    DashboardWorkflowRunRead,
    PillarCoverageEntry,
    RemediationSummaryRead,
    SeverityCounts,
)

router = APIRouter(prefix="/organizations/{organization_id}/dashboard", tags=["dashboard"])

#: How many rows each "recent activity" list shows. A dashboard is an
#: at-a-glance surface — a deeper look belongs on the runs/findings pages
#: that already list everything, paginated.
_RECENT_LIMIT = 5
_TOP_FINDINGS_LIMIT = 10


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> DashboardSummary:
    overview = await queries.overview(db, organization_id)
    recent_runs = await queries.recent_runs(db, organization_id, limit=_RECENT_LIMIT)
    recent_workflow_runs = await queries.recent_workflow_runs(
        db, organization_id, limit=_RECENT_LIMIT
    )
    top_findings = await queries.open_findings(db, organization_id, limit=_TOP_FINDINGS_LIMIT)
    pillar_coverage = await queries.pillar_coverage_for(db, organization_id)
    remediation = await queries.remediation_summary(db, organization_id)
    pending_retests = await queries.pending_retest_count(db, organization_id)

    # Batched name lookups rather than N+1 joins per row: the lists above are
    # each at most _RECENT_LIMIT/_TOP_FINDINGS_LIMIT long, so one extra query
    # per name kind stays cheap regardless of how large the org's history is.
    target_ids = {run.target_id for run in recent_runs} | {
        finding.target_id for finding in top_findings if finding.target_id is not None
    }
    target_names: dict[uuid.UUID, str] = {}
    if target_ids:
        rows = (
            await db.execute(select(Target.id, Target.name).where(Target.id.in_(target_ids)))
        ).all()
        target_names = {row[0]: row[1] for row in rows}

    workflow_ids = {run.workflow_id for run in recent_workflow_runs}
    workflow_names: dict[uuid.UUID, str] = {}
    if workflow_ids:
        rows = (
            await db.execute(
                select(Workflow.id, Workflow.name).where(Workflow.id.in_(workflow_ids))
            )
        ).all()
        workflow_names = {row[0]: row[1] for row in rows}

    return DashboardSummary(
        targets=overview.targets,
        open_findings=overview.open_findings,
        open_findings_by_severity=SeverityCounts(
            critical=overview.critical,
            high=overview.high,
            medium=next(
                (c.count for c in overview.by_severity if c.severity == "MEDIUM"), 0
            ),
            low=next((c.count for c in overview.by_severity if c.severity == "LOW"), 0),
            informational=next(
                (c.count for c in overview.by_severity if c.severity == "INFORMATIONAL"), 0
            ),
        ),
        runs_last_7_days=overview.runs_last_7_days,
        failed_runs_last_7_days=overview.failed_runs_last_7_days,
        workflows=overview.workflows,
        failing_gates_last_7_days=overview.failing_gates,
        undelivered_notifications=overview.undelivered_notifications,
        remediation=RemediationSummaryRead(open=remediation.open, overdue=remediation.overdue),
        pending_retests=pending_retests,
        pillar_coverage=[
            PillarCoverageEntry(pillar=row.pillar, tested=row.tested) for row in pillar_coverage
        ],
        recent_runs=[
            DashboardRunRead(
                id=run.id,
                target_id=run.target_id,
                target_name=target_names.get(run.target_id, "Unknown target"),
                status=run.status,
                profile=run.profile,
                findings_reported=run.findings_reported,
                created_at=run.created_at,
            )
            for run in recent_runs
        ],
        recent_workflow_runs=[
            DashboardWorkflowRunRead(
                id=run.id,
                workflow_id=run.workflow_id,
                workflow_name=workflow_names.get(run.workflow_id, "Unknown workflow"),
                status=run.status,
                gate_passed=run.gate_passed,
                created_at=run.created_at,
            )
            for run in recent_workflow_runs
        ],
        top_findings=[
            DashboardFindingRead(
                id=finding.id,
                title=finding.title,
                severity=finding.severity,
                risk_score=finding.risk_score,
                status=finding.status,
                target_id=finding.target_id,
                target_name=(
                    target_names.get(finding.target_id) if finding.target_id is not None else None
                ),
                last_seen=finding.last_seen,
            )
            for finding in top_findings
        ],
    )
