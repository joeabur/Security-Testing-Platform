"""Every number the dashboard shows, as a real query.

§27's definition of done says it plainly: *no hardcoded dashboard values — every
number is a real query*. So this module holds them all, and the templates
receive only what these functions return. A template that needed a number not
in here would have to add it here first, which is the point.

Two related rules the functions below follow:

* **Zero and unknown are different.** A count of zero findings is a fact and
  renders as `0`. A value that was never decided is not: `WorkflowRun.gate_passed`
  is nullable and the template renders `None` as *not decided* rather than as a
  pass. Every count in `Overview` is computable from rows that always exist, so
  none of them is nullable today; one that stopped being computable would return
  `None` rather than a confident `0`.
* **Everything is organization-scoped.** Each query takes an
  `organization_id` and filters on it at the database level, so a missing
  filter is a missing row rather than a leaked one.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.probes.models import Severity
from app.models.assessment_run import AssessmentRun, RunStatus
from app.models.authorization import Authorization
from app.models.finding import Finding, FindingStatus
from app.models.integration import DeliveryStatus, NotificationDelivery
from app.models.rules_of_engagement import RulesOfEngagementRecord
from app.models.target import Target, TargetKind
from app.models.workflow import Workflow, WorkflowRun

#: Severity order for display: worst first, because that is the reading order
#: for someone deciding what to do next.
SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")

#: Findings in these states are not "open work". `accepted_risk` is deliberately
#: included as closed: someone decided, and the dashboard should not keep
#: nagging about a decision that was made.
CLOSED_STATUSES = (
    FindingStatus.CLOSED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
    FindingStatus.REMEDIATED,
)


@dataclass(frozen=True)
class SeverityCount:
    severity: str
    count: int


@dataclass
class Overview:
    """The numbers on the dashboard's front page."""

    targets: int
    open_findings: int
    by_severity: list[SeverityCount] = field(default_factory=list)
    runs_last_7_days: int = 0
    failed_runs_last_7_days: int = 0
    workflows: int = 0
    failing_gates: int = 0
    undelivered_notifications: int = 0

    @property
    def critical(self) -> int:
        return next((item.count for item in self.by_severity if item.severity == "CRITICAL"), 0)

    @property
    def high(self) -> int:
        return next((item.count for item in self.by_severity if item.severity == "HIGH"), 0)


async def overview(db: AsyncSession, organization_id: uuid.UUID) -> Overview:
    since = datetime.now(UTC) - timedelta(days=7)

    targets = (
        await db.execute(
            select(func.count(Target.id)).where(Target.organization_id == organization_id)
        )
    ).scalar_one()

    severity_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(
                Finding.organization_id == organization_id,
                Finding.status.not_in(CLOSED_STATUSES),
            )
            .group_by(Finding.severity)
        )
    ).all()
    counts = {
        str(getattr(severity, "value", severity)).upper(): int(count)
        for severity, count in severity_rows
    }
    by_severity = [
        SeverityCount(severity=name, count=counts.get(name, 0)) for name in SEVERITY_ORDER
    ]

    runs = (
        await db.execute(
            select(func.count(AssessmentRun.id)).where(
                AssessmentRun.organization_id == organization_id,
                AssessmentRun.created_at >= since,
            )
        )
    ).scalar_one()
    failed = (
        await db.execute(
            select(func.count(AssessmentRun.id)).where(
                AssessmentRun.organization_id == organization_id,
                AssessmentRun.created_at >= since,
                AssessmentRun.status == RunStatus.FAILED,
            )
        )
    ).scalar_one()

    workflows = (
        await db.execute(
            select(func.count(Workflow.id)).where(Workflow.organization_id == organization_id)
        )
    ).scalar_one()
    failing = (
        await db.execute(
            select(func.count(WorkflowRun.id)).where(
                WorkflowRun.organization_id == organization_id,
                WorkflowRun.gate_passed.is_(False),
                WorkflowRun.created_at >= since,
            )
        )
    ).scalar_one()

    undelivered = (
        await db.execute(
            select(func.count(NotificationDelivery.id)).where(
                NotificationDelivery.organization_id == organization_id,
                NotificationDelivery.status.in_(
                    [DeliveryStatus.DEAD_LETTER.value, DeliveryStatus.REFUSED.value]
                ),
            )
        )
    ).scalar_one()

    return Overview(
        targets=int(targets),
        open_findings=sum(item.count for item in by_severity),
        by_severity=by_severity,
        runs_last_7_days=int(runs),
        failed_runs_last_7_days=int(failed),
        workflows=int(workflows),
        failing_gates=int(failing),
        undelivered_notifications=int(undelivered),
    )


async def recent_runs(
    db: AsyncSession, organization_id: uuid.UUID, *, limit: int = 10, offset: int = 0
) -> Sequence[AssessmentRun]:
    result = await db.execute(
        select(AssessmentRun)
        .where(AssessmentRun.organization_id == organization_id)
        .order_by(AssessmentRun.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(result.scalars().all())


async def has_more_runs(
    db: AsyncSession, organization_id: uuid.UUID, *, limit: int, offset: int
) -> bool:
    """Whether a run exists past the page just fetched.

    A second, cheap query rather than fetching `limit + 1` rows and trimming
    one off: the caller already has exactly the page it asked for, and this
    answers only the one further question a "next" link needs.
    """
    result = await db.execute(
        select(AssessmentRun.id)
        .where(AssessmentRun.organization_id == organization_id)
        .order_by(AssessmentRun.created_at.desc())
        .offset(offset + limit)
        .limit(1)
    )
    return result.first() is not None


async def open_findings(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Sequence[Finding]:
    """Open findings, worst first.

    Ordered by risk score rather than severity alone: two criticals are not
    equally urgent, and the score is what the risk model actually computed.
    """
    statement = select(Finding).where(
        Finding.organization_id == organization_id,
        Finding.status.not_in(CLOSED_STATUSES),
    )
    if severity and severity.upper() in SEVERITY_ORDER:
        statement = statement.where(Finding.severity == Severity(severity.upper()))
    statement = (
        statement.order_by(Finding.risk_score.desc(), Finding.last_seen.desc())
        .offset(offset)
        .limit(limit)
    )
    return list((await db.execute(statement)).scalars().all())


async def has_more_findings(
    db: AsyncSession,
    organization_id: uuid.UUID,
    *,
    severity: str | None = None,
    limit: int,
    offset: int,
) -> bool:
    statement = select(Finding.id).where(
        Finding.organization_id == organization_id,
        Finding.status.not_in(CLOSED_STATUSES),
    )
    if severity and severity.upper() in SEVERITY_ORDER:
        statement = statement.where(Finding.severity == Severity(severity.upper()))
    statement = (
        statement.order_by(Finding.risk_score.desc(), Finding.last_seen.desc())
        .offset(offset + limit)
        .limit(1)
    )
    return (await db.execute(statement)).first() is not None


async def recent_workflow_runs(
    db: AsyncSession, organization_id: uuid.UUID, *, limit: int = 10
) -> Sequence[WorkflowRun]:
    result = await db.execute(
        select(WorkflowRun)
        .where(WorkflowRun.organization_id == organization_id)
        .order_by(WorkflowRun.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


@dataclass(frozen=True)
class TargetRow:
    """A target and whether it could actually be scanned right now.

    `blockers` is the point of this row. A target missing its authorization
    grant is refused at run time, and a dashboard that showed only the name
    would leave an operator to discover that by trying. Every blocker here
    names a real precondition the orchestrator checks.
    """

    id: uuid.UUID
    name: str
    kind: str
    environment: str
    base_url: str
    authorization_state: str
    has_scope: bool
    has_code_repo: bool
    blockers: tuple[str, ...]


async def targets_for(
    db: AsyncSession, organization_id: uuid.UUID, *, now: datetime | None = None
) -> Sequence[TargetRow]:
    """Targets with their readiness, in one pass.

    The joins are explicit rather than relationship access: these rows are
    rendered by a template, and a lazy load during rendering fails under
    asyncpg. Loading what the page shows is also the only way to be sure the
    page shows what was loaded.
    """
    moment = now or datetime.now(UTC)
    result = await db.execute(
        select(
            Target.id,
            Target.name,
            Target.kind,
            Target.environment,
            Target.base_url,
            Target.adapter_kind,
            Target.code_repo_ref,
            Authorization.valid_from,
            Authorization.valid_until,
            RulesOfEngagementRecord.allowed_domains,
            RulesOfEngagementRecord.code_scope,
        )
        .outerjoin(Authorization, Authorization.target_id == Target.id)
        .outerjoin(RulesOfEngagementRecord, RulesOfEngagementRecord.target_id == Target.id)
        .where(Target.organization_id == organization_id)
        .order_by(Target.created_at.desc())
    )

    rows: list[TargetRow] = []
    for (
        target_id,
        name,
        kind,
        environment,
        base_url,
        adapter_kind,
        code_repo_ref,
        valid_from,
        valid_until,
        allowed_domains,
        # SQLAlchemy's typed `select()` overloads only cover up to ten
        # positional columns; an eleventh (`code_scope`) makes `result.all()`
        # a variadic tuple type, which mypy requires a star target to
        # destructure even though there is exactly one column left.
        *rest,
    ) in result.all():
        code_scope = rest[0]
        if valid_from is None or valid_until is None:
            state = "none"
        elif valid_from <= moment <= valid_until:
            state = "valid"
        else:
            # Outside the window either way. "expired" reads correctly for the
            # common case and a not-yet-valid grant is equally unusable, so the
            # page says the same thing about both: you cannot scan with it.
            state = "expired"

        kind_value = str(getattr(kind, "value", kind))
        # A `code_repo` target has no network surface at all by design (see
        # `TargetKind.CODE_REPO`'s docstring) — its Rules of Engagement carry
        # only `code_scope`, and `allowed_domains` is deliberately empty. Judging
        # its scope by `allowed_domains`, as every other kind's row does, would
        # call a correctly-configured repository "missing rules of engagement".
        has_scope = bool(code_scope) if kind_value == "code_repo" else bool(allowed_domains)
        blockers: list[str] = []
        if state != "valid":
            blockers.append("no valid authorization grant")
        if not has_scope:
            blockers.append("no rules of engagement")
        # An LLM target with no adapter has no surface to talk to, so the AI
        # probes would report nothing and the run would look clean. Naming it
        # here is the difference between "nothing found" and "nothing tested".
        if kind_value in ("llm_app", "agent", "rag") and not adapter_kind:
            blockers.append("no adapter configured")

        rows.append(
            TargetRow(
                id=target_id,
                name=name,
                kind=kind_value,
                environment=str(getattr(environment, "value", environment)),
                base_url=base_url,
                authorization_state=state,
                has_scope=has_scope,
                has_code_repo=bool(code_repo_ref),
                blockers=tuple(blockers),
            )
        )
    return rows


@dataclass(frozen=True)
class RepositoryRow:
    """One connected repository and its most recent scan, if any."""

    id: uuid.UUID
    name: str
    url: str
    branch: str | None
    environment: str
    latest_run_status: str | None
    latest_run_at: datetime | None


async def repositories_for(db: AsyncSession, organization_id: uuid.UUID) -> Sequence[RepositoryRow]:
    """Connected repositories with their latest scan, in one pass.

    A `LATERAL` join for "the most recent run per target" rather than a
    window function over a subquery (`app/core/repositories/service.py`'s
    `latest_scans` takes that approach for the API): this module selects
    explicit columns throughout rather than ORM relationships, and a
    `LATERAL` subquery reads as the direct SQL translation of "for each
    repository, its newest run" without a second query shape to follow.
    """
    latest_run = (
        select(AssessmentRun.status, AssessmentRun.created_at)
        .where(AssessmentRun.target_id == Target.id)
        .order_by(AssessmentRun.created_at.desc())
        .limit(1)
        .lateral()
    )
    result = await db.execute(
        select(
            Target.id,
            Target.name,
            Target.code_repo_ref,
            Target.environment,
            latest_run.c.status,
            latest_run.c.created_at,
        )
        .outerjoin(latest_run, true())
        .where(Target.organization_id == organization_id, Target.kind == TargetKind.CODE_REPO)
        .order_by(Target.created_at.desc())
    )

    rows: list[RepositoryRow] = []
    for target_id, name, code_repo_ref, environment, status, created_at in result.all():
        url, _, branch = (code_repo_ref or "").removeprefix("git+").partition("#")
        rows.append(
            RepositoryRow(
                id=target_id,
                name=name,
                url=url,
                branch=branch or None,
                environment=str(getattr(environment, "value", environment)),
                latest_run_status=str(getattr(status, "value", status)) if status else None,
                latest_run_at=created_at,
            )
        )
    return rows
