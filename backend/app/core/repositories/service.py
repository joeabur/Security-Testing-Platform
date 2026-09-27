"""Adding a repository for code scanning, without the live-target workflow.

The rest of this platform's code-scanning support (`app/core/appsec/`,
`app/core/orchestrator/code_check.py`) is built around one `Target` that may
optionally carry a `code_repo_ref` — reachable only through the full
Target -> Authorization -> Rules-of-Engagement sequence built for a live
network assessment (docs/BUILD_SPEC.md §5), which asks for things a
source-code-only scan has no use for: a base URL to probe, an operator-role
authorization grant from someone else, a YAML Rules-of-Engagement document.

This module is the fast path: given a repository URL, a branch, and an
explicit affirmation that the caller has the right to have it scanned, it
composes the same three rows a full Target setup would produce —

* a `Target` of kind `code_repo` (`base_url` is the repository's own URL;
  there is nothing else to probe, and `TargetKind.CODE_REPO` is what keeps
  `app/workers/tasks.py` from building a `DastCheck` or an AI check for it —
  see that enum's docstring),
* an `Authorization` whose `authorized_by_*` fields and `reference` record
  the affirming user and the fact that this was self-service consent, not a
  grant from an operator, and
* a `RulesOfEngagementRecord` carrying only a `code_scope` (no network
  scope at all: empty `allowed_domains`, `allowed_methods`, etc., since this
  target is never dialled).

— so that everything downstream (the AppSec engines, the run/report
pipeline, the findings board) works on a repository added this way exactly
as it already works on a target someone configured by hand.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.appsec.checkout import CheckoutError, RepositoryRef, parse_repo_ref
from app.core.probes.models import Severity
from app.models.assessment_run import AssessmentRun
from app.models.authorization import Authorization
from app.models.finding import Finding, FindingStatus
from app.models.rules_of_engagement import RulesOfEngagementRecord
from app.models.target import Target, TargetEnvironment, TargetKind
from app.models.user import User

# `RulesOfEngagementRecord.budgets` is required and validated as a positive
# `Budgets` shape (app/core/scope/resolve.py), but nothing in a code-only
# run ever spends it: `CodeScanCheck.run()` never calls `transport.send()`.
# These values exist only to satisfy that validation.
_INERT_BUDGETS: dict[str, Any] = {
    "max_requests": 1,
    "max_concurrency": 1,
    "requests_per_second": 1.0,
    "max_tokens_sent": 1,
    "max_tokens_received": 1,
    "max_estimated_cost_usd": 0.01,
    "max_wall_clock_minutes": 30,
}

# The self-service consent is not a network authorization window with an
# operational reason to expire soon — it lasts as long as the repository
# stays connected. Ten years is "does not need renewing," not "forever":
# `docs/security-model.md` guarantee #1 still refuses a run whose
# authorization has passed `valid_until`, so a repository nobody has
# touched in a decade still stops scanning rather than running on
# authorization nobody re-affirmed.
_CONSENT_VALIDITY = timedelta(days=3650)

# Open findings a repository's summary counts. Closed and false-positive
# findings are resolved, not open; accepted-risk is deliberately still
# counted — accepting a risk does not mean it stopped existing.
_RESOLVED_FINDING_STATUSES = (FindingStatus.CLOSED, FindingStatus.FALSE_POSITIVE)
_OPEN_FINDING_STATUSES = tuple(
    status for status in FindingStatus if status not in _RESOLVED_FINDING_STATUSES
)


class RepositoryError(ValueError):
    """The repository reference or scope could not be accepted."""


class RepositoryAlreadyConnectedError(RepositoryError):
    """This organization already has this exact repository connected."""


@dataclass(frozen=True)
class RepositoryScopeInput:
    name: str
    url: str
    branch: str | None
    environment: TargetEnvironment
    languages: list[str]
    build_manifest_paths: list[str]
    allowed_paths: list[str]
    excluded_paths: list[str]
    max_repo_size_mb: int


def _build_repo_ref(url: str, branch: str | None) -> str:
    """`git+https://host/org/repo.git#branch` from a plain URL and branch.

    A branch fragment already embedded in a pasted URL is respected as-is;
    the separate `branch` field only applies when the URL carries none, so
    the two inputs cannot silently produce two different fragments.
    """
    candidate = url.strip()
    if candidate.startswith("git+"):
        candidate = candidate[len("git+") :]
    if "#" not in candidate and branch:
        candidate = f"{candidate}#{branch.strip()}"
    return f"git+{candidate}"


def parse_and_validate_ref(url: str, branch: str | None) -> tuple[str, RepositoryRef]:
    """The raw `git+...#branch` string to store, and its parsed form.

    Raises `CheckoutError` (via `parse_repo_ref`) for a scheme this platform
    will not clone from (`ext::`, `git://`) or a URL carrying inline
    credentials — the same checks `checkout.py` applies at scan time,
    surfaced here instead so a bad reference is rejected when it is typed,
    not on the first scan attempt.
    """
    raw = _build_repo_ref(url, branch)
    ref = parse_repo_ref(raw)
    return raw, ref


async def _find_existing(
    db: AsyncSession, *, organization_id: uuid.UUID, repo_ref: str
) -> Target | None:
    result = await db.execute(
        select(Target).where(
            Target.organization_id == organization_id,
            Target.kind == TargetKind.CODE_REPO,
            Target.code_repo_ref == repo_ref,
        )
    )
    return result.scalar_one_or_none()


async def create_repository(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    user: User,
    scope: RepositoryScopeInput,
) -> Target:
    """Create the Target/Authorization/RulesOfEngagement triple for one
    repository, or raise if this exact repository is already connected."""
    try:
        raw_ref, ref = parse_and_validate_ref(scope.url, scope.branch)
    except CheckoutError as exc:
        raise RepositoryError(str(exc)) from exc

    if await _find_existing(db, organization_id=organization_id, repo_ref=raw_ref):
        raise RepositoryAlreadyConnectedError(
            f"{scope.url!r} is already connected for this organization"
        )

    now = datetime.now(UTC)
    target = Target(
        organization_id=organization_id,
        name=scope.name,
        environment=scope.environment,
        kind=TargetKind.CODE_REPO,
        base_url=ref.url,
        code_repo_ref=raw_ref,
        code_languages=list(scope.languages),
        code_build_manifest_paths=list(scope.build_manifest_paths),
        created_by_user_id=user.id,
    )
    db.add(target)
    await db.flush()

    db.add(
        Authorization(
            target_id=target.id,
            authorized_by_name=user.full_name,
            authorized_by_role="self_service",
            authorized_by_email=user.email,
            reference=(
                "Self-service repository scan consent, affirmed at connection time "
                "by the user who added it — not an operator-granted authorization."
            ),
            valid_from=now,
            valid_until=now + _CONSENT_VALIDITY,
            accepted_by_user_id=user.id,
            accepted_at=now,
        )
    )
    db.add(
        RulesOfEngagementRecord(
            target_id=target.id,
            allowed_domains=[],
            excluded_domains=[],
            allowed_ip_ranges=[],
            allowed_paths=[],
            excluded_paths=[],
            allowed_methods=[],
            forbidden_headers=[],
            budgets=dict(_INERT_BUDGETS),
            safe_mode=True,
            allow_state_mutation=False,
            blackout_windows=[],
            code_scope={
                "allowed_paths": list(scope.allowed_paths) or ["**"],
                "excluded_paths": list(scope.excluded_paths),
                "max_repo_size_mb": scope.max_repo_size_mb,
                # Scoped to exactly the host this repository names — not a
                # general allowlist. Adding this repository authorizes
                # cloning from its own host, nothing wider.
                "allowed_repo_hosts": [ref.host],
            },
            appsec_budgets={},
        )
    )
    await db.commit()
    created = await load_repository(db, organization_id=organization_id, target_id=target.id)
    assert created is not None  # just committed under this same organization_id
    return created


async def load_repository(
    db: AsyncSession, *, organization_id: uuid.UUID, target_id: uuid.UUID
) -> Target | None:
    result = await db.execute(
        select(Target)
        .where(
            Target.id == target_id,
            Target.organization_id == organization_id,
            Target.kind == TargetKind.CODE_REPO,
        )
        .options(selectinload(Target.authorization), selectinload(Target.rules_of_engagement))
    )
    return result.scalar_one_or_none()


async def list_repositories(db: AsyncSession, *, organization_id: uuid.UUID) -> list[Target]:
    result = await db.execute(
        select(Target)
        .where(Target.organization_id == organization_id, Target.kind == TargetKind.CODE_REPO)
        .options(selectinload(Target.authorization), selectinload(Target.rules_of_engagement))
        .order_by(Target.created_at.desc())
    )
    return list(result.scalars().all())


async def latest_scans(
    db: AsyncSession, *, target_ids: list[uuid.UUID]
) -> dict[uuid.UUID, AssessmentRun]:
    """The most recent run per target, in one query.

    Postgres has no "top 1 per group" without a window function or a
    lateral join; a window function is the one that does not require a
    correlated subquery per row.
    """
    if not target_ids:
        return {}

    ranked = (
        select(
            AssessmentRun.id,
            func.row_number()
            .over(partition_by=AssessmentRun.target_id, order_by=AssessmentRun.created_at.desc())
            .label("rn"),
        )
        .where(AssessmentRun.target_id.in_(target_ids))
        .subquery()
    )
    rows = await db.execute(
        select(AssessmentRun).join(ranked, AssessmentRun.id == ranked.c.id).where(ranked.c.rn == 1)
    )
    return {run.target_id: run for run in rows.scalars().all()}


async def recent_scans(
    db: AsyncSession, *, target_id: uuid.UUID, limit: int = 10
) -> list[AssessmentRun]:
    result = await db.execute(
        select(AssessmentRun)
        .where(AssessmentRun.target_id == target_id)
        .order_by(AssessmentRun.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def open_findings_by_severity(
    db: AsyncSession, *, organization_id: uuid.UUID, target_id: uuid.UUID
) -> dict[str, int]:
    result = await db.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.organization_id == organization_id,
            Finding.target_id == target_id,
            Finding.status.in_(_OPEN_FINDING_STATUSES),
        )
        .group_by(Finding.severity)
    )
    counts = {severity.value: 0 for severity in Severity if severity is not Severity.INFORMATIONAL}
    for severity, count in result.all():
        counts[severity.value] = count
    return counts


async def delete_repository(db: AsyncSession, *, target: Target) -> None:
    await db.delete(target)
    await db.commit()
