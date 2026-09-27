"""Connecting a repository for code scanning (app/core/repositories/service.py).

The fast path onto the AppSec engines (SAST, SCA, secrets, IaC): a URL, a
branch, and an affirmation that the caller may have it scanned — no
Rules-of-Engagement document, no operator-granted Authorization. See the
service module's docstring for what this composes underneath, and
`docs/repositories.md` for the operator-facing version of this page.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.v1.routers.runs import queue_run
from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession, require_membership
from app.core.repositories.service import (
    RepositoryAlreadyConnectedError,
    RepositoryError,
    RepositoryScopeInput,
    create_repository,
    delete_repository,
    latest_scans,
    list_repositories,
    load_repository,
    open_findings_by_severity,
    recent_scans,
)
from app.models.assessment_run import AssessmentRun, RunKind
from app.models.organization import Membership, Role
from app.models.target import Target
from app.schemas.repository import (
    RepositoryCreate,
    RepositoryDetail,
    RepositoryRead,
    RepositoryScanResult,
    RepositoryScanSummary,
    RepositoryScanTrigger,
)

router = APIRouter(prefix="/organizations/{organization_id}/repositories", tags=["repositories"])


def _read(target: Target, latest_scan: AssessmentRun | None) -> RepositoryRead:
    url, _, branch = (target.code_repo_ref or "").removeprefix("git+").partition("#")
    return RepositoryRead(
        id=target.id,
        organization_id=target.organization_id,
        name=target.name,
        url=url,
        branch=branch or None,
        environment=target.environment,
        languages=[str(item) for item in (target.code_languages or [])],
        build_manifest_paths=[str(item) for item in (target.code_build_manifest_paths or [])],
        created_at=target.created_at,
        latest_scan=(
            RepositoryScanSummary.model_validate(latest_scan) if latest_scan is not None else None
        ),
    )


@router.post("", response_model=RepositoryRead, status_code=status.HTTP_201_CREATED)
async def add_repository(
    organization_id: uuid.UUID,
    payload: RepositoryCreate,
    request: Request,
    db: DbSession,
    current_user: CurrentUser,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> RepositoryRead:
    scope = RepositoryScopeInput(
        name=payload.name,
        url=payload.url,
        branch=payload.branch,
        environment=payload.environment,
        languages=payload.languages,
        build_manifest_paths=payload.build_manifest_paths,
        allowed_paths=payload.allowed_paths,
        excluded_paths=payload.excluded_paths,
        max_repo_size_mb=payload.max_repo_size_mb,
    )
    try:
        target = await create_repository(
            db, organization_id=organization_id, user=current_user, scope=scope
        )
    except RepositoryAlreadyConnectedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RepositoryError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    await record_event(
        db,
        action="repository.add",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"repo_ref": target.code_repo_ref, "authorized_by": current_user.email},
    )
    await db.commit()
    return _read(target, None)


@router.get("", response_model=list[RepositoryRead])
async def list_connected_repositories(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[RepositoryRead]:
    targets = await list_repositories(db, organization_id=organization_id)
    scans = await latest_scans(db, target_ids=[target.id for target in targets])
    return [_read(target, scans.get(target.id)) for target in targets]


async def _load_or_404(
    organization_id: uuid.UUID, repository_id: uuid.UUID, db: DbSession
) -> Target:
    target = await load_repository(db, organization_id=organization_id, target_id=repository_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Repository not found")
    return target


@router.get("/{repository_id}", response_model=RepositoryDetail)
async def get_repository(
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> RepositoryDetail:
    target = await _load_or_404(organization_id, repository_id, db)
    runs = await recent_scans(db, target_id=target.id)
    counts = await open_findings_by_severity(
        db, organization_id=organization_id, target_id=target.id
    )
    base = _read(target, runs[0] if runs else None)
    roe = target.rules_of_engagement
    code_scope = dict((roe.code_scope if roe else None) or {})
    authorization = target.authorization
    # Built from `base`'s already-validated fields directly, rather than
    # `**base.model_dump()`: `model_dump()` serializes `latest_scan` by
    # field name (`run_id`), but that field's `validation_alias="id"`
    # means re-validating it from that dict fails looking for a key that
    # is not there. Passing the model instance through as-is has no such
    # round trip.
    return RepositoryDetail(
        id=base.id,
        organization_id=base.organization_id,
        name=base.name,
        url=base.url,
        branch=base.branch,
        environment=base.environment,
        languages=base.languages,
        build_manifest_paths=base.build_manifest_paths,
        created_at=base.created_at,
        latest_scan=base.latest_scan,
        allowed_paths=[str(item) for item in code_scope.get("allowed_paths", [])],
        excluded_paths=[str(item) for item in code_scope.get("excluded_paths", [])],
        max_repo_size_mb=int(code_scope.get("max_repo_size_mb", 500)),
        authorized_by_name=authorization.authorized_by_name if authorization else "",
        authorized_at=authorization.accepted_at if authorization else target.created_at,
        recent_scans=[RepositoryScanSummary.model_validate(run) for run in runs],
        open_findings_by_severity=counts,
    )


@router.post("/{repository_id}/scan", response_model=RepositoryScanResult)
async def scan_repository(
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    payload: RepositoryScanTrigger,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> RepositoryScanResult:
    target = await _load_or_404(organization_id, repository_id, db)
    run = await queue_run(
        db,
        organization_id=organization_id,
        target=target,
        membership=membership,
        request=request,
        profile="code_scan",
        safe_mode=payload.safe_mode,
        confirmed_at=datetime.now(UTC),
        kind=RunKind.ASSESSMENT,
    )
    return RepositoryScanResult(run_id=run.id, status=run.status)


@router.delete("/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_repository(
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    target = await _load_or_404(organization_id, repository_id, db)
    await record_event(
        db,
        action="repository.remove",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"repo_ref": target.code_repo_ref},
    )
    await delete_repository(db, target=target)
