"""Findings (docs/BUILD_SPEC.md §11).

Read and triage. A finding's severity, risk score and measurement are
computed from evidence and are not editable here — a severity someone typed
over would no longer match its rationale, and the pair losing sync is how a
report stops being trustworthy. What a human decides is the **status**, and
that is what these endpoints change.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.findings.service import FindingLinkError, link_duplicate, unlink_duplicate
from app.core.probes.models import Severity
from app.models.finding import ALLOWED_TRANSITIONS, Finding, FindingStatus
from app.models.organization import Membership, Role
from app.schemas.finding import FindingDuplicateLink, FindingRead, FindingTransition

router = APIRouter(prefix="/organizations/{organization_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
async def list_findings(
    organization_id: uuid.UUID,
    db: DbSession,
    severity: Severity | None = None,
    finding_status: FindingStatus | None = None,
    run_id: uuid.UUID | None = None,
    # Both optional and both backward compatible: a caller that passes
    # neither (every existing one — the CLI, the CI gate, this router's own
    # earlier tests) gets the exact same unbounded, fully-ordered list as
    # before. Only a caller that opts in by passing `limit` gets a page —
    # the frontend's findings view, added once pagination had a reason to
    # exist (pentest module Phase 11).
    limit: int | None = Query(default=None, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    # False by default: a finding a human has explicitly linked as a
    # duplicate of another (see `POST .../duplicate`) describes the same
    # underlying defect, so it drops out of "how many findings does this
    # organization have" the same way it drops out of a report's counts —
    # opt in to see everything, including what was folded in.
    include_duplicates: bool = Query(default=False),
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[FindingRead]:
    query = select(Finding).where(Finding.organization_id == organization_id)
    if not include_duplicates:
        query = query.where(Finding.duplicate_of_finding_id.is_(None))
    if severity is not None:
        query = query.where(Finding.severity == severity)
    if finding_status is not None:
        query = query.where(Finding.status == finding_status)
    if run_id is not None:
        # The findings this run last saw. What a CI gate needs: "did the build
        # I just scanned introduce something", not "what does this
        # organization have open in total".
        query = query.where(Finding.last_run_id == run_id)

    query = query.order_by(Finding.risk_score.desc(), Finding.last_seen.desc()).offset(offset)
    if limit is not None:
        query = query.limit(limit)

    rows = await db.execute(query)
    return [FindingRead.model_validate(row) for row in rows.scalars().all()]


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> FindingRead:
    return FindingRead.model_validate(await _load(organization_id, finding_id, db))


@router.post("/{finding_id}/status", response_model=FindingRead)
async def transition_finding(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingTransition,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> FindingRead:
    """Move a finding through its lifecycle.

    Transitions are restricted so a finding cannot jump from `new` to
    `closed` without passing through a state that records why — which is
    what makes a closed finding auditable months later.
    """
    finding = await _load(organization_id, finding_id, db)

    if payload.status != finding.status:
        allowed = ALLOWED_TRANSITIONS.get(finding.status, frozenset())
        if payload.status not in allowed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=(
                    f"cannot move a finding from {finding.status.value} to "
                    f"{payload.status.value}; allowed: "
                    f"{', '.join(sorted(item.value for item in allowed)) or 'none'}"
                ),
            )
        finding.status = payload.status
        finding.status_note = payload.note
        finding.status_changed_by_user_id = membership.user_id

        await record_event(
            db,
            action="finding.status.change",
            resource_type="finding",
            resource_id=str(finding.id),
            result="allow",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"status": payload.status.value, "fingerprint": finding.fingerprint},
        )
    await db.commit()

    return FindingRead.model_validate(finding)


@router.post("/{finding_id}/duplicate", response_model=FindingRead)
async def link_finding_duplicate(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingDuplicateLink,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> FindingRead:
    """Record a human's explicit judgment that this finding and another
    describe the same underlying defect — the cross-engine dedup gap this
    codebase's own roadmap named rather than papering over with an
    invented similarity heuristic. Both findings must belong to this
    organization; `link_duplicate` enforces the rest (no self-link, no
    chains — see its own docstring).
    """
    finding = await _load(organization_id, finding_id, db)
    duplicate_of = await _load(organization_id, payload.duplicate_of_finding_id, db)

    try:
        finding = await link_duplicate(
            db,
            finding=finding,
            duplicate_of=duplicate_of,
            linked_by_user_id=membership.user_id,
            note=payload.note,
        )
    except FindingLinkError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    await record_event(
        db,
        action="finding.duplicate.linked",
        resource_type="finding",
        resource_id=str(finding.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"duplicate_of_finding_id": str(duplicate_of.id)},
    )
    await db.commit()

    return FindingRead.model_validate(finding)


@router.delete("/{finding_id}/duplicate", response_model=FindingRead)
async def unlink_finding_duplicate(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ANALYST)),  # noqa: B008
) -> FindingRead:
    finding = await _load(organization_id, finding_id, db)
    finding = await unlink_duplicate(db, finding=finding)

    await record_event(
        db,
        action="finding.duplicate.unlinked",
        resource_type="finding",
        resource_id=str(finding.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return FindingRead.model_validate(finding)


@router.get("/{finding_id}/duplicates", response_model=list[FindingRead])
async def list_finding_duplicates(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[FindingRead]:
    """Every finding currently linked as a duplicate of this one."""
    await _load(organization_id, finding_id, db)
    rows = await db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.duplicate_of_finding_id == finding_id,
        )
    )
    return [FindingRead.model_validate(row) for row in rows.scalars().all()]


async def _load(organization_id: uuid.UUID, finding_id: uuid.UUID, db: DbSession) -> Finding:
    finding = (
        await db.execute(
            select(Finding).where(
                Finding.id == finding_id, Finding.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding
