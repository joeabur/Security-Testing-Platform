import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession, require_membership
from app.models.organization import Membership, Organization, Role
from app.models.user import User
from app.schemas.organization import (
    MembershipInvite,
    MembershipRead,
    MembershipUpdate,
    OrganizationCreate,
    OrganizationRead,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])

_OWNER_DETAIL = "Only an owner can grant, change, or remove another owner"


async def _owner_count(db: AsyncSession, organization_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.count(Membership.id)).where(
            Membership.organization_id == organization_id, Membership.role == Role.OWNER
        )
    )
    return int(result.scalar_one())


_SLUG_INVALID_CHARS = re.compile(r"[^a-z0-9-]+")


def _slugify(name: str) -> str:
    base = _SLUG_INVALID_CHARS.sub("-", name.lower()).strip("-") or "org"
    return f"{base}-{uuid.uuid4().hex[:8]}"


@router.post("", response_model=OrganizationRead, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate, request: Request, current_user: CurrentUser, db: DbSession
) -> OrganizationRead:
    org = Organization(name=payload.name, slug=_slugify(payload.name))
    db.add(org)
    await db.flush()

    membership = Membership(user_id=current_user.id, organization_id=org.id, role=Role.OWNER)
    db.add(membership)
    await db.flush()

    await record_event(
        db,
        action="organization.create",
        resource_type="organization",
        resource_id=str(org.id),
        result="allow",
        organization_id=org.id,
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return OrganizationRead(id=org.id, name=org.name, slug=org.slug, role=Role.OWNER)


@router.get("", response_model=list[OrganizationRead])
async def list_organizations(current_user: CurrentUser, db: DbSession) -> list[OrganizationRead]:
    result = await db.execute(
        select(Membership)
        .where(Membership.user_id == current_user.id)
        .options(selectinload(Membership.organization))
    )
    memberships = result.scalars().all()
    return [
        OrganizationRead(
            id=m.organization.id, name=m.organization.name, slug=m.organization.slug, role=m.role
        )
        for m in memberships
    ]


@router.get("/{organization_id}", response_model=OrganizationRead)
async def get_organization(
    organization_id: uuid.UUID,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> OrganizationRead:
    org = membership.organization
    return OrganizationRead(id=org.id, name=org.name, slug=org.slug, role=membership.role)


@router.get("/{organization_id}/members", response_model=list[MembershipRead])
async def list_members(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[MembershipRead]:
    result = await db.execute(
        select(Membership)
        .where(Membership.organization_id == organization_id)
        .options(selectinload(Membership.user))
    )
    members = result.scalars().all()
    return [
        MembershipRead(
            id=m.id, user_id=m.user_id, email=m.user.email, full_name=m.user.full_name, role=m.role
        )
        for m in members
    ]


@router.post(
    "/{organization_id}/members", response_model=MembershipRead, status_code=status.HTTP_201_CREATED
)
async def invite_member(
    organization_id: uuid.UUID,
    payload: MembershipInvite,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> MembershipRead:
    """Add an existing user to the organization by email.

    Owner/Admin may grant membership, per docs/BUILD_SPEC.md §17.2 — except
    granting `Role.OWNER` itself, which only an existing owner may do. Without
    that carve-out an Admin could mint a co-owner (or a second account they
    control) and hand it authority equal to the org's own founder; `at_least`
    against `Role.OWNER` is true only for a caller who already is one, since
    owner is the single most senior role in `seniority_order`. This Phase-1
    version requires the invitee to already have an account; email
    invitations for not-yet-registered users are deferred (docs/roadmap.md).
    """
    if payload.role == Role.OWNER and not membership.role.at_least(Role.OWNER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_OWNER_DETAIL)

    result = await db.execute(select(User).where(User.email == payload.email))
    invitee = result.scalar_one_or_none()
    if invitee is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No registered user with that email")

    existing = await db.execute(
        select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == invitee.id
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="User is already a member")

    new_membership = Membership(
        user_id=invitee.id, organization_id=organization_id, role=payload.role
    )
    db.add(new_membership)
    await db.flush()

    await record_event(
        db,
        action="organization.member_added",
        resource_type="membership",
        resource_id=str(new_membership.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"invitee_id": str(invitee.id), "role": payload.role.value},
    )
    await db.commit()

    return MembershipRead(
        id=new_membership.id,
        user_id=invitee.id,
        email=invitee.email,
        full_name=invitee.full_name,
        role=new_membership.role,
    )


async def _load_target_member(
    db: AsyncSession, organization_id: uuid.UUID, member_id: uuid.UUID
) -> Membership:
    result = await db.execute(
        select(Membership)
        .where(Membership.id == member_id, Membership.organization_id == organization_id)
        .options(selectinload(Membership.user))
    )
    target = result.scalar_one_or_none()
    if target is None:
        # 404, not a 403 or an empty list: a member id from another
        # organization is not distinguishable from one that never existed,
        # the same non-disclosure `require_membership` already uses for the
        # organization itself.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Member not found")
    return target


@router.patch("/{organization_id}/members/{member_id}", response_model=MembershipRead)
async def update_member_role(
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    payload: MembershipUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> MembershipRead:
    """Change one member's role.

    Owner/Admin may change most roles, but only an existing owner may
    promote someone *to* owner or demote an existing owner *away from* it —
    the same carve-out `invite_member` applies, for the same reason: role is
    the one thing in this organization an Admin must not be able to grant to
    themselves or an accomplice. An organization's last owner cannot be
    demoted at all — refused with `409`, not merely discouraged — because
    doing so would leave the organization with no one who can perform an
    owner-only action, including undoing the mistake.
    """
    target = await _load_target_member(db, organization_id, member_id)

    role_changing_to_or_from_owner = Role.OWNER in (target.role, payload.role)
    if role_changing_to_or_from_owner and not membership.role.at_least(Role.OWNER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_OWNER_DETAIL)

    if (
        target.role == Role.OWNER
        and payload.role != Role.OWNER
        and await _owner_count(db, organization_id) <= 1
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Cannot change the last owner's role — promote another member first",
        )

    previous_role = target.role
    target.role = payload.role
    await db.flush()

    await record_event(
        db,
        action="organization.member_role_changed",
        resource_type="membership",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "target_user_id": str(target.user_id),
            "from_role": previous_role.value,
            "to_role": payload.role.value,
        },
    )
    await db.commit()

    return MembershipRead(
        id=target.id,
        user_id=target.user_id,
        email=target.user.email,
        full_name=target.user.full_name,
        role=target.role,
    )


@router.delete("/{organization_id}/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    """Remove a member from the organization.

    Only an owner may remove another owner, and an organization's last owner
    can never be removed — the same two rules `update_member_role` enforces,
    since a removal is just a role change to "none" for the purpose of both.
    """
    target = await _load_target_member(db, organization_id, member_id)

    if target.role == Role.OWNER:
        if not membership.role.at_least(Role.OWNER):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_OWNER_DETAIL)
        if await _owner_count(db, organization_id) <= 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail="Cannot remove the last owner — promote another member first",
            )

    await db.delete(target)

    await record_event(
        db,
        action="organization.member_removed",
        resource_type="membership",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"target_user_id": str(target.user_id), "role": target.role.value},
    )
    await db.commit()
