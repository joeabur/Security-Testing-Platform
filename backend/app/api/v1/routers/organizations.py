import re
import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession, require_membership
from app.core.config import get_settings
from app.core.invitation_email import InvitationEmailNotConfigured, send_invitation_email
from app.core.revocation import dependency as revocation
from app.db.tenant_context import set_tenant_context
from app.models.invitation import OrganizationInvitation, digest_of, mint_invitation_token
from app.models.organization import Membership, Organization, Role
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.auth import SessionRead
from app.schemas.organization import (
    InvitationAccept,
    InvitationRead,
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
    "/{organization_id}/members",
    response_model=MembershipRead | InvitationRead,
    status_code=status.HTTP_201_CREATED,
)
async def invite_member(
    organization_id: uuid.UUID,
    payload: MembershipInvite,
    request: Request,
    db: DbSession,
    current_user: CurrentUser,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> MembershipRead | InvitationRead:
    """Add an existing user to the organization by email, or — if no account
    exists for that address — create a pending invitation and email it.

    Owner/Admin may grant membership, per docs/BUILD_SPEC.md §17.2 — except
    granting `Role.OWNER` itself, which only an existing owner may do. Without
    that carve-out an Admin could mint a co-owner (or a second account they
    control) and hand it authority equal to the org's own founder; `at_least`
    against `Role.OWNER` is true only for a caller who already is one, since
    owner is the single most senior role in `seniority_order`. The same
    carve-out applies to a pending invitation for `Role.OWNER` — it is
    checked here, at issue time, rather than deferred to acceptance, so an
    Admin cannot queue up an owner-granting invitation on the chance they
    are later promoted before it is redeemed.

    The caller cannot tell from the response alone which of the two
    happened for an address they do not already know — `MembershipRead` and
    `InvitationRead` are deliberately different shapes (no `user_id` on the
    latter) rather than one shape with nullable fields, so "this person is
    not a member yet" is never something a reader has to infer from an
    absence.
    """
    if payload.role == Role.OWNER and not membership.role.at_least(Role.OWNER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_OWNER_DETAIL)

    result = await db.execute(select(User).where(User.email == payload.email))
    invitee = result.scalar_one_or_none()

    if invitee is None:
        return await _create_invitation(
            db,
            organization_id=organization_id,
            email=payload.email,
            role=payload.role,
            request=request,
            inviter=membership,
            current_user=current_user,
        )

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


async def _create_invitation(
    db: DbSession,
    *,
    organization_id: uuid.UUID,
    email: str,
    role: Role,
    request: Request,
    inviter: Membership,
    current_user: User,
) -> InvitationRead:
    """The not-yet-registered branch of `invite_member`.

    At most one live invitation per `(organization_id, email)`: a prior
    unused, unrevoked one is revoked first, the same "the link in your
    latest email is the one that works" rule `PasswordResetToken` already
    applies to itself — see that model's own docstring.
    """
    await db.execute(
        update(OrganizationInvitation)
        .where(
            OrganizationInvitation.organization_id == organization_id,
            OrganizationInvitation.email == email,
            OrganizationInvitation.used_at.is_(None),
            OrganizationInvitation.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(UTC))
    )

    settings = get_settings()
    token, digest = mint_invitation_token()
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.invitation_token_ttl_minutes)
    invitation = OrganizationInvitation(
        organization_id=organization_id,
        email=email,
        role=role,
        token_digest=digest,
        invited_by_user_id=inviter.user_id,
        expires_at=expires_at,
    )
    db.add(invitation)
    await db.flush()

    base = (settings.public_base_url or "").rstrip("/")
    accept_url = f"{base}/accept-invitation?token={quote(token)}"
    with suppress(InvitationEmailNotConfigured):
        await send_invitation_email(
            settings,
            to_address=email,
            organization_name=inviter.organization.name,
            role=role,
            invited_by_name=current_user.full_name or current_user.email,
            accept_url=accept_url,
        )

    await record_event(
        db,
        action="organization.invitation_created",
        resource_type="organization_invitation",
        resource_id=str(invitation.id),
        result="allow",
        organization_id=organization_id,
        user_id=inviter.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"email": email, "role": role.value},
    )
    await db.commit()

    return InvitationRead(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
    )


@router.get("/{organization_id}/invitations", response_model=list[InvitationRead])
async def list_invitations(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> list[OrganizationInvitation]:
    """Pending invitations only — used, revoked and expired ones are not
    actionable by an admin reading this list, and keeping them out is
    simpler than asking the reader to filter on three different columns
    themselves."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(OrganizationInvitation)
        .where(
            OrganizationInvitation.organization_id == organization_id,
            OrganizationInvitation.used_at.is_(None),
            OrganizationInvitation.revoked_at.is_(None),
            OrganizationInvitation.expires_at > now,
        )
        .order_by(OrganizationInvitation.created_at.desc())
    )
    return list(result.scalars().all())


@router.delete(
    "/{organization_id}/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def revoke_invitation(
    organization_id: uuid.UUID,
    invitation_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    result = await db.execute(
        select(OrganizationInvitation).where(
            OrganizationInvitation.id == invitation_id,
            OrganizationInvitation.organization_id == organization_id,
        )
    )
    invitation = result.scalar_one_or_none()
    if invitation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Invitation not found")

    if invitation.usable_at():
        invitation.revoked_at = datetime.now(UTC)
        await record_event(
            db,
            action="organization.invitation_revoked",
            resource_type="organization_invitation",
            resource_id=str(invitation.id),
            result="allow",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"email": invitation.email},
        )
    await db.commit()


@router.post(
    "/invitations/accept",
    response_model=MembershipRead,
    status_code=status.HTTP_201_CREATED,
)
async def accept_invitation(
    payload: InvitationAccept,
    request: Request,
    db: DbSession,
    current_user: CurrentUser,
) -> MembershipRead:
    """Redeem an invitation token, as the now-authenticated person it was
    sent to.

    Deliberately not folded into `POST /auth/register` — accepting is its
    own action, independent of whether the invitee registered just now to
    redeem it or already had an account under that address before the
    invitation existed. The caller must already be signed in: the token
    alone proves which address was invited, not who is allowed to act as
    that address, so the usual session/bearer-token authentication still
    does the identity proof here, same as any other authenticated write.

    No `{organization_id}` in the path, unlike every other route in this
    file: which organization this is for is exactly what the token encodes,
    so asking the caller to also supply it would be redundant at best and a
    second thing that could disagree with the token at worst. That also
    means this route is not organization-scoped the way
    `tests/security/test_authorization_matrix.py` means that term — there is
    no `require_membership` dependency to declare a minimum role, on
    purpose, since the entire point is a caller who is *not yet* a member.

    The token lookup itself happens before `set_tenant_context` can be
    called — the same shape `resolve_api_key`'s `ApiKey.key_id` lookup
    already has, for the same reason: which organization a presented secret
    belongs to is precisely what looking it up *tells* you, not something
    knowable beforehand. Once the invitation's organization is known, every
    later query in this handler runs under it like any other organization-
    scoped write.
    """
    digest = digest_of(payload.token)
    result = await db.execute(
        select(OrganizationInvitation).where(OrganizationInvitation.token_digest == digest)
    )
    invitation = result.scalar_one_or_none()

    if invitation is None or not invitation.usable_at():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired invitation")

    if invitation.email.lower() != current_user.email.lower():
        # Not found, not forbidden: confirming a valid token exists for a
        # *different* address than the caller's own would let an attacker
        # use a guessed-wrong caller identity to probe who was invited.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired invitation")

    organization_id = invitation.organization_id
    await set_tenant_context(db, organization_id)

    existing = await db.execute(
        select(Membership).where(
            Membership.organization_id == organization_id, Membership.user_id == current_user.id
        )
    )
    if existing.scalar_one_or_none() is not None:
        invitation.used_at = datetime.now(UTC)
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="User is already a member")

    new_membership = Membership(
        user_id=current_user.id, organization_id=organization_id, role=invitation.role
    )
    db.add(new_membership)
    invitation.used_at = datetime.now(UTC)
    await db.flush()

    await record_event(
        db,
        action="organization.invitation_accepted",
        resource_type="membership",
        resource_id=str(new_membership.id),
        result="allow",
        organization_id=organization_id,
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        metadata={"invitation_id": str(invitation.id), "role": invitation.role.value},
    )
    await db.commit()

    return MembershipRead(
        id=new_membership.id,
        user_id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
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


@router.get(
    "/{organization_id}/members/{member_id}/sessions", response_model=list[SessionRead]
)
async def list_member_sessions(
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> list[SessionRead]:
    """An admin's view of a fellow member's active sessions.

    `GET /auth/sessions` is deliberately scoped to the caller's own account
    (see its own docstring) — there was no way for an admin to answer "is
    this person's account still logged in somewhere I don't expect" for
    anyone but themselves. This closes that gap the same way every other
    admin action here does: `member_id` is a `Membership` row, not a bare
    user id, so `_load_target_member`'s 404-not-403 non-disclosure applies
    identically, and the admin never needs to already know a user id outside
    their own organization to ask the question.
    """
    target = await _load_target_member(db, organization_id, member_id)

    now = datetime.now(UTC)
    result = await db.execute(
        select(UserSession)
        .where(
            UserSession.user_id == target.user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .order_by(UserSession.created_at.desc())
    )
    current_jti = getattr(request.state, "token_jti", None)
    return [
        SessionRead(
            id=session.id,
            created_at=session.created_at,
            expires_at=session.expires_at,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            is_current=(session.jti == current_jti),
        )
        for session in result.scalars().all()
    ]


@router.delete(
    "/{organization_id}/members/{member_id}/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_member_session(
    organization_id: uuid.UUID,
    member_id: uuid.UUID,
    session_id: uuid.UUID,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> None:
    """Force-revoke one of a fellow member's sessions.

    Same carve-out `update_member_role`/`remove_member` already enforce for
    an Owner: an Admin may revoke another Admin's, Security Engineer's,
    Analyst's, or Viewer's session, but not an Owner's — an Admin who could
    unilaterally force an Owner out of every active session could disrupt
    the one role that could undo whatever damage the Admin is doing, the
    same reasoning that already stops an Admin from demoting or removing an
    Owner outright.

    404, not 403, for a session that exists but does not belong to this
    member — the same non-disclosure `revoke_session` itself already
    applies to a caller revoking a session that is not theirs.
    """
    target = await _load_target_member(db, organization_id, member_id)
    if target.role == Role.OWNER and not membership.role.at_least(Role.OWNER):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=_OWNER_DETAIL)

    session = await db.get(UserSession, session_id)
    if session is None or session.user_id != target.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Session not found")

    if session.revoked_at is None:
        ttl = int((session.expires_at - datetime.now(UTC)).total_seconds())
        if ttl > 0:
            await revocation.revoke(session.jti, ttl)
        session.revoked_at = datetime.now(UTC)
        await record_event(
            db,
            action="auth.session_revoke",
            resource_type="user_session",
            resource_id=str(session.id),
            result="allow",
            organization_id=organization_id,
            user_id=membership.user_id,
            ip_address=request.client.host if request.client else None,
            metadata={"target_user_id": str(target.user_id)},
        )
        await db.commit()
