"""Platform-level authority — above every organization's own `Role.OWNER`.

Every other authorization check in this codebase is organization-scoped:
`require_membership` reads an `organization_id` path parameter and answers
"what may this caller do *in this organization*" (app/auth/dependencies.py).
Nothing until now has answered "what may this caller do to the deployment
itself" — grant or revoke another account's platform-wide authority, or
anything else no single organization is the right scope for.

`User.platform_role` (app/models/user.py) is that answer, and it is set in
exactly two ways: once, at deployment setup, by
`backend/scripts/bootstrap_platform_owner.py` reading
`settings.platform_owner_bootstrap_email`; or afterwards, by an existing
platform owner through the endpoints below. Nothing in this module or that
script compares a request's own data against a hard-coded address — the
bootstrap email is read once, to find the *first* owner's account, and never
touched again. Authorization from then on is purely the stored column,
checked by `require_platform_owner`.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_platform_owner
from app.models.user import PlatformRole, User
from app.schemas.platform import PlatformOwnerGrant, PlatformOwnerRead

router = APIRouter(prefix="/platform", tags=["platform"])


def _read(user: User) -> PlatformOwnerRead:
    return PlatformOwnerRead(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        platform_role=PlatformRole.OWNER,
    )


async def _platform_owner_count(db: AsyncSession) -> int:
    result = await db.execute(
        select(func.count(User.id)).where(User.platform_role == PlatformRole.OWNER)
    )
    return int(result.scalar_one())


@router.get("/owners", response_model=list[PlatformOwnerRead])
async def list_platform_owners(
    db: DbSession,
    current_user: User = Depends(require_platform_owner),  # noqa: B008
) -> list[PlatformOwnerRead]:
    result = await db.execute(
        select(User).where(User.platform_role == PlatformRole.OWNER).order_by(User.email)
    )
    return [_read(user) for user in result.scalars().all()]


@router.post("/owners", response_model=PlatformOwnerRead, status_code=status.HTTP_201_CREATED)
async def grant_platform_owner(
    payload: PlatformOwnerGrant,
    request: Request,
    db: DbSession,
    current_user: User = Depends(require_platform_owner),  # noqa: B008
) -> PlatformOwnerRead:
    """Grant platform-owner authority to an already-registered user.

    Mirrors `organizations.invite_member`'s own carve-out, at higher stakes:
    the grantee must already have an account, and there is no email-
    invitation flow here either — a not-yet-registered address cannot be a
    platform owner by definition, since there is no user row yet to set the
    column on.
    """
    result = await db.execute(select(User).where(User.email == payload.email))
    grantee = result.scalar_one_or_none()
    if grantee is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No registered user with that email")
    if grantee.platform_role == PlatformRole.OWNER:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="User is already a platform owner")

    grantee.platform_role = PlatformRole.OWNER
    await db.flush()

    await record_event(
        db,
        action="platform_owner.grant",
        resource_type="user",
        resource_id=str(grantee.id),
        result="allow",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        metadata={"grantee_id": str(grantee.id), "grantee_email": grantee.email},
    )
    await db.commit()
    return _read(grantee)


@router.delete("/owners/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_platform_owner(
    user_id: uuid.UUID,
    request: Request,
    db: DbSession,
    current_user: User = Depends(require_platform_owner),  # noqa: B008
) -> None:
    """Revoke platform-owner authority.

    The platform's last owner can never be revoked — refused with `409`, the
    same protection `organizations.remove_member` gives an organization's
    last owner, for the same reason: it would leave nobody who can perform a
    platform-owner-only action, including undoing the mistake.
    """
    target = await db.get(User, user_id)
    if target is None or target.platform_role != PlatformRole.OWNER:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Platform owner not found")

    if await _platform_owner_count(db) <= 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Cannot revoke the last platform owner — grant another owner first",
        )

    target.platform_role = None
    await db.flush()

    await record_event(
        db,
        action="platform_owner.revoke",
        resource_type="user",
        resource_id=str(target.id),
        result="allow",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        metadata={"revoked_user_id": str(target.id), "revoked_email": target.email},
    )
    await db.commit()
