import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.security import (
    InvalidTokenError,
    decode_access_token,
    expires_at,
    issued_at_precise,
    token_id,
)
from app.core.config import get_settings
from app.core.revocation import dependency as revocation
from app.core.revocation.contract import RevocationStoreUnavailable
from app.db.session import get_db
from app.db.tenant_context import set_current_organization
from app.models.api_key import ApiKey, split_token
from app.models.organization import Membership, Role
from app.models.user import User

DbSession = Annotated[AsyncSession, Depends(get_db)]


def _extract_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header[7:]
    settings = get_settings()
    return request.cookies.get(settings.session_cookie_name)


async def resolve_api_key(token: str, db: AsyncSession) -> ApiKey | None:
    """The key a presented token names, if it is one and it is usable.

    Returns `None` for anything that is not a well-formed key so the caller
    can fall through to the JWT path; raises only when the token *is* a key
    and that key cannot be used, because "your key is revoked" and "your
    token is not a key" are different problems for the operator reading the
    CI log.
    """
    parts = split_token(token)
    if parts is None:
        return None
    key_id, secret = parts

    key = (await db.execute(select(ApiKey).where(ApiKey.key_id == key_id))).scalar_one_or_none()
    # A wrong secret and an unknown id give the same answer, so a caller
    # cannot learn which ids exist.
    if key is None or not key.matches(secret):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    if not key.usable_at():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="API key is revoked or expired")
    return key


async def get_current_user(request: Request, db: DbSession) -> User:
    token = _extract_token(request)
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    # An API key authenticates as the member who created it, with the key's
    # own authority rather than that member's — `require_membership` reads
    # the key off the request and caps the role. Without that cap a CI key
    # minted by an owner would act as an owner.
    api_key = await resolve_api_key(token, db)
    if api_key is not None:
        request.state.api_key = api_key
        api_key.last_used_at = datetime.now(UTC)
        await db.commit()
        if api_key.created_by_user_id is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="the user who created this API key no longer exists",
            )
        user = await db.get(User, api_key.created_by_user_id)
        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
        return user

    try:
        payload = decode_access_token(token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        ) from exc

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject") from exc

    # Revocation is checked here, before the database round trip below, for
    # the same reason budget is consumed before the login lookup: a request
    # for a killed token should not do any more work than necessary to refuse
    # it. This fails CLOSED on a store failure — the exact opposite of the
    # rate limiter's choice a few lines of reasoning away in
    # app/core/ratelimit/, and `app/core/revocation/contract.py` explains why
    # the two controls make opposite trades.
    jti = token_id(payload)
    try:
        revoked = await revocation.is_revoked(jti)
    except RevocationStoreUnavailable as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Could not verify this token has not been revoked. Try again.",
        ) from exc
    if revoked:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    # A "log out everywhere" bulk cutover, checked against Postgres — durable
    # across a Redis restart precisely because the per-token deny-list is not.
    if user.tokens_valid_after is not None and issued_at_precise(payload) < user.tokens_valid_after:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    # The handler for logout needs the jti and expiry of *this* token to
    # revoke it precisely, and has no other way to reach them — the request
    # only carries the encoded string. Stashed on request.state, the same
    # pattern `resolve_api_key` above uses for the API key it resolved.
    request.state.token_jti = jti
    request.state.token_exp = expires_at(payload)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def _lower_of(first: Role, second: Role) -> Role:
    order = Role.seniority_order()
    return first if order.index(first) >= order.index(second) else second


def require_membership(
    minimum_role: Role = Role.VIEWER,
) -> Callable[[uuid.UUID, Request, User, AsyncSession], Awaitable[Membership]]:
    """Dependency factory enforcing RBAC on an `organization_id` path parameter.

    A user who is not a member of the organization gets 404, not 403 — this
    avoids confirming the organization exists to a caller with no legitimate
    reason to know, and is the behaviour the tenant-isolation tests in
    docs/BUILD_SPEC.md §24 assert on ("wrong organization -> BLOCKED").
    """

    async def dependency(
        organization_id: uuid.UUID, request: Request, current_user: CurrentUser, db: DbSession
    ) -> Membership:
        # Set before the membership check itself (rather than after it
        # succeeds) so that every query this request makes from here on,
        # including this one, runs under the Postgres session variable RLS
        # policies read — this is what makes forgetting an
        # `organization_id` filter fail closed instead of silently
        # succeeding.
        set_current_organization(organization_id)
        result = await db.execute(
            select(Membership)
            .where(
                Membership.organization_id == organization_id,
                Membership.user_id == current_user.id,
            )
            .options(selectinload(Membership.organization))
        )
        membership = result.scalar_one_or_none()
        if membership is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")

        effective = membership.role
        api_key = getattr(request.state, "api_key", None)
        if api_key is not None:
            if api_key.organization_id != organization_id:
                # A key belongs to one organization. Same 404 as a
                # non-member, for the same reason.
                raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Organization not found")
            # The lower of the two: a key cannot exceed its scopes, and it
            # cannot exceed what its creator still has.
            effective = _lower_of(membership.role, api_key.role)

        if not effective.at_least(minimum_role):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{minimum_role.value}' or higher",
            )
        return membership

    # Recorded on the closure so the authorization pass in
    # `tests/security/test_authorization_matrix.py` can read every route's
    # declared minimum role and prove that no organization-scoped endpoint
    # exists without one. Introspection beats a hand-maintained list: a list
    # is only as good as whoever remembered to update it.
    dependency.minimum_role = minimum_role  # type: ignore[attr-defined]
    return dependency
