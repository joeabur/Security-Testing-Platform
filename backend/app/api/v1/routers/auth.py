import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update

from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession
from app.auth.security import (
    create_access_token,
    decode_access_token,
    expires_at,
    hash_password,
    token_id,
    verify_password,
)
from app.core.config import Settings, get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf import enforce as csrf_enforce
from app.core.csrf import tokens as csrf_tokens
from app.core.oauth import providers as oauth_providers
from app.core.oauth.state import OAuthStateInvalid, OAuthStateStore, OAuthStateUnavailable
from app.core.password_reset_email import PasswordResetEmailNotConfigured, send_password_reset_email
from app.core.ratelimit import dependency as ratelimit
from app.core.revocation import dependency as revocation
from app.models.oauth import OAuthIdentity, OAuthProvider
from app.models.password_reset import PasswordResetToken, digest_of, mint_reset_token
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    OAuthProvidersRead,
    RegisterRequest,
    ResetPasswordRequest,
    SessionRead,
    TokenResponse,
    UserRead,
)

router = APIRouter(prefix="/auth", tags=["auth"])


async def _record_session(
    db: DbSession, *, user_id: uuid.UUID, token: str, request: Request
) -> None:
    """A row for `GET /auth/sessions` to list, alongside the cookie/token
    `_set_session_cookie` hands to the caller. Decoding the token just
    encoded is one redundant pass over it, in exchange for not changing
    `create_access_token`'s signature for every other caller.
    """
    payload = decode_access_token(token)
    db.add(
        UserSession(
            user_id=user_id,
            jti=token_id(payload),
            expires_at=expires_at(payload),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    )


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )
    # A CSRF token bound to the session just issued. Set together, so a
    # session can never exist without one — a browser holding a session but no
    # token would be unable to make any state-changing request, which is a
    # broken product rather than a secure one.
    response.set_cookie(
        key=csrf_enforce.COOKIE_NAME,
        value=csrf_tokens.issue(token, secret=settings.effective_csrf_secret),
        # NOT httponly, on purpose: the page has to read this to echo it back.
        # Safe because the token authenticates nothing by itself — it proves
        # only that the request came from a page able to read this site's
        # cookies, which is exactly the claim CSRF needs.
        httponly=False,
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )


@router.get("/csrf", status_code=status.HTTP_204_NO_CONTENT)
async def issue_anonymous_csrf_token(response: Response) -> None:
    """Hand an unauthenticated caller a token for `/auth/login` or `/auth/register`.

    There is no session yet for either of those to bind a token to
    (`app/core/csrf/anon.py` explains why a merely self-signed one is not
    enough on its own); this is the endpoint a login or registration page
    calls first to get one. `GET`, so it needs none itself.
    """
    settings = get_settings()
    response.set_cookie(
        key=csrf_anon.cookie_name(secure=settings.session_cookie_secure),
        value=csrf_anon.issue(secret=settings.effective_csrf_secret),
        httponly=False,  # the page must read this to echo it back
        secure=settings.session_cookie_secure,
        samesite="lax",
        max_age=600,
        path="/",
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse:
    # Registration is unauthenticated and creates rows, so it is bounded per
    # IP before anything is written. Doing this first also means a throttled
    # caller cannot use the endpoint to probe which addresses are taken.
    await ratelimit.enforce(request, "register")

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none() is not None:
        await record_event(
            db,
            action="auth.register",
            resource_type="user",
            result="deny",
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "email_already_registered"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Email is already registered")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()

    token = create_access_token(subject=user.id)
    await _record_session(db, user_id=user.id, token=token, request=request)
    await record_event(
        db,
        action="auth.register",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    _set_session_cookie(response, token)
    return TokenResponse(access_token=token, user=UserRead.model_validate(user))


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse:
    # Budget is consumed *before* the lookup and identically for every
    # address, so a throttled response cannot tell a caller whether the
    # account exists — the limiter must not become the enumeration oracle the
    # handler below is careful not to be.
    await ratelimit.enforce(request, "login", identity=payload.email)

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    # `password_hash` is null for an OAuth-only account (app/models/user.py);
    # such an account has no local password to check, so it fails the same
    # generic way a wrong password would rather than calling into Argon2 with
    # a null hash.
    if (
        user is None
        or user.password_hash is None
        or not verify_password(payload.password, user.password_hash)
    ):
        await record_event(
            db,
            action="auth.login",
            resource_type="user",
            result="deny",
            ip_address=request.client.host if request.client else None,
            metadata={"email": payload.email},
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        await record_event(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=str(user.id),
            result="deny",
            user_id=user.id,
            metadata={"reason": "inactive_account"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Account is inactive")

    token = create_access_token(subject=user.id)
    await _record_session(db, user_id=user.id, token=token, request=request)
    # A correct password clears the counters. Only failures should accumulate:
    # counting successes would let a busy legitimate user throttle themselves,
    # which is how a rate limit gets switched off in production.
    await ratelimit.clear(request, "login", identity=payload.email)
    await record_event(
        db,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    _set_session_cookie(response, token)
    return TokenResponse(access_token=token, user=UserRead.model_validate(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request, response: Response, current_user: CurrentUser, db: DbSession
) -> None:
    """End *this* session. Other tokens for this user, if any exist, keep
    working — see `/auth/logout-all` for "kick everything"."""
    # Set only when authentication went through the JWT path — an API key has
    # its own revocation (`ApiKey.revoked_at`) and never reaches this store.
    jti = getattr(request.state, "token_jti", None)
    if jti is not None:
        exp: datetime = request.state.token_exp
        ttl = int((exp - datetime.now(UTC)).total_seconds())
        await revocation.revoke(jti, ttl)
        # The deny-list entry above is what actually stops this token working
        # again; this update is so `GET /auth/sessions` stops listing it as
        # active. Losing one without the other is not a security gap either
        # way — see the `UserSession` model docstring.
        await db.execute(
            update(UserSession)
            .where(UserSession.jti == jti, UserSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )

    await record_event(
        db,
        action="auth.logout",
        resource_type="user",
        resource_id=str(current_user.id),
        result="allow",
        user_id=current_user.id,
    )
    await db.commit()
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(csrf_enforce.COOKIE_NAME, path="/")


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(response: Response, current_user: CurrentUser, db: DbSession) -> None:
    """Kill every token this user has ever been issued, this one included.

    The response to "I think my token leaked" or "I logged in on a shared
    machine and forgot to log out". A bulk cutover on the user row, not a
    loop over every session row this platform now tracks
    (`app/models/user_session.py`) — the cutoff invalidates a token by *when*
    it was issued, so it works even for a token whose row was lost, and
    covers one issued the instant before this request commits, which a loop
    over rows fetched slightly earlier could not.
    """
    # Compared against a token's precise `iat_us` claim
    # (app/auth/security.py), not the standard second-granularity `iat` — see
    # that module for why the distinction matters here specifically.
    current_user.tokens_valid_after = datetime.now(UTC)
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    await record_event(
        db,
        action="auth.logout_all",
        resource_type="user",
        resource_id=str(current_user.id),
        result="allow",
        user_id=current_user.id,
    )
    await db.commit()
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(csrf_enforce.COOKIE_NAME, path="/")


@router.get("/me", response_model=UserRead)
async def me(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)


@router.get("/sessions", response_model=list[SessionRead])
async def list_sessions(
    request: Request, current_user: CurrentUser, db: DbSession
) -> list[SessionRead]:
    """Every session this account can currently authenticate with.

    The gap this closes: previously the only answers to "what is logged in
    as me right now" were "this one" (`/auth/logout`) or "everything"
    (`/auth/logout-all`) — there was nothing to list. Scoped to the caller's
    own account only; there is no admin view of another user's sessions
    here, the same boundary `/auth/logout-all` already draws.
    """
    now = datetime.now(UTC)
    result = await db.execute(
        select(UserSession)
        .where(
            UserSession.user_id == current_user.id,
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


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(session_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> None:
    """Revoke one session by name — the piece `/auth/logout` (this one) and
    `/auth/logout-all` (every one) could not express between them.

    404 rather than 403 for a session belonging to someone else, the same
    non-disclosure `require_membership` uses for another organization's
    resource: a caller with no legitimate reason to know already cannot tell
    "not yours" from "does not exist" for anything else on this API either.
    """
    session = await db.get(UserSession, session_id)
    if session is None or session.user_id != current_user.id:
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
            user_id=current_user.id,
        )
        await db.commit()


# --- Social OAuth login (Google, GitHub) -----------------------------------
#
# `/authorize` and `/callback` are navigated by the browser directly (a link,
# then a provider-issued redirect), never called with `fetch` — so failures
# below send the browser back to the frontend's login page with an
# `oauth_error` query parameter rather than raising an API-style HTTPException
# a person would otherwise see rendered as raw JSON mid-flow. Success does the
# same: it 302s with the session cookie already set on the redirect response,
# exactly the way `_set_session_cookie` sets it after a password login.


def _oauth_provider_or_404(provider: str) -> OAuthProvider:
    try:
        return OAuthProvider(provider)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown OAuth provider") from exc


def _require_oauth_ready(settings: Settings, provider: OAuthProvider) -> str:
    """The provider is configured and there is somewhere to send the browser
    back to. Returns the callback `redirect_uri` a caller needs next.

    404 for every failure mode here, not just an unconfigured provider: from
    the caller's perspective "not configured" and "half-configured" both mean
    the same thing — this login option does not work — and there is nothing
    an unauthenticated caller can do about either.
    """
    if not oauth_providers.enabled(settings, provider) or not settings.public_base_url:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="OAuth provider not available")
    try:
        return oauth_providers.redirect_uri_for(settings, provider)
    except oauth_providers.OAuthProviderDisabled as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="OAuth provider not available"
        ) from exc


@router.get("/oauth/providers", response_model=OAuthProvidersRead)
async def oauth_providers_available() -> OAuthProvidersRead:
    settings = get_settings()
    return OAuthProvidersRead(
        google=settings.google_oauth_enabled, github=settings.github_oauth_enabled
    )


@router.get("/oauth/{provider}/authorize")
async def oauth_authorize(provider: str, request: Request) -> RedirectResponse:
    settings = get_settings()
    provider_enum = _oauth_provider_or_404(provider)
    redirect_uri = _require_oauth_ready(settings, provider_enum)

    try:
        state = await OAuthStateStore().issue(provider=provider_enum.value)
    except OAuthStateUnavailable as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="OAuth login is temporarily unavailable"
        ) from exc

    url = oauth_providers.authorize_url(
        settings, provider_enum, redirect_uri=redirect_uri, state=state
    )
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


def _oauth_error_redirect(settings: Settings, code: str) -> RedirectResponse:
    base = (settings.public_base_url or "").rstrip("/")
    return RedirectResponse(
        f"{base}/login?oauth_error={quote(code)}", status_code=status.HTTP_302_FOUND
    )


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str, request: Request, response: Response, db: DbSession
) -> RedirectResponse:
    settings = get_settings()
    provider_enum = _oauth_provider_or_404(provider)
    redirect_uri = _require_oauth_ready(settings, provider_enum)

    await ratelimit.enforce(request, "oauth_callback")

    query = request.query_params
    if query.get("error"):
        return _oauth_error_redirect(settings, "provider_denied")
    code = query.get("code")
    state = query.get("state")
    if not code or not state:
        return _oauth_error_redirect(settings, "missing_code_or_state")

    try:
        await OAuthStateStore().consume(state, provider=provider_enum.value)
    except OAuthStateInvalid:
        return _oauth_error_redirect(settings, "invalid_state")
    except OAuthStateUnavailable:
        return _oauth_error_redirect(settings, "service_unavailable")

    try:
        profile = await oauth_providers.exchange_code_for_profile(
            settings, provider_enum, code=code, redirect_uri=redirect_uri
        )
    except (oauth_providers.OAuthExchangeError, oauth_providers.OAuthProviderDisabled):
        return _oauth_error_redirect(settings, "exchange_failed")

    identity_result = await db.execute(
        select(OAuthIdentity).where(
            OAuthIdentity.provider == provider_enum.value,
            OAuthIdentity.provider_user_id == profile.provider_user_id,
        )
    )
    identity = identity_result.scalar_one_or_none()

    is_new_account = False
    if identity is not None:
        user = await db.get(User, identity.user_id)
        if user is None:
            return _oauth_error_redirect(settings, "account_missing")
    else:
        existing_user_result = await db.execute(select(User).where(User.email == profile.email))
        existing_user = existing_user_result.scalar_one_or_none()
        if existing_user is not None:
            # Never silently link — see app/models/oauth.py's module
            # docstring for why matching by email alone would be unsafe.
            await record_event(
                db,
                action="auth.oauth_login",
                resource_type="user",
                resource_id=str(existing_user.id),
                result="deny",
                ip_address=request.client.host if request.client else None,
                metadata={"provider": provider_enum.value, "reason": "email_already_registered"},
            )
            await db.commit()
            return _oauth_error_redirect(settings, "email_already_registered")

        user = User(email=profile.email, full_name=profile.full_name, password_hash=None)
        db.add(user)
        await db.flush()
        db.add(
            OAuthIdentity(
                user_id=user.id,
                provider=provider_enum.value,
                provider_user_id=profile.provider_user_id,
                email_at_link=profile.email,
            )
        )
        is_new_account = True

    if not user.is_active:
        await record_event(
            db,
            action="auth.oauth_login",
            resource_type="user",
            resource_id=str(user.id),
            result="deny",
            metadata={"provider": provider_enum.value, "reason": "inactive_account"},
        )
        await db.commit()
        return _oauth_error_redirect(settings, "account_inactive")

    token = create_access_token(subject=user.id)
    await _record_session(db, user_id=user.id, token=token, request=request)
    await record_event(
        db,
        action="auth.oauth_register" if is_new_account else "auth.oauth_login",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata={"provider": provider_enum.value},
    )
    await db.commit()

    base = (settings.public_base_url or "").rstrip("/")
    destination = f"{base}/organizations/new" if is_new_account else f"{base}/dashboard"
    redirect = RedirectResponse(destination, status_code=status.HTTP_302_FOUND)
    _set_session_cookie(redirect, token)
    return redirect


# --- Forgot / reset password -------------------------------------------------


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(
    payload: ForgotPasswordRequest, request: Request, db: DbSession
) -> None:
    """Always 202, whether or not the address is registered, has no local
    password, or the platform has no mail relay configured — the same
    non-enumerating shape `/auth/login` uses. Only a configured, matching,
    password-having account ever actually gets a token or an email."""
    await ratelimit.enforce(request, "forgot_password")
    settings = get_settings()

    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user is not None and user.password_hash is not None and settings.password_reset_enabled:
        # At most one live link per user: an older, unused token is deleted
        # rather than merely outlived, so "the link in your latest email" is
        # always the true statement — see PasswordResetToken's docstring.
        await db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=datetime.now(UTC))
        )
        token, digest = mint_reset_token()
        expires_at_value = datetime.now(UTC) + timedelta(
            minutes=settings.password_reset_token_ttl_minutes
        )
        db.add(
            PasswordResetToken(user_id=user.id, token_digest=digest, expires_at=expires_at_value)
        )
        base = (settings.public_base_url or "").rstrip("/")
        reset_url = f"{base}/reset-password?token={quote(token)}"
        with suppress(PasswordResetEmailNotConfigured):
            await send_password_reset_email(settings, to_address=user.email, reset_url=reset_url)
        await record_event(
            db,
            action="auth.forgot_password",
            resource_type="user",
            resource_id=str(user.id),
            result="allow",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
        )
    else:
        await record_event(
            db,
            action="auth.forgot_password",
            resource_type="user",
            result="deny",
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "no_matching_password_account"},
        )
    await db.commit()


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(payload: ResetPasswordRequest, request: Request, db: DbSession) -> None:
    """Consumes the token and sets a new password. Deliberately does not
    also start a session — the caller has proven control of an email inbox,
    not (yet) presented on a browser worth trusting with a cookie; they are
    sent back to `/login` to sign in with the new password, same as any
    other first use of a credential.

    Every existing session is invalidated (`tokens_valid_after`), the same
    `logout-all` mechanism a "log out everywhere" request uses — a password
    reset is exactly the "I think this account was compromised" case that
    exists for.
    """
    digest = digest_of(payload.token)
    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_digest == digest)
    )
    reset_token = result.scalar_one_or_none()

    if reset_token is None or not reset_token.usable_at():
        await record_event(
            db,
            action="auth.reset_password",
            resource_type="password_reset_token",
            result="deny",
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "invalid_or_expired_token"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    user = await db.get(User, reset_token.user_id)
    if user is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    now = datetime.now(UTC)
    user.password_hash = hash_password(payload.new_password)
    user.tokens_valid_after = now
    reset_token.used_at = now
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await record_event(
        db,
        action="auth.reset_password",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()
