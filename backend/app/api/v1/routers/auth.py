import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select, update

from app.audit.service import record_event
from app.auth.dependencies import CurrentUser, DbSession
from app.auth.security import (
    InvalidTotpChallengeError,
    create_access_token,
    create_totp_challenge_token,
    decode_access_token,
    decode_totp_challenge_token,
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
from app.core.twofactor import challenge_store, totp
from app.models.oauth import OAuthIdentity, OAuthProvider
from app.models.password_reset import PasswordResetToken, digest_of, mint_reset_token
from app.models.totp_recovery_code import TotpRecoveryCode, mint_recovery_codes
from app.models.totp_recovery_code import digest_of as recovery_digest_of
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
    TotpChallengeResponse,
    TotpDisableRequest,
    TotpEnableRequest,
    TotpEnableResponse,
    TotpLoginRequest,
    TotpSetupResponse,
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


@router.post("/login", response_model=TokenResponse | TotpChallengeResponse)
async def login(
    payload: LoginRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse | TotpChallengeResponse:
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

    # The password is correct, so the rate-limit counters clear here — same
    # as the unconditional-success path below — whether or not a second
    # factor is still owed. A wrong TOTP code afterward is bounded by its
    # own `login_2fa` budget (`POST /auth/login/2fa`), not this one.
    await ratelimit.clear(request, "login", identity=payload.email)

    if user.totp_enabled:
        challenge = create_totp_challenge_token(subject=user.id)
        await record_event(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=str(user.id),
            result="allow",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
            metadata={"totp_required": True},
        )
        await db.commit()
        return TotpChallengeResponse(challenge=challenge)

    token = create_access_token(subject=user.id)
    await _record_session(db, user_id=user.id, token=token, request=request)
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
    own account only, the same boundary `/auth/logout-all` already draws.
    An organization admin's equivalent view of a fellow member's sessions is
    a separate, org-scoped pair of endpoints —
    `GET/DELETE .../organizations/{organization_id}/members/{member_id}/sessions`
    in `app/api/v1/routers/organizations.py` — not a wider version of this
    one.
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
async def forgot_password(payload: ForgotPasswordRequest, request: Request, db: DbSession) -> None:
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


# --- Two-factor authentication (TOTP) ---------------------------------------


def _totp_key_or_503(settings: Settings) -> bytes:
    key = settings.totp_encryption_key_bytes
    if key is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Two-factor authentication is not configured on this deployment",
        )
    return key


async def _verify_totp_or_recovery_code(db: DbSession, user: User, code: str) -> bool:
    """True and, for a recovery code, marks it used — the caller commits.
    False leaves the database untouched either way."""
    settings = get_settings()
    key = settings.totp_encryption_key_bytes
    if user.totp_secret_encrypted is not None and key is not None:
        secret = totp.decrypt_secret(user.totp_secret_encrypted, key=key)
        if totp.verify_code(secret, code):
            return True

    digest = recovery_digest_of(code.strip())
    result = await db.execute(
        select(TotpRecoveryCode).where(
            TotpRecoveryCode.user_id == user.id,
            TotpRecoveryCode.code_digest == digest,
            TotpRecoveryCode.used_at.is_(None),
        )
    )
    recovery_code = result.scalar_one_or_none()
    if recovery_code is None:
        return False
    recovery_code.used_at = datetime.now(UTC)
    return True


@router.post("/2fa/setup", response_model=TotpSetupResponse)
async def setup_totp(current_user: CurrentUser, db: DbSession) -> TotpSetupResponse:
    """Generate a new shared secret and return it for an authenticator app
    to scan — not yet active. `POST /2fa/enable` confirms it by proving the
    caller can produce a real code from it.

    Refuses (409) when 2FA is already enabled: overwriting the stored
    secret while it is still the one an authenticator app has would lock
    the account out of its own second factor between the two calls.
    Disable first to reconfigure.
    """
    settings = get_settings()
    key = _totp_key_or_503(settings)
    if current_user.totp_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Two-factor authentication is already enabled; disable it first to reconfigure",
        )

    secret = totp.generate_secret()
    current_user.totp_secret_encrypted = totp.encrypt_secret(secret, key=key)
    await db.commit()

    return TotpSetupResponse(
        secret=secret, provisioning_uri=totp.provisioning_uri(secret, email=current_user.email)
    )


@router.post("/2fa/enable", response_model=TotpEnableResponse)
async def enable_totp(
    payload: TotpEnableRequest, request: Request, current_user: CurrentUser, db: DbSession
) -> TotpEnableResponse:
    """Confirm a pending secret from `/2fa/setup` and turn 2FA on. Returns
    ten recovery codes, shown once — the same "shown once, digest kept" UX
    a password-reset link or an API key's plaintext token already uses."""
    key = _totp_key_or_503(get_settings())
    if current_user.totp_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Two-factor authentication is already enabled"
        )
    if current_user.totp_secret_encrypted is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Call /auth/2fa/setup first")

    secret = totp.decrypt_secret(current_user.totp_secret_encrypted, key=key)
    if not totp.verify_code(secret, payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    current_user.totp_enabled = True
    # A clean slate: any recovery codes from a previous enable/disable cycle
    # are gone, since they were minted for a secret this account no longer
    # necessarily has any relationship to.
    await db.execute(delete(TotpRecoveryCode).where(TotpRecoveryCode.user_id == current_user.id))
    codes = mint_recovery_codes()
    for _plaintext, digest in codes:
        db.add(TotpRecoveryCode(user_id=current_user.id, code_digest=digest))
    await record_event(
        db,
        action="auth.2fa_enabled",
        resource_type="user",
        resource_id=str(current_user.id),
        result="allow",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return TotpEnableResponse(recovery_codes=[plaintext for plaintext, _ in codes])


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_totp(
    payload: TotpDisableRequest, request: Request, current_user: CurrentUser, db: DbSession
) -> None:
    """Turn 2FA off. Requires proof of possession — a current TOTP code or
    an unused recovery code — so a hijacked session cannot silently strip
    the account's second factor; a bearer token alone is not enough."""
    if not current_user.totp_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Two-factor authentication is not enabled"
        )

    if not await _verify_totp_or_recovery_code(db, current_user, payload.code):
        await record_event(
            db,
            action="auth.2fa_disabled",
            resource_type="user",
            resource_id=str(current_user.id),
            result="deny",
            user_id=current_user.id,
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "invalid_code"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    current_user.totp_enabled = False
    current_user.totp_secret_encrypted = None
    await db.execute(delete(TotpRecoveryCode).where(TotpRecoveryCode.user_id == current_user.id))
    await record_event(
        db,
        action="auth.2fa_disabled",
        resource_type="user",
        resource_id=str(current_user.id),
        result="allow",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()


@router.post("/login/2fa", response_model=TokenResponse)
async def login_totp(
    payload: TotpLoginRequest, request: Request, response: Response, db: DbSession
) -> TokenResponse:
    """The second step of a two-factor login: redeem the challenge
    `POST /auth/login` issued, plus a current code or a recovery code, for
    a real session. The challenge itself is single-use, the same as every
    other short-lived security token in this platform (a password reset
    link, an OAuth state nonce) — `challenge_store` claims its `cid` before
    anything else runs, so a second redemption of the same challenge fails
    even with the correct code."""
    try:
        challenge = decode_totp_challenge_token(payload.challenge)
    except InvalidTotpChallengeError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired challenge"
        ) from None

    try:
        await challenge_store.consume_or_raise(challenge.challenge_id)
    except challenge_store.TotpChallengeAlreadyConsumed:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired challenge"
        ) from None
    except challenge_store.TotpChallengeConsumptionUnavailable as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, detail="Login is temporarily unavailable"
        ) from exc

    # Decoding is a local JWT verification, cheap and not itself something to
    # bound — the budget exists for guessing the six-digit code, so it is
    # keyed on the account the now-decoded challenge names, the same way
    # `login`'s own identity dimension is keyed on the email once the request
    # body is parsed.
    await ratelimit.enforce(request, "login_2fa", identity=str(challenge.user_id))

    user = await db.get(User, challenge.user_id)
    if user is None or not user.is_active or not user.totp_enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired challenge")

    if not await _verify_totp_or_recovery_code(db, user, payload.code):
        await record_event(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=str(user.id),
            result="deny",
            user_id=user.id,
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "invalid_totp_code"},
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid code")

    token = create_access_token(subject=user.id)
    await _record_session(db, user_id=user.id, token=token, request=request)
    await ratelimit.clear(request, "login_2fa", identity=str(user.id))
    await record_event(
        db,
        action="auth.login",
        resource_type="user",
        resource_id=str(user.id),
        result="allow",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        metadata={"totp_verified": True},
    )
    await db.commit()

    _set_session_cookie(response, token)
    return TokenResponse(access_token=token, user=UserRead.model_validate(user))
