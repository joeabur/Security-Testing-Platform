# Authentication

Three ways to authenticate, with different lifetimes and different ceilings —
plus social login and password reset as alternate ways into the same session.

## Passwords

**Argon2id**, via `argon2-cffi`. Not bcrypt: Argon2id is memory-hard, which is
what raises the cost of an offline attack against a stolen hash.

Registration returns an access token immediately, so the quickstart is one call
rather than two. Passwords are never logged, never returned, and never
recoverable — there is no "show password" path because there is nothing to show.

`User.password_hash` is nullable: an account created through social login (below)
has none, and `login()` treats a null hash the same generic way it treats a wrong
password — a null-hash account cannot be signed into with a password at all, but
the 401 it gets looks identical to any other failed login.

## Session tokens

A signed JWT (`HS256`) carrying the user id and expiry, default 12 hours. The
frontend keeps it in an httpOnly, SameSite=Lax cookie; `SESSION_COOKIE_SECURE`
adds the Secure attribute and should be on behind TLS.

`JWT_SECRET` has an insecure development default, and the application **refuses
to start** with it when `ENVIRONMENT=production`. A loud failure beats a quiet
insecure default.

## Two-factor authentication

Optional, per-user TOTP (`pyotp`, RFC 6238) — off by default, enabled from
`/account/security` in the frontend or `POST /auth/2fa/setup` + `.../enable`
directly. Requires `KERVY_TOTP_ENCRYPTION_KEY` (AES-256, base64) to be
configured on the deployment; without it, setup refuses with `503` rather
than storing a secret insecurely or pretending the feature works.

When enabled, `POST /auth/login` no longer returns a session for that
account — it returns a `TotpChallenge` (a `challenge` string, five-minute
lifetime) that carries no `iat_us`/`jti` claim, so `get_current_user` can
never mistake it for a Bearer token even if one were presented. `POST
/auth/login/2fa` redeems the challenge exactly once, through a Redis-backed
store that fails **closed**: an already-redeemed challenge, or a
`login/2fa` call made while Redis is unreachable, is refused rather than
waved through. A correct code or one of ten single-use recovery codes
(minted at enable time, shown once, stored as SHA-256 digests like an API
key's own secret) both complete the second step.

Disabling requires a current code or recovery code too — an attacker who
merely hijacks an already-open session cannot turn 2FA off to make a
password alone sufficient again.

`POST /auth/login/2fa` has its own rate-limit budget (`login_2fa`, per
identity — `docs/rate-limiting.md`), separate from `login`'s own: a correct
password does not entitle an attacker to unlimited guesses at a six-digit
code.

## Social login (Google, GitHub)

`GET /auth/oauth/{provider}/authorize` redirects to the provider;
`GET /auth/oauth/{provider}/callback` completes it. Both are 404 — not merely
disabled — when the provider has no client id/secret configured
(`GOOGLE_OAUTH_CLIENT_ID`/`GOOGLE_OAUTH_CLIENT_SECRET_ENV_VAR`,
`GITHUB_OAUTH_CLIENT_ID`/`GITHUB_OAUTH_CLIENT_SECRET_ENV_VAR`, plus
`KERVY_OAUTH_CALLBACK_BASE_URL`) or the deployment has no `public_base_url` —
the same "not configured and half-configured both mean unavailable" shape
`/2fa/setup` uses for a missing encryption key. `GET /auth/oauth/providers`
tells the frontend which buttons to render.

An `OAuthIdentity` row is keyed on `(provider, provider_user_id)` — the
provider's own stable subject id, **never** email. A callback whose reported
email matches an existing password account refuses with `409`
(`app/models/oauth.py`) rather than linking silently: a provider that does not
itself verify email ownership would otherwise let anyone claiming that address
attach themselves to someone else's account. A first-time login for a new
address creates the `User` (with `password_hash=None`) and the identity row
together, and redirects to `/organizations/new`; a returning identity redirects
to `/dashboard`. Either way the browser gets the same session and CSRF cookies
`_set_session_cookie` sets after a password login — social login is a second
front door onto the identical session, not a separate credential type.

The callback is rate limited per IP (`oauth_callback`, `docs/rate-limiting.md`)
because every attempt — even a doomed one with a bad `code` — costs this
server a real outbound token-exchange call to the provider.

## Forgot / reset password

`POST /auth/forgot-password` always returns `202`, whether or not the address
is registered, has a password at all, or `KERVY_PLATFORM_SMTP_HOST`/
`KERVY_PLATFORM_SMTP_FROM_ADDRESS` are even configured — the same
non-enumerating shape `/auth/login` uses, extended to a route that by design
tells an anonymous caller nothing. Rate limited per IP only
(`forgot_password`, `docs/rate-limiting.md`): the budget is consumed before
any lookup, so there is no identity to key a second dimension on without
itself leaking whether the address exists.

A reset link carries a 256-bit token (`KERVY_PASSWORD_RESET_TOKEN_TTL_MINUTES`,
default 30); only its SHA-256 digest is stored (`app/models/password_reset.py`),
the same "shown once, digest kept" shape an API key's secret or a TOTP
recovery code already uses. At most one live link per user — requesting a new
one invalidates any unused older one. `POST /auth/reset-password` consumes the
token, sets the new password, and — deliberately — does **not** start a
session: the caller has proven control of an inbox, not a browser worth
trusting with a cookie yet, so they are sent back to `/login`. It also sets
`tokens_valid_after` and revokes every row in `user_sessions`, the identical
"log out everywhere" cutover `/auth/logout-all` uses — a password reset is
exactly the "I think this account was compromised" case that mechanism exists
for (`docs/revocation.md`).

## API keys

For CI, where a standing credential lives in a runner and is the most exposed
thing the platform issues. Three properties matter:

**Hashed with SHA-256, not Argon2.** That is deliberate and not a weakening: the
token is 256 bits of CSPRNG output, so there is no low-entropy guess to slow
down. Password hashing exists to buy time against guessable inputs; a random
256-bit token has none.

**Shown once.** `POST …/api-keys` returns the secret; no endpoint returns it
again, and none exists to. Rotation is create-then-revoke, so a pipeline can
move to the new key before the old one stops working.

**Capped below the creator's role.** Keys carry scopes — `read`, `scan`,
`triage` — and the highest role any scope maps to is *security engineer*. A key
therefore cannot create a target, grant authorization, add a member, or mint
another key, no matter who created it. A credential in a CI runner must not be
able to authorize a new target: that grant is the human act this platform is
built around.

Comparison is constant-time (`hmac.compare_digest`). Keys may carry an expiry,
and one already in the past is rejected at creation — a key that cannot be used
is a confusing way to say "revoked".

## Where this is enforced

`app/auth/dependencies.py`. `get_current_user` accepts either a session token or
an API key; `require_membership(role)` then resolves the caller's membership in
the organization named in the path and applies the role floor, capping at the
key's ceiling where one applies.

Non-members get **404, not 403**, so the existence of another organization's
resources is not observable. `backend/tests/security/test_authorization_matrix.py`
walks every route and asserts exactly that, then pins the required role for each
one so a downgrade fails by name.
