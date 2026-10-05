# Configuration

Every setting is an environment variable, loaded by `app/core/config.py` and
documented with an example in `.env.example`. There is **no configuration key
that disables scope enforcement** — that is deliberate and permanent.

## Core

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `local` | `local`, `ci`, `staging`, `production` |
| `DATABASE_URL` | local Postgres | `postgresql+asyncpg://…` |
| `REDIS_URL` | `redis://localhost:6379/0` | Celery broker and kill switch |
| `JWT_SECRET` | insecure local default | **Startup fails** if `ENVIRONMENT=production` and this is still the default |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 720 | |
| `CORS_ALLOWED_ORIGINS` | local frontend | |
| `SESSION_COOKIE_SECURE` | `false` | Opt-in so local HTTP development works; set it in production |
| `KERVY_RATE_LIMIT_ENABLED` | `true` | See `docs/rate-limiting.md` |
| `KERVY_TRUSTED_PROXY_COUNT` | `0` | How many reverse proxies sit in front of this deployment. `0` means `X-Forwarded-For` is ignored entirely and the socket address is used — load-bearing: trusting the header with no proxy in front lets a client mint a fresh rate-limit bucket per forged value |
| `KERVY_RATE_LIMIT_PEPPER` | falls back to `JWT_SECRET` | HMAC pepper for identity-based rate-limit bucket keys, so the counter store never holds a plaintext email |
| `KERVY_CSRF_ENABLED` | `true` | See `docs/csrf.md` |
| `KERVY_CSRF_SECRET` | falls back to `JWT_SECRET` | Signs the session-bound CSRF token |
| `EVIDENCE_ROOT` | `var/evidence` | A path, not a URL. Evidence never leaves the deployment by default |
| `KERVY_EVIDENCE_ENCRYPTION_KEY` | unset (plaintext) | Base64, 32 bytes (AES-256). One static key, no rotation — set before a deployment starts collecting evidence, not partway through |
| `KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY` | unset (workflow webhook automation disabled) | Base64, 32 bytes (AES-256). Not optional-encryption like the evidence key above — a webhook secret must never sit in Postgres in cleartext, so absent means a workflow's inbound webhook cannot be enabled at all, rather than being stored unencrypted |
| `KERVY_TOTP_ENCRYPTION_KEY` | unset (2FA disabled platform-wide) | Base64, 32 bytes (AES-256). A TOTP shared secret is exactly as sensitive as a webhook secret — absent, `POST /auth/2fa/setup` refuses outright rather than storing one unencrypted; there is no per-organization opt-out once set |
| `KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL` | unset (no platform owner) | Read exactly once, by `python -m scripts.bootstrap_platform_owner`, and never by the running application — see `docs/rbac.md`'s "Above the ladder" section. Names an *already-registered* account to grant the deployment's first platform owner; every owner after that is granted by an existing one through `POST /platform/owners`, not this variable |

## Credentials are held by reference

This is the rule that shapes most of the rest of this page. Anywhere the
platform needs a secret — a target's test account, a Slack webhook URL, an SMTP
password, a GitHub token, an AI provider key — the database stores the **name of
an environment variable**, never the value.

The consequence worth internalising: **the process that makes the request is the
one that must have the variable.** For a scan, that is the Celery worker, not
the API. Exporting a target credential only in the API shell produces a run that
completes but reports nothing from the probes that needed it.

A Slack incoming webhook URL is a credential, because the token is its path —
so the whole URL is held by reference, and only a redacted form
(`https://hooks.slack.com/…/…/…`) is stored for display.

## AI provider (optional)

Leave unset and the platform behaves identically — scanning, scoring, reporting
and the CI gate all work with no provider.

| Variable | Notes |
|---|---|
| `AI_PROVIDER` | e.g. `openai_compatible` |
| `AI_ENDPOINT` | Any OpenAI-compatible endpoint, including a local one |
| `AI_MODEL` | |
| `AI_API_KEY_ENV_VAR` | The *name* of the variable holding the key |
| `AI_AUTONOMY_MODE` | `OFF`, `ASSIST`, `RECOMMEND`, `APPROVAL_REQUIRED`, `EXECUTE` |
| `AI_DAILY_SPEND_CAP_USD` | Default `20.0`. A platform-wide ceiling on cumulative provider spend, on top of the $5.00 per-interaction budget — see `docs/security-model.md` guarantee #27 |

`EXECUTE` does not grant execution of scans, authorization or finding changes.
No mode does; see `docs/ai-security-testing.md`.

## Plugins

| Variable | Notes |
|---|---|
| `PLUGINS_CONFIG` | Path to the allowlist file. Absent → no plugins load |
| `KERVY_NO_PLUGINS` | `1` wins over any configuration — the one thing to set when something has gone wrong |

## Outbound notifications

| Variable | Notes |
|---|---|
| `KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS` | JSON list. Required for a generic webhook; vendor kinds are pinned in code |
| `KERVY_NOTIFY_ALLOWED_SMTP_HOSTS` | JSON list. No vendor defaults exist for SMTP |
| `KERVY_PUBLIC_BASE_URL` | Used to build links in notifications. Absent → no link rendered, rather than a guessed one |

These live in the environment, not the database, on purpose: an organization
admin may choose *which* sanctioned destination to notify; adding a brand-new
outbound destination is an operator decision.

## Code hosts

| Variable | Notes |
|---|---|
| `KERVY_VCS_ALLOWED_HOSTS` | JSON list, for GitHub Enterprise only. `api.github.com` is pinned in code |

## Exploitation tier (pentest module Phase 12)

| Variable | Notes |
|---|---|
| `KERVY_EXPLOITATION_ALLOWED_NSE_SCRIPTS` | JSON list. Empty by default — nothing is fireable on a fresh deployment until an operator explicitly names scripts here. Never a category (`exploit`/`brute`/`dos`/`intrusive` stay excluded in code regardless) |

This is one of three independent allowlists a fire request must clear —
the target's own `asset_scope.approved_modules` and a live
`ExploitationAuthorization.approved_script_names` are the other two, and
all three must agree. Like the webhook/VCS host allowlists above, this is
the operator's own reviewed list, not a database row an organization admin
can add — deciding which NSE `exploit`-category scripts are safe enough to
fire against a given deployment's targets is explicitly the operator's
call, not this platform's.

## Social OAuth login (optional)

Leave a provider's client id/secret unset and its button never appears —
`GET /api/v1/auth/oauth/providers` reports it as unavailable, and its
`/authorize`/`/callback` routes 404 rather than half-working. The client
*secret* is never a setting: only the name of the environment variable
holding it is, read fresh at call time the same way `AI_API_KEY_ENV_VAR` is.

| Variable | Notes |
|---|---|
| `GOOGLE_OAUTH_CLIENT_ID` | From the Google Cloud Console OAuth client |
| `GOOGLE_OAUTH_CLIENT_SECRET_ENV_VAR` | Name of the variable holding the secret |
| `GITHUB_OAUTH_CLIENT_ID` | From a GitHub OAuth App |
| `GITHUB_OAUTH_CLIENT_SECRET_ENV_VAR` | Name of the variable holding the secret |
| `KERVY_OAUTH_CALLBACK_BASE_URL` | This backend's own externally-reachable origin — where a provider redirects back to. Required for either provider to work; distinct from `KERVY_PUBLIC_BASE_URL` below, which is the frontend's |

Register `{KERVY_OAUTH_CALLBACK_BASE_URL}/api/v1/auth/oauth/google/callback`
(and the `github` equivalent) as the provider's own allowed redirect URI —
it refuses any other.

## Outbound mail: password reset + organization invitations (optional)

One platform SMTP relay, two features built on it — there is no per-feature
configuration, only `password_reset_enabled`/`invitation_email_enabled`,
which are both just "is `KERVY_PLATFORM_SMTP_HOST` set" read under two
different names (`app/core/config.py`).

Leave `KERVY_PLATFORM_SMTP_HOST` unset and both features degrade the same
way: no error, just no mail. `POST /auth/forgot-password` still answers its
usual 202 (never disclosing whether an address is registered — see
`docs/security-model.md`), but issues no token. Inviting a not-yet-
registered address from the dashboard's Members tab (`docs/dashboard.md`)
still creates the pending invitation row — so an admin can revoke it and
re-invite later once mail is configured — but the row's own `email_sent`
field comes back `false`, and the dashboard shows that plainly (a warning,
not the "email was sent" success message) rather than claiming delivery
that didn't happen.

| Variable | Notes |
|---|---|
| `KERVY_PLATFORM_SMTP_HOST` | The platform's own outbound relay — distinct from any per-organization notification channel |
| `KERVY_PLATFORM_SMTP_PORT` | Default `587` |
| `KERVY_PLATFORM_SMTP_FROM_ADDRESS` | Required alongside the host |
| `KERVY_PLATFORM_SMTP_USERNAME` | Optional |
| `KERVY_PLATFORM_SMTP_PASSWORD_ENV_VAR` | Name of the variable holding the password, not the value itself |
| `KERVY_PASSWORD_RESET_TOKEN_TTL_MINUTES` | Default `30` |
| `KERVY_INVITATION_TOKEN_TTL_MINUTES` | Default `10080` (a week) — longer than a password reset's, since an invitation goes to someone who may not check their inbox right away |

### Local development: catching mail without a real provider

No real SMTP account is needed to see these emails locally. `docker-
compose.yml` bundles [Mailpit](https://github.com/axllent/mailpit), a
throwaway SMTP server with a web UI, behind `--profile mail` — the same
opt-in shape as the demo target lab, so it never starts as part of an
ordinary `docker compose up` or in a real deployment:

```bash
docker compose --profile mail up -d mailpit
```

Then point `.env` at it instead of a real relay:

```bash
KERVY_PLATFORM_SMTP_HOST=mailpit
KERVY_PLATFORM_SMTP_PORT=1025
KERVY_PLATFORM_SMTP_FROM_ADDRESS=dev@localhost
```

Restart the backend so it picks up the new values, then read whatever this
platform sent at **http://localhost:8025** — invitation emails and password
resets both land there, with working accept/reset links pointed at
whatever `KERVY_PUBLIC_BASE_URL` is set to.

## Frontend

| Variable | Notes |
|---|---|
| `BACKEND_INTERNAL_URL` | Reached from inside the Docker network |
| `NEXT_PUBLIC_API_URL` | Reached from the browser |

## Production checklist

- `ENVIRONMENT=production` and a real `JWT_SECRET` (startup refuses otherwise).
- `SESSION_COOKIE_SECURE=true` behind TLS.
- `EVIDENCE_ROOT` on storage you have a retention and deletion policy for.
- `KERVY_EVIDENCE_ENCRYPTION_KEY` set before the first run, if evidence
  encryption at rest is required — there is no tool to encrypt bundles
  already written without it.
- `KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY` set before any workflow's inbound
  webhook is enabled — required, not optional, since the secret is refused
  outright without it.
- `KERVY_TOTP_ENCRYPTION_KEY` set before any organization enrolls in 2FA, if
  it is to be offered at all — there is no way to turn it on retroactively
  for accounts that enrolled before the key existed.
- `KERVY_EXPLOITATION_ALLOWED_NSE_SCRIPTS` reviewed and set explicitly if
  the exploitation tier's fire step is to be used at all; left empty, it is
  simulate-only forever, which is the correct default for most deployments.
- `python -m scripts.bootstrap_platform_owner` run once, after the intended
  owner's account has registered, with `KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL`
  set — a deployment with zero platform owners has no way to grant one
  through the API itself (`POST /platform/owners` is platform-owner-only).
- Separate database credentials for the app role; consider revoking `UPDATE` and
  `DELETE` on `audit_logs` at the database level. The application never issues
  them, but defence in depth here is cheap (tracked in `docs/roadmap.md`).
- Every credential variable present in the **worker's** environment.
- Allowlists (`KERVY_NOTIFY_*`, `KERVY_VCS_ALLOWED_HOSTS`) set to the minimum.
