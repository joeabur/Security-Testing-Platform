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
| `EVIDENCE_ROOT` | `var/evidence` | A path, not a URL. Evidence never leaves the deployment by default |
| `KERVY_EVIDENCE_ENCRYPTION_KEY` | unset (plaintext) | Base64, 32 bytes (AES-256). One static key, no rotation — set before a deployment starts collecting evidence, not partway through |

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

## Password reset (optional)

Leave `KERVY_PLATFORM_SMTP_HOST` unset and `POST /auth/forgot-password`
still answers 202 (never disclosing whether an address is registered — see
`docs/security-model.md`), but issues no token and sends no mail.

| Variable | Notes |
|---|---|
| `KERVY_PLATFORM_SMTP_HOST` | The platform's own outbound relay — distinct from any per-organization notification channel |
| `KERVY_PLATFORM_SMTP_PORT` | Default `587` |
| `KERVY_PLATFORM_SMTP_FROM_ADDRESS` | Required alongside the host |
| `KERVY_PLATFORM_SMTP_USERNAME` | Optional |
| `KERVY_PLATFORM_SMTP_PASSWORD_ENV_VAR` | Name of the variable holding the password, not the value itself |
| `KERVY_PASSWORD_RESET_TOKEN_TTL_MINUTES` | Default `30` |

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
- Separate database credentials for the app role; consider revoking `UPDATE` and
  `DELETE` on `audit_logs` at the database level. The application never issues
  them, but defence in depth here is cheap (tracked in `docs/roadmap.md`).
- Every credential variable present in the **worker's** environment.
- Allowlists (`KERVY_NOTIFY_*`, `KERVY_VCS_ALLOWED_HOSTS`) set to the minimum.
