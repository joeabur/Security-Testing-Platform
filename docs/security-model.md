# Security model

The guarantees this platform makes about itself, and the mechanism behind each
one. `docs/threat-model.md` says who might attack it; this page says what holds.
`docs/guardrails.md` is the shorter, consolidated map of the AI/LLM-specific
guardrails, human-in-the-loop checkpoints, and the controls below, each linked
back to the full mechanism.

Each row names how the guarantee is enforced. "By construction" means there is
no code path that could do otherwise; "by test" means a test fails if it stops
being true. Most are both.

## Guarantees

| # | Guarantee | Mechanism |
|---|---|---|
| 1 | Nothing reaches a target without a valid authorization grant | API refuses with `409`; the scope engine halts on an expired window |
| 2 | Every outbound HTTP request passes the scope engine | `GatedTransport` is the only place an HTTP client is constructed; a static test greps `app/` |
| 3 | No flag disables scope enforcement | No such key exists in `app/core/config.py`, and adding one is a declined change |
| 4 | Cloud metadata addresses are never reachable | Checked before the allowlist and never excused, including under `0.0.0.0/0` |
| 5 | Redirects cannot move a request out of scope | `follow_redirects=False`; the `Location` is re-checked as a fresh target |
| 6 | DNS rebinding cannot move a request out of scope | Resolution happens at send time; every resolved address is checked |
| 7 | Credentials are never stored in the database | Schemas hold variable *names*; a test reads every column of a stored row |
| 8 | No secret is persisted or logged unredacted | Redaction runs before the write; the store refuses a bundle containing one |
| 9 | Error strings cannot leak a credential | URLs are reduced to scheme + host + path shape, then the secret detector runs |
| 10 | Evidence cannot be altered undetected | Content-addressed, hash-chained; verification re-hashes the files |
| 11 | Audit records cannot be changed | No update or delete function exists in the audit service |
| 12 | A tenant cannot observe another tenant | Queries filter by `organization_id`; non-members get 404, and a pinned route→role matrix test guards it |
| 13 | A CI credential cannot authorize testing | API key scopes cap at security engineer, below the admin required to grant |
| 14 | No finding carries an invented identifier | Every CVE/GHSA/OSV/CWE is shape-verified; unverifiable ones are dropped, not repaired |
| 15 | No framework mapping is unversioned | Versions come only from the pinned table; a framework with no references is not claimed |
| 16 | A missing tool produces a visible gap | `KERVY-APPSEC-000 — not tested`, never an empty result set |
| 17 | The AI layer cannot execute | No code path from assistant to scan, authorization or non-draft field; import-linter confirms the dependency direction |
| 18 | The platform works with no AI provider | The full suite passes unchanged with none configured |
| 19 | A plugin cannot bypass the scope engine | Plugins receive a scope-bound transport; a test proves the bypass fails |
| 20 | The pull-request layer cannot write to a repository | No such method; a static check greps for the write verbs and endpoints; the egress context permits only `GET`/`POST` |
| 21 | The demo lab has no network egress | `internal: true` network, no gateway, no published ports, and it refuses to start with a provider credential present |
| 22 | Reports have no public URLs | Served through the authenticated API; evidence is a filesystem path, not a URL |
| 23 | Authentication endpoints cannot be brute-forced without cost | Login/register are rate limited on both per-identity and per-IP dimensions, and the 2FA challenge step (`login/2fa`) has its own tighter per-identity budget; throttled (429), never locked out — `docs/rate-limiting.md` |
| 24 | A cross-site page cannot forge a cookie-authenticated write | CSRF token is an HMAC over the session cookie's own value, enforced as middleware over every route — `docs/csrf.md` |
| 25 | A logged-out or suspected-leaked token stops working immediately | Per-token deny-list on `/auth/logout`; durable per-user cutoff on `/auth/logout-all`; this control fails *closed* — `docs/revocation.md` |
| 26 | A query that forgets its `organization_id` filter cannot return another tenant's rows | Postgres Row-Level Security on the 21 tenant-scoped tables (confirmed live against `pg_policies`, not hand-counted from migration files), independent of guarantee #12's application-level filtering — `app/db/tenant_context.py`; requires the operator setup in `docs/deployment.md`'s Database section |
| 27 | Cumulative AI provider spend cannot run away across many calls | A Redis-backed daily counter, checked before every call and charged with a real per-call estimate, on top of the $5.00 per-interaction budget — `app/core/assistant/spend_cap.py`, `app/core/assistant/pricing.py` |
| 28 | The AI layer retains nothing for later use | Every provider call is single-shot; only platform-owned, audited rows (`AiDraft`, evidence bundles) persist anything, for a human to review and accept — never a store the AI itself reads back on a later call, run, or organization — `docs/guardrails.md` §1.1 |
| 29 | The native agent cannot act beyond the caller's own role and tenant | Every tool call runs under an `AgentContext` built from the same role-ceiling logic `require_membership` enforces at the HTTP boundary; a `SENSITIVE` tool additionally requires an explicit, separately-authorized approval that no role or autonomy setting can substitute for — `app/core/agent/permissions.py`, `docs/agent.md` |
| 30 | The native agent persists no conversation, prompt, response, or tool output | Five closed tables (`Agent`, `AgentProvider`, `AgentTool`, `AgentConfiguration`, `AgentUsageMetadata`) hold configuration and non-content metrics only, pinned by a closed-table-set test and a column-allowlist test; the only content that ever reaches Redis is a paused investigation's plan and state, key-expired at 30 minutes and read fail-closed — `app/models/agent.py`, `app/core/agent/session_store.py`, `docs/agent.md` |
| 31 | A social login cannot silently take over an existing password account | Identity is matched only by `(provider, provider_user_id)`, never by email; a callback whose email matches an existing account refuses with `409`, the same non-enumerating-at-registration shape `POST /auth/register`'s duplicate-email case already uses — `app/models/oauth.py`, `app/api/v1/routers/auth.py::oauth_callback` |
| 32 | A password reset token is single-use, short-lived, and invalidates every existing session | Stored as a SHA-256 digest, never the plaintext; a successful reset sets `tokens_valid_after` and revokes every `UserSession` row, the same "log out everywhere" cutover `/auth/logout-all` uses — `app/models/password_reset.py` |
| 33 | Only an existing owner can grant, change, or remove another owner | `invite_member`, `update_member_role`, and `remove_member` all check `Role.at_least(Role.OWNER)` before any operation that touches `Role.OWNER`, so an Admin — despite having every other membership-management permission — cannot mint a co-owner or demote one; an organization's last remaining owner additionally cannot be demoted or removed at all, refused with `409`, so an organization can never end up with no one able to perform an owner-only action — `app/api/v1/routers/organizations.py` |
| 34 | A stolen password alone cannot sign in to a 2FA-enabled account | `login()` returns a short-lived, single-use `TotpChallenge` instead of a session when `User.totp_enabled` is true; the challenge token deliberately omits the `iat_us`/`jti` claims `decode_access_token` requires, so it can never be accepted as a Bearer token even if presented as one, and `POST /auth/login/2fa` redeems it exactly once through a fail-closed Redis store — a second redemption attempt, or one after Redis is unreachable, is refused, never silently accepted — `app/auth/security.py`, `app/core/twofactor/challenge_store.py` |
| 35 | An organization cannot widen what the native agent may do below its code-defined floor | `AgentTool.minimum_role_override` can only *raise* a tool's required role, never lower it — `validate_role_override` refuses a write that would drop it below the code default, and `effective_minimum_role` takes `max(code default, org override)` even if a stored row somehow bypassed that guard; `AgentTool.enabled` and the effective minimum are both re-checked by `run_plan` on every step, including one resumed after an approval pause, not only when the plan was first built — `app/core/agent/tool_config.py`, `app/core/agent/runtime.py` |
| 36 | Firing a real exploit requires two different people, not one role check twice | `ExploitationFire` starts `awaiting_approval` on `POST .../exploitation-fires`; `approve_fire` refuses with `409` if the approver is the same `user_id` as the requester, regardless of role — a lone Security Engineer (or Owner) cannot request and approve their own fire — `app/core/pentest/exploitation_service.py`, `app/models/exploitation.py` |
| 37 | Every route under `/api/v1`, not only login and registration, is bounded against a scripted loop | `app.main`'s `api_rate_limit_middleware` applies a coarse `api_default` ceiling (IP always, identity when a bearer JWT's subject decodes for free) ahead of every route's own dependencies, covering any route added later the same way the CSRF middleware beside it already covers every route's CSRF check — `docs/rate-limiting.md` |

## The habit behind the tests

Several controls here were verified by **deliberately breaking them** and
confirming the test caught it:

- A route downgraded from analyst to viewer — the suite stayed green until the
  pinned role table was added, then named the route.
- An AWS key planted in a tracked file — detect-secrets caught it.
- A second `import smtplib` added outside the sanctioned module — the static
  check failed.
- A `PATCH` verb and a `/merges` endpoint planted in `app/core/vcs` — the
  repository-write check failed.
- An adjacent-secret string that defeated the redactor's word boundaries — found
  by a property test, which is why the patterns no longer use `\b`.

A control whose test has never been seen to fail is a control nobody has
checked.

## Where the guarantees stop

- **Plugins are not sandboxed.** Stated in `docs/plugin-development.md`; the
  allowlist is the control.
- **SMTP is adjudicated, not carried.** The engine clears the relay host; it
  does not see the socket.
- **Append-only is by construction, not by grant.** Revoking `UPDATE`/`DELETE`
  on `audit_logs` at the database level is recommended and not enforced.
- **Evidence is unencrypted at rest.**
- **Rate limiting covers `login`/`register` and, since 2FA, social OAuth
  login and password reset shipped, `login/2fa`, `oauth_callback`, and
  `forgot_password` too.** Authenticated routes rely on RBAC instead — see
  `docs/rate-limiting.md` §"What is not limited". The native agent's own
  `agent_tool_call`/`agent_sensitive_tool_call` rules exist in the same
  policy table but are not yet wired to a route — don't read their presence
  there as enforcement.

`docs/security-review.md` carries the full self-review, including how each
control was verified and what is not covered.
