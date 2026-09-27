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
| 16 | A missing tool produces a visible gap | `AEGIS-APPSEC-000 — not tested`, never an empty result set |
| 17 | The AI layer cannot execute | No code path from assistant to scan, authorization or non-draft field; import-linter confirms the dependency direction |
| 18 | The platform works with no AI provider | The full suite passes unchanged with none configured |
| 19 | A plugin cannot bypass the scope engine | Plugins receive a scope-bound transport; a test proves the bypass fails |
| 20 | The pull-request layer cannot write to a repository | No such method; a static check greps for the write verbs and endpoints; the egress context permits only `GET`/`POST` |
| 21 | The demo lab has no network egress | `internal: true` network, no gateway, no published ports, and it refuses to start with a provider credential present |
| 22 | Reports have no public URLs | Served through the authenticated API; evidence is a filesystem path, not a URL |
| 23 | Authentication endpoints cannot be brute-forced without cost | Login/register are rate limited on both per-identity and per-IP dimensions; throttled (429), never locked out — `docs/rate-limiting.md` |
| 24 | A cross-site page cannot forge a cookie-authenticated write | CSRF token is an HMAC over the session cookie's own value, enforced as middleware over every route — `docs/csrf.md` |
| 25 | A logged-out or suspected-leaked token stops working immediately | Per-token deny-list on `/auth/logout`; durable per-user cutoff on `/auth/logout-all`; this control fails *closed* — `docs/revocation.md` |
| 26 | A query that forgets its `organization_id` filter cannot return another tenant's rows | Postgres Row-Level Security on the 14 tenant-scoped tables, independent of guarantee #12's application-level filtering — `app/db/tenant_context.py`; requires the operator setup in `docs/deployment.md`'s Database section |
| 27 | Cumulative AI provider spend cannot run away across many calls | A Redis-backed daily counter, checked before every call and charged with a real per-call estimate, on top of the $5.00 per-interaction budget — `app/core/assistant/spend_cap.py`, `app/core/assistant/pricing.py` |

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
- **Rate limiting covers only `login`/`register`.** Authenticated routes rely
  on RBAC instead — see `docs/rate-limiting.md` §"What is not limited".

`docs/security-review.md` carries the full self-review, including how each
control was verified and what is not covered.
