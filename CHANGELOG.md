# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Findings listing had no deterministic tiebreaker, so a page could silently disagree
  with the unbounded list it was paging through.** `GET /organizations/{id}/findings` and
  the dashboard's `top_findings`/`has_more_findings` queries all ordered by
  `risk_score.desc(), last_seen.desc()` alone; two findings from the same scan commonly tie
  on both, and Postgres gives no guarantee about a tied row's relative order between two
  differently-shaped queries over the same data (e.g. an unbounded `SELECT` vs. one with
  `LIMIT`/`OFFSET`). Added `Finding.id` as a final, unique `order_by` term in all three
  query sites (`app/api/v1/routers/findings.py`, `app/core/dashboard/queries.py`) so paging
  and the dashboard's "has more" check always agree with the full list's own order.
- **`owasp_asvs` was pinned to a superseded edition, and the weekly
  framework-drift check couldn't tell.** OWASP ASVS 5.0.0 has been out since
  well before this deployment's last manual read, but the pin in
  `app/core/findings/frameworks.py` still named 4.0.3. Per OWASP's own
  published v4.0.3→v5.0.0 crosswalk, `V2.10.4` ("secrets, API keys, and
  passwords not included in source code") was deleted and merged into
  `V13.3.1` ("secrets must not be included in application source code or
  build artifacts") — updated the secrets-detection engine's two finding
  sites (`app/core/appsec/secrets/engine.py`,
  `.../secrets/gitleaks_engine.py`) accordingly, bumped the pinned edition,
  and updated `docs/frameworks.md`'s table to match. Also fixed the
  `framework-drift.yml` workflow itself: `gh api`'s HTTP error body can
  reach stdout even with `--jq` and a non-2xx exit, and the old
  `$(cmd || true)` capture trusted that output unconditionally — a 404 for
  a framework with no GitHub releases (`owasp_llm_2026`) was landing in the
  weekly drift issue as spurious "drift" (`{"message":"Not Found",...}`
  read as the upstream version) instead of "could not be read." The fetch
  now only trusts a capture when the command itself exited zero. See
  GitHub issue #10.
- **Frontend CI was broken on `main` for every PR**: the zod 3.23.8→4.5.0
  security bump left `lib/validation.ts`'s three `z.literal(true, {
  errorMap: ... })` calls using a v3-only option zod v4 no longer accepts
  (`tsc` failure). Migrated them to v4's own syntax, `z.literal(true,
  "message")`. Fixing only that surfaced a second, deeper break invisible
  until typecheck passed: `@hookform/resolvers@3.9.0`'s zod adapter detects
  a `ZodError` via `Array.isArray(r?.errors)`, but zod v4 only exposes
  `.issues`, not a `.errors` alias — so on any validation failure the
  adapter re-threw instead of converting it, leaving forms stuck mid-submit
  with an unhandled rejection instead of a validation message. Bumped
  `@hookform/resolvers` to `5.9.1` (the first release whose compiled zod
  resolver checks `.issues` via the schema's `_zod` trait marker) and its
  required peer `react-hook-form` to `7.89.0`; verified two intermediate
  versions (`4.1.3`, `5.0.1`) still shipped the old `.errors`-checking
  resolver despite their package metadata suggesting otherwise. The newer
  `@hookform/resolvers` also tightened its `Resolver` type to distinguish a
  schema's pre-coerce input shape from its post-coerce output shape, which
  `components/runs/exploitation-fires.tsx`'s `z.coerce.number()` port field
  needs — added `ExploitationFireCreateFormInput` (`z.input<...>`) in
  `lib/validation.ts` alongside the existing output-typed
  `ExploitationFireCreateInput`, and split `useForm`'s generics accordingly.

### Security

- **Fixed a critical transitive vulnerability: `asteval` 1.0.6, pulled in
  exactly-pinned by `checkov` (the IaC scanner), was subject to
  GHSA-9w56-46f6-3qhx — with its default configuration (numpy enabled,
  `import` disabled), an attacker-controlled expression gets an arbitrary
  process-memory read/write primitive, a complete sandbox escape, with no
  `import`/`eval`/`getattr` needed. checkov never evaluates
  attacker-controlled expressions in this platform's own usage, but the
  fix (`asteval>=1.0.9`, a same-1.0.x patch release) is pinned directly in
  `backend/pyproject.toml`'s `appsec` extra to override checkov's own
  unpatched exact pin, since no checkov release through 3.3.20 has bumped
  it. Because every checkov release through 3.3.20 pins `asteval==1.0.6`
  exactly, satisfying the override resolves to `checkov==3.2.414` instead
  of the newest `3.3.x` — verified against this project's own AppSec/IaC
  test suite before and after, with identical results either way.
- **Bumped `pyjwt` to `>=2.14`**, fixing GHSA-w6j9-cwv2-h6wq (a malformed
  RSA JWK inside a JWK Set could abort parsing of an entire JWK Set via an
  uncaught `ValueError`). This platform doesn't call `PyJWKClient`/
  `PyJWKSet` today, but the fix is a clean version bump with no other
  behavior change.
- **Deferred, and why**: `pip-audit` also flags `click` (PYSEC-2026-2132,
  a command-injection in `click.edit()`) and `mcp` (three advisories,
  PYSEC-2026-3481/3482/3483, all requiring an opt-in server feature —
  `enable_tasks()`, an HTTP transport with bearer auth, or the deprecated
  WebSocket transport). A fix does exist — `semgrep>=1.173` pulls in
  `click>=8.4.2`/`mcp==1.29.0` — but every `semgrep` release from `1.173`
  onward hard-pins `pyjwt[crypto]~=2.13.0`, which directly conflicts with
  this file's own `pyjwt>=2.14` fix above (verified: `pip install
  "semgrep>=1.173" "pyjwt>=2.14"` in a clean venv is `ResolutionImpossible`,
  not just a warning). Neither side of that trade is reachable in this
  codebase either way: `semgrep` is invoked only as a CLI subprocess
  against a local `--config` path, never as a library and never via its
  `mcp` subcommand; `backend/mcp_server/` is a hand-rolled implementation
  that never imports the `mcp` package; and nothing here calls
  `PyJWKClient`/`PyJWKSet`. Swapping one unreachable-path CVE for three
  equally-unreachable ones is a lateral move, not a fix, so the existing
  `pyjwt>=2.14` pin stays and `click`/`mcp` stay deferred.
- **No longer applicable**: `.github/workflows/deps.yml` used to carry
  `--ignore-vuln` entries for `ecdsa` (PYSEC-2026-1325, the Minerva timing
  attack, transitively pulled in by an older `checkov` resolution) and for
  the pre-override `asteval==1.0.6` pin. Neither applies any more —
  `ecdsa` is absent from the resolved dependency tree entirely (confirmed
  across two independent installs resolving to different `checkov` patch
  versions, `3.2.10` and `3.2.414`), and `asteval` resolves to `1.0.10` in
  both, satisfying the `asteval>=1.0.9` override above. Removed both
  `--ignore-vuln` flags rather than carry a stale exemption that no
  longer matches reality — tracked rather than blindly forced, the same
  reasoning `.github/dependabot.yml`'s own comment gives for not
  auto-bumping the lab fixtures' pins.
- **Fixed: the `deps.yml` `pip-audit` job was failing on every run**,
  including immediately after the ignore-flag cleanup above merged. That
  commit removed the `asteval`/`ecdsa` ignores (correctly — neither
  applies) but never added the ones the `click`/`mcp` deferral above has
  needed all along; `pip-audit --skip-editable` with zero `--ignore-vuln`
  flags fails whenever any advisory is present, and this deployment has
  always resolved `click`/`mcp` versions carrying the four advisories
  named in that same deferral note. Added
  `--ignore-vuln PYSEC-2026-2132/3481/3482/3483` to the job, citing the
  identical reachability analysis already on record rather than a new
  one — verified locally (`pip-audit --skip-editable --progress-spinner
  off` with those four flags exits `0`, "4 ignored").

### Changed

- **The backend's dependencies are now locked, not just range-pinned.**
  `backend/pyproject.toml`'s `>=` ranges let every fresh install — a CI
  run, a Docker build, a contributor's own machine — resolve to a
  different concrete version depending on what PyPI happened to have
  published that day; this repo has hit that exact drift more than once
  (several historical commits exist solely to re-pin something after an
  upstream release moved). `backend/uv.lock` now resolves the whole tree
  once; `backend/constraints.lock.txt` is a flat, plain-`pip`-readable
  projection of the same lock (`python -m scripts.relock` regenerates
  both together), and every `pip install` in `.github/workflows/`
  (except `deps.yml`'s Python job, whose entire purpose is a weekly
  *fresh* resolution to catch a new CVE the lock hasn't caught up to
  yet) and both Dockerfiles now installs through it via `-c
  constraints.lock.txt`. `detect-secrets` stays outside the lock,
  pinned on its own in `security.yml` exactly as before — the hook
  treats any version drift against `.secrets.baseline` as "needs
  updating," so bumping it is its own deliberate step. See
  `docs/cicd.md`'s "The backend's dependency lock" section.
- **Renamed the platform from Aegis AI Security to Kervy Security**,
  end to end rather than at the branding layer alone: every `AEGIS_*`
  environment variable (`AEGIS_EVIDENCE_ENCRYPTION_KEY`,
  `AEGIS_WEBHOOK_SECRET_ENCRYPTION_KEY`, `AEGIS_RATE_LIMIT_ENABLED`,
  and the rest) is now `KERVY_*`; the `X-Aegis-Signature`/
  `X-Aegis-Timestamp`/`X-Aegis-Event` webhook-signing headers are now
  `X-Kervy-*`; the `aegis_session`/`aegis_csrf` cookies are now
  `kervy_session`/`kervy_csrf`; every `AEGIS-<engine>-<rule>` finding/
  probe-ID prefix (`AEGIS-SAST-...`, `AEGIS-API-...`, `AEGIS-IAC-...`,
  and the rest) is now `KERVY-<engine>-<rule>`; every Redis key prefix,
  the Celery app/task names, the `aegis-ai`/`aegis-mcp` CLI commands
  (now `kervy-ai`/`kervy-mcp`, `backend/aegis_cli` now
  `backend/kervy_cli`), and the package names in both
  `backend/pyproject.toml` and `frontend/package.json` all follow. The
  Postgres Row-Level Security session variable
  (`app/db/tenant_context.py`) moved from `aegis.org_id` to
  `kervy.org_id` via a dedicated `ALTER POLICY` migration
  (`e1d16423a6b1`) rather than an edit to any of the five historical
  migrations that created those policies, which are left exactly as
  they were run. Every historical Alembic migration file is
  deliberately untouched for the same reason — a migration is a record
  of what actually ran, not a place to retell it under a new name.
  **This is a breaking change** for any existing deployment or
  integration still using the old env var names, header names, cookie
  names, or database name.

### Added

- **SIEM integration: Splunk HEC, Microsoft Sentinel, and generic CEF
  notification channels.** `ChannelKind.GENERIC_WEBHOOK` was always the
  extension point for "feed a SIEM," but a generic signed JSON POST isn't
  what Splunk's HTTP Event Collector or Sentinel's Logs Ingestion API
  actually expect on the wire. Three new channel kinds
  (`app/core/integrations/`): `siem_splunk_hec` (HEC-token auth), `siem_sentinel`
  (Entra ID client-credentials exchange, then a POST to the Data Collection
  Endpoint — `*.ingest.monitor.azure.com` is the only pinned vendor host),
  and `siem_generic_cef` (Common Event Format over the existing signed
  generic-webhook path, for any SIEM with no dedicated adapter). New
  `NotificationChannel` columns via migration `d4f8e2a91c73`. See
  `docs/integrations.md`'s "SIEM channels" section and
  `docs/roadmap.md`'s write-up for the full design and what remains
  unverified against a real vendor account.
- **External ticketing: production Jira Cloud and ServiceNow adapters for
  notification channels.** Two new `ChannelKind` values, `ticket_jira` and
  `ticket_servicenow`, alongside the existing Slack/Teams/webhook/email
  kinds — a delivery to one of these *creates a record* rather than
  notifying about one. Jira: `POST /rest/api/3/issue` with Basic auth
  (account email + API token) and an Atlassian Document Format description;
  ServiceNow: `POST /api/now/table/<table>` with Basic auth (username +
  password), severity mapped to `urgency`/`impact`. Both vendor-host-pinned
  (`*.atlassian.net`, `*.service-now.com`) from an admin-chosen site/instance
  *label*, never a URL, so there is no field through which a channel could
  be repointed at an arbitrary host. The created ticket's key/number comes
  back as `NotificationDelivery.external_reference`. See
  `docs/integrations.md`'s "Ticketing channels" section and
  `docs/roadmap.md`'s external-ticketing write-up.
- **MITRE ATT&CK (Enterprise) mapping for the pentest module's own findings.**
  `docs/frameworks.md` already pinned `mitre_atlas` (AI-specific), but the
  pentest module's engines test conventional infrastructure — exactly
  ATT&CK's domain — and carried no mapping at all. New `mitre_attack` entry
  in `app/core/findings/frameworks.py` (Enterprise v19.2) and a
  `"MITRE-ATTACK:"` prefix in `group_mappings`; `app/core/pentest/engine.py`'s
  discovery, vulnerability-scan, validation and exploitation-fire findings
  now each cite the one technique they actually observed (`T1046`,
  `T1595.002`, `T1078.001`, `T1210`). See `docs/roadmap.md`'s "MITRE ATT&CK
  (Enterprise) mapping for the pentest module" write-up.
- **A platform-owner authority model, above every organization's own
  `Role.OWNER`.** Every authorization check this platform has ever had was
  organization-scoped; nothing governed the deployment itself, or who may
  grant and revoke that governance. New nullable `User.platform_role`
  column, a `require_platform_owner` dependency with no `organization_id` to
  be unsure about (`app/auth/dependencies.py`), and three endpoints —
  `GET`/`POST /platform/owners`, `DELETE /platform/owners/{user_id}`
  (`app/api/v1/routers/platform.py`) — to list, grant and revoke it, with
  the same last-owner protection an organization's own last owner already
  gets. A fresh deployment has zero platform owners; `backend/scripts/
  bootstrap_platform_owner.py` grants the first, once, against an
  already-registered account named by `KERVY_PLATFORM_OWNER_BOOTSTRAP_EMAIL`
  — read exactly once, by that script alone, never compared against
  anything at request time. An organization's own `Role.OWNER` grants
  nothing here, by design: see `docs/rbac.md`'s "Above the ladder" section
  and `docs/roadmap.md`'s "The platform-owner model" write-up.
- **An organization admin's view of a fellow member's active sessions**:
  `docs/revocation.md` stated the boundary plainly when `user_sessions`
  shipped — "no admin view of another user's sessions" — which left an
  admin investigating a suspected compromised teammate account no way to
  see or force-end that account's sessions. New `GET`/`DELETE
  /organizations/{organization_id}/members/{member_id}/sessions[/{id}]`
  (`Role.ADMIN`, `app/api/v1/routers/organizations.py`) close it, scoped
  to a fellow member of the caller's own organization — not a widened
  `GET /auth/sessions`. Revoking carries the same owner carve-out
  `update_member_role`/`remove_member` already enforce: an Admin may
  force-revoke another Admin's, Security Engineer's, Analyst's, or
  Viewer's session, but only an Owner may revoke an Owner's.
- **A "Report" card on the run detail page**: the backend has rendered
  markdown/HTML/PDF/JSON/SARIF/CSV reports across four audience templates
  (`/reports` API, §14) since Phase 9, but nothing in the dashboard ever
  offered a way to request one — a member had to already know the API
  shape to get a report out. Added `ReportDownload`
  (`components/runs/report-download.tsx`) to `RunDetail`: a format and
  audience-template picker plus a download button, shown once a run is
  past `draft`/`queued` (mirroring the API's own 409 gate for "nothing to
  report on yet"). Downloading goes through a new `clientApiDownload`
  helper (`lib/api-client.ts`) rather than `clientApiFetch`, since a
  report response is a file with a `Content-Disposition` header, not
  JSON — it fetches the blob under the same session-cookie auth, reads
  the filename the backend already chose, and triggers the browser's own
  save via a transient object-URL anchor. A `501` (PDF requested without
  the optional `weasyprint` dependency installed) surfaces as a plain
  message pointing at another format, instead of a raw error.
- **A "Findings trend" chart on the organization overview page**: a new
  `GET /organizations/{organization_id}/dashboard/findings-trend` endpoint
  (`app/core/dashboard/queries.py::findings_trend`) buckets findings by day
  and severity over a trailing window (30 days by default, clamped to at
  most 180), and a new stacked-area chart
  (`components/dashboard/findings-trend-chart.tsx`) renders it — the first
  use of the `recharts` dependency, which had sat unused in
  `package.json` since the UI redesign. Bucketed by `first_seen`, not
  `last_seen`/`created_at`: a finding's row updates in place every time a
  later scan sees the same one again, so `first_seen` is the one
  timestamp that answers "when did this first show up" and never moves.
- **A general rate-limit ceiling over the rest of the API**, closing a gap
  `docs/rate-limiting.md` named plainly: only login/register/2FA/
  forgot-password/OAuth-callback were throttled; every authenticated route
  had no rate limit at all beyond RBAC. A new `api_default` policy entry
  (1200 requests/5 min per IP, 600/5 min per identity when one is cheaply
  available) is applied by a new `api_rate_limit_middleware`
  (`app/main.py`) — middleware rather than a per-route call, the same
  reasoning the CSRF middleware beside it already gives, so it covers every
  route under `/api/v1` including any added later. `GET /health` is
  exempt. See `docs/rate-limiting.md` and `docs/roadmap.md`.
- **`retest.completed` and `gate.failed` notification events, previously
  defined in the event vocabulary but never emitted** (`docs/integrations.md`
  said so plainly). A retest run now fires `retest.completed` alongside its
  own `assessment.completed`, carrying reproduced/not-reproduced/not-tested
  verdict counts (`app/workers/notifications.py::_notify_run`); a workflow
  run whose gate decision refuses it fires `gate.failed`, carrying the
  severity counts and reasons the gate itself recorded
  (`_notify_workflow_gate_failed`, scheduled from each of `finish()`'s three
  call sites once their own transaction commits — the same "never let a
  hanging channel hold the caller's request open" discipline
  `notify_run_finished` already follows). A passing gate stays silent by
  design: `workflow.completed` in the audit log already covers it, and only
  the failing outcome is worth paging on.
- **CLI: `kervy-ai assist` and `kervy-ai workflow`.** Two domains with a
  real API and no CLI command group at all — Phase 16's own write-up
  named `kervy assist` as deferred, and Phase 17 explicitly refused to add
  CLI support for only its newer pieces (scheduling, webhooks) while base
  workflow CRUD had none, calling that "inconsistent scope creep." Both
  ship complete now: `assist status|draft|drafts|accept` mirrors
  `app/api/v1/routers/assistant.py` exactly, including that
  `--field run_summary` needs no `--scan-result`; `workflow
  create|list|show|update|delete|trigger|runs|webhook-secret|approve|reject`
  mirrors `app/api/v1/routers/workflows.py`. No new backend endpoints or
  logic — every command calls what already existed. See `docs/roadmap.md`
  and `docs/cicd.md`.

- **Dashboard and CLI: tool config, exploitation approve/reject, and
  duplicate-linking are no longer API-only.** The three whole-system-review
  fixes above shipped as REST endpoints with nothing in the dashboard or
  CLI to reach them — a real user had no way to see or use any of them.
  The finding detail page now shows a "Duplicate" card (link/unlink, plus
  the reverse "Duplicates of this finding" list) and the findings list
  gained an `include_duplicates` filter and a "Duplicate" badge;
  `kervy-ai findings link-duplicate`/`unlink-duplicate` mirror the same
  API from the CLI. The agent workspace's "Available tools" card now shows
  each tool's enabled state and effective vs. code-default minimum role,
  with an inline form calling `PUT .../agent/tools/{tool_name}/config`
  directly. The target detail page gained an "Exploitation authorization"
  card (mirroring the existing Authorization card) to grant/view
  `ExploitationAuthorization`, and the run detail page gained an
  "Exploitation fires" section: a create-fire form, a live-polled list of
  fires, and approve/reject actions enforcing the same dual-control rule
  the API already requires. No CLI commands were added for the agent or
  exploitation surfaces — this CLI has never had partial coverage of
  either domain, and adding one command while leaving the rest uncovered
  would be scope creep, the same reasoning already on record for agent
  provider provisioning. See `docs/roadmap.md`.

- **Findings: human-verified cross-engine duplicate linking.** "No
  cross-engine deduplication" has been an honest, stated gap since the
  AppSec engine's own Phase 14 — a SAST finding and a DAST finding
  describing the same underlying defect get different `probe_id` prefixes
  and therefore different fingerprints, so they've always inflated finding
  counts as two findings instead of one. Rather than an invented
  similarity heuristic (explicitly rejected back then as "worse than the
  honest gap"), a new `POST/DELETE .../findings/{finding_id}/duplicate`
  (`Role.ANALYST`) lets an analyst explicitly link one finding as a
  duplicate of another, and `GET .../findings/{finding_id}/duplicates`
  lists them. `GET .../findings` now excludes a linked duplicate by
  default (`include_duplicates=true` to see everything), and a run's own
  report excludes it from its findings section and severity counts too.
  The link is two-level only by construction — a duplicate cannot become
  a primary, a primary with duplicates cannot become one — so there's
  never a chain to walk. See `docs/roadmap.md`.

- **Pentest module: the exploitation tier now requires dual control to
  fire.** A whole-system review flagged Phase 12's own stated deferral —
  "no two-person review... does not require a second, different human
  than the one who fires" — as a real control gap: one
  `Role.SECURITY_ENGINEER` could single-handedly decide and execute a live
  exploit alone. `POST .../runs/{run_id}/exploitation-fires` now creates
  the fire `awaiting_approval` and queues nothing; a new
  `POST .../exploitation-fires/{fire_id}/approve` (`Role.SECURITY_
  ENGINEER`) refuses with `409` if the approver is the same person who
  requested it, re-validates the full three-allowlist gate, and only then
  dispatches the worker. A new `.../reject` endpoint lets the requester (or
  anyone else at that tier) stand a fire down instead. The worker task
  itself re-checks the dual-control invariant at execution time rather
  than trusting the API route. See `docs/roadmap.md`.

- **Agent framework: `AgentTool.enabled`/`minimum_role_override` are now
  enforced**, closing a gap a whole-system review found: both columns had
  existed since the agent's Phase 2 with no code anywhere reading or
  writing them, so an org admin who believed they had disabled a tool or
  raised its minimum role was silently unprotected. New `GET`/
  `PUT .../agent/tools/{tool_name}/config` endpoints (analyst read, admin
  write) let an organization disable a tool or raise (never lower — `422`
  on a lowering attempt) its minimum role above the code default; both
  `POST .../agent/tools/{tool_name}/call` and every step of
  `POST .../agent/investigate`/`.../approve` now enforce it, including on
  a *resumed* investigation, where the configuration is re-loaded fresh
  rather than trusted from before the approval pause. `GET .../agent/tools`
  now reports each tool's `enabled` state and `effective_minimum_role`
  alongside its code default. See `docs/roadmap.md`.

- **Pentest module, Phase 12: the exploitation tier's simulate-then-fire
  two-step.** Real exploit execution — deferred since the Phase 1
  foundation "behind its own `ExploitationAuthorization` tier" — is now
  built, deliberately conservatively. Simulate is automatic: a scan run
  with `asset_scope.max_depth=exploitation` never invokes the real
  module, only an informational marker (`KERVY-PENTEST-108`) showing what
  would be eligible to fire. Fire is a new, separate,
  `Role.SECURITY_ENGINEER` action (`POST .../runs/{run_id}/exploitation-
  fires`) gated by three independent allowlists that must all agree: the
  deployment-wide `KERVY_EXPLOITATION_ALLOWED_NSE_SCRIPTS` operator
  setting (empty by default — nothing is fireable until an operator names
  specific scripts), a new, distinct per-target `ExploitationAuthorization`
  grant (`PUT .../targets/{id}/exploitation-authorization`, `Role.ADMIN`),
  and the target's own `asset_scope.approved_modules`. A successful fire
  produces a `Severity.CRITICAL` finding with full evidence, dispatched to
  the worker rather than run inline, the same way every other scan on this
  platform is. See `docs/roadmap.md`'s Phase 12 write-up and
  `docs/authorization-and-scope.md`.

- **Pentest module, Phase 11: a fuller Next.js findings view.** The
  dashboard summary's top-findings list has always had "no filtering,
  pagination, or status transitions from this surface" (`docs/dashboard.md`)
  — that capability existed only in the older Jinja2 dashboard and the raw
  API. New `/organizations/{id}/findings` (filterable by severity and
  status, paginated) and `/organizations/{id}/findings/{findingId}`
  (full detail: description, impact, remediation, reproduction steps,
  risk inputs) pages close that gap, plus a status-transition form
  restricted to each finding's actual allowed next states
  (`ALLOWED_TRANSITIONS` in `app/models/finding.py`) rather than a free
  dropdown. `GET .../findings` gained optional `limit`/`offset` query
  params to support it — both default to "unbounded", so the CLI, the CI
  gate, and every existing caller see the exact same response they always
  have. Verified live: a real scan of a real target produced a real
  finding, then a scripted browser session filtered, opened, and
  transitioned it end to end. See `docs/dashboard.md`.

- **Optional TOTP-based two-factor authentication**, end to end: backend
  enroll/enable/disable endpoints (`POST /auth/2fa/setup`, `.../enable`,
  `.../disable`) and a login-time challenge (`POST /auth/login/2fa`) that
  redeems a short-lived, single-use ticket `POST /auth/login` returns
  instead of a session once an account has 2FA enabled; and a frontend
  enrollment flow at `/account/security` (QR code, manual-entry secret,
  ten one-time recovery codes shown once) plus a login-time code-entry
  step that replaces the login form's redirect when the backend answers
  with a challenge instead of a session. A password alone is no longer
  sufficient to sign in to a 2FA-enabled account — verified live against
  the running application, including the recovery-code path and disabling
  2FA. Requires `KERVY_TOTP_ENCRYPTION_KEY` on the deployment; the setup
  endpoint refuses with `503` rather than storing a secret insecurely
  when it's unset. See `docs/authentication.md`.

- **Native AI agent provider provisioning.** The agent engine (planner,
  tool runtime, `POST /agent/investigate`) has existed since Agent Phase
  5, but nothing could ever create an `AgentProvider` row for it —
  `investigate` always refused with `409` and there was no endpoint, CLI
  command, or UI anywhere to clear it. Six new endpoints on
  `app/api/v1/routers/agent.py` close that gap: `POST`/`GET`/`PATCH`/
  `DELETE .../agent/providers` and `GET`/`PUT .../agent` (admin tier to
  write, analyst tier to read — never the secret itself, only an
  `api_key_env_var` *name*). Creating a provider with `is_default: true`
  (the default) wires it into `Agent.default_provider_id` and enables the
  agent in the same call, so provisioning is one request, not several.
  `AgentProvider.allowed_ip_ranges` (new column) is what makes the
  `openai_compatible` local-provider path actually usable: it lets a
  self-hosted Ollama/vLLM/llama.cpp endpoint at a private/loopback
  address (`platform_egress_context` previously hardcoded an empty
  allowlist, so `GatedTransport` refused every such endpoint outright)
  authorize exactly the CIDR the operator explicitly configured it at,
  the same `RulesOfEngagement.allowed_ip_ranges` mechanism a scan
  target's own authorization already uses. See `docs/agent.md`
  ("Provisioning a provider").

- Social OAuth login (Google, GitHub) and self-service password reset.
  `User.password_hash` is now nullable for an OAuth-only account; a new
  `OAuthIdentity` table links `(provider, provider_user_id)` to a user —
  never by email, so a provider profile can never silently take over an
  existing password account (a matching email on an unlinked account
  refuses with `409`, same as a duplicate registration). New endpoints:
  `GET /auth/oauth/providers`, `GET /auth/oauth/{provider}/authorize`,
  `GET /auth/oauth/{provider}/callback`, `POST /auth/forgot-password`,
  `POST /auth/reset-password`. Password reset is a single-use, SHA-256-
  digested `PasswordResetToken` (mirroring `ApiKey`'s own secret-handling
  shape) that, on success, invalidates every existing session the same
  way `/auth/logout-all` does. Both OAuth token exchange and the
  platform's own password-reset email go through the same
  `RunContext`/`GatedTransport` scope-engine pattern every other outbound
  destination in this platform uses (`app/core/oauth/egress.py`), scoped
  to exactly the one host each call needs. Both features are off by
  default and require explicit configuration — see
  `docs/configuration.md`.

- Pentest module, Phase 10 (security operations dashboard): a new
  `GET /organizations/{id}/dashboard/summary` endpoint (`Role.VIEWER`)
  and an org-wide overview page in the Next.js frontend — open findings
  by severity, 7-day run/gate activity, remediation and pending-retest
  counts, coverage by pillar (organization-wide, sharing the
  `PILLAR_PREFIXES` table with per-report coverage rather than a second
  copy), and the five most recent runs, five most recent workflow runs,
  and ten highest-risk open findings. The query module behind it
  (`app/web/queries.py`, "no hardcoded dashboard values, every number is
  a real query") moved to `app/core/dashboard/queries.py` so this
  endpoint and the existing Jinja2 dashboard both call the same
  implementation instead of each computing the same counts
  independently. See `docs/dashboard.md`.

- Frontend UI redesign: refreshed design tokens (richer primary color,
  `success`/`warning`/`accent` tokens, an elevation shadow scale, a
  softer radius scale) in `app/globals.css`/`tailwind.config.ts`; new
  `Badge`, `Alert`, and `Skeleton` primitives, and a polish pass on
  `Button`/`Card`/`Input`/`Select`/`Textarea`/`Checkbox`/`Label`
  (shadows, focus/hover/active transitions, loading spinners via
  `Button`'s new `isLoading` prop). Every dashboard page, the org
  section nav, the top nav, and every form's error state now use these
  consistently — ad hoc status pills replaced with `Badge`, and
  `formError` blocks replaced with `Alert`. Dark mode and mobile
  layouts verified with Playwright screenshots at 500px/1440px and a
  true 390px viewport; fixed a real header-overflow bug on narrow
  screens found during that check (the landing page's nav row had no
  shrink/wrap protection).

- Pentest module, Phase 8 (automation): Celery Beat scheduling
  (`Workflow.schedule_interval_minutes`/`next_run_at`, a 60-minute floor),
  an authenticated, replay-protected inbound webhook
  (`POST /api/v1/webhooks/workflows/{id}`, HMAC-SHA256 reusing
  `app/core/integrations/signing.py`'s own scheme as a receiver for the
  first time), and an approval gate for both: any run triggered
  unattended (Beat or the webhook) whose plan would queue a scan-touching
  action pauses (`awaiting_approval`) until a security engineer approves
  or rejects it — approving queues the scan through the exact same
  `queue_run()` `POST /runs` already uses, attributed to the approver. A
  manually-triggered run never pauses. Replay protection is a new
  Redis-backed store that fails closed (the opposite of the rate
  limiter's own fail-open). See `docs/workflows.md`.
- Native AI agent framework (`app/core/agent/`), a structured,
  permission-gated tool-calling layer on top of the existing AI assistant:
  multi-provider support (Anthropic, Gemini, OpenAI, and any
  local/self-hosted endpoint via `openai_compatible`); a closed registry of
  fifteen typed tools across three risk tiers (`READ_ONLY`/`STANDARD`/
  `SENSITIVE`), each requiring its own minimum role; an investigation
  lifecycle that pauses — never silently executes — at an unapproved
  `SENSITIVE` step, resumed only by a separate, higher-tier approval call;
  a six-endpoint API (`/organizations/{id}/agent/...`) and a Next.js AI
  workspace with no persisted conversation; investigation-completed
  notifications through the existing integrations pipeline; and
  `backend/mcp_server/`, a hand-rolled JSON-RPC 2.0 MCP server giving
  external agents the identical, fully-authorized REST surface a native
  caller uses. **Zero new conversation/prompt/response storage**: five
  closed tables hold configuration and non-content metrics only, enforced
  by a closed-table-set pin test, a column-allowlist test, a Redis-TTL
  static test, and a dynamic secret-redaction test. See `docs/agent.md`,
  `docs/guardrails.md` §1.4, and `docs/security-model.md` guarantees
  #29–#30.
- Pentest module, Phase 7 (AI expansion): three new AI capabilities —
  `Capability.ANSWER_EVIDENCE_QUESTION` (`AutonomyMode.ASSIST`) alongside
  the already-declared `CORRELATE_FINDINGS`/`PRIORITISE_FINDINGS`
  (`AutonomyMode.RECOMMEND`), which had sat in `app/core/assistant/autonomy.py`
  with no implementing method until this phase. `AIService` gains
  `correlate_findings()`, `prioritise_findings()`, and
  `answer_evidence_question()`, each its own versioned, evidence-fenced
  prompt template. Exposed as three new READ_ONLY native-agent tools
  (`answer_evidence_question`, `correlate_findings`, `prioritise_findings`
  in `app/core/agent/tools/`), reusing the existing per-organization
  multi-provider infrastructure (`app/core/agent/provider/factory.py`) the
  Agent framework already built — this phase adds no second provider
  layer, since one tool call already resolves an org's configured
  Anthropic/Gemini/OpenAI/`openai_compatible` provider before reaching
  `AIService`. All three tools are read-only recommendations: none writes a
  finding's stored severity, status, or relationships. See `docs/agent.md`.
- Pentest module, Phase 6 (pentest-tool architecture): `app/core/pentest/`
  — a closed, tier-gated `nmap`-NSE-script module registry layered on an
  already-discovered, already-authorized service (this phase wires it only
  to the VM engine's discovered open services). Three modules map onto
  `TestDepth`'s discovery/vulnerability_scan/validation tiers by what an
  NSE script category actually does: `discovery` (safe info-gathering),
  `vuln` (known-vulnerability checks via the `vulns` NSE library's own
  `State: VULNERABLE` convention), and `auth` (confirms no/default-
  credential access — this platform's validation tier). No `exploitation`-
  tier module is registered at all; real exploit execution stays behind
  its own authorization tier, last in the plan (Phase 12). Gated on
  `asset_scope.max_depth`/`approved_modules`, configured through the
  existing `vm-scope` endpoint (`PentestScopeIn` nested in `VmScopeIn` —
  no separate endpoint, since both read the same `asset_scope` document).
  The first check on this platform to depend on another check's result
  (`vm_check.discovered`) rather than only on the target/scope. Also fixes
  a Bandit B314 (XML XXE) finding this phase's own dogfooded static
  analysis exposed in both this engine and the Phase 5 VM engine's `nmap`
  XML parsing — both now use `defusedxml`. See `docs/roadmap.md`.
- Pentest module, Phase 5 (VM engine): `app/core/vm/` — authorized
  port/service discovery against a `TargetKind.VIRTUAL_MACHINE` target's
  declared host, gated on `asset_scope.host`/`allowed_ports`. `nmap -Pn -sV
  --open`, restricted to exactly the declared ports (never a full range),
  parsed from XML with `defusedxml`. Declaring a port already is
  the authorization to probe it — no separate opt-in flag, unlike the
  container engine's `allow_live_pull`. Emits an unconditional port
  inventory plus a finding for a small, fixed set of ports whose mere
  reachability is already noteworthy (Telnet, SMB, Redis, MongoDB, and
  similar); this engine does not itself judge a service vulnerable — that
  is the pentest-tool architecture's job. The second engine to populate
  `run_tool_invocations`, and the first to use `AssetKind.OPEN_SERVICE`.
  Configurable via `PUT /organizations/{id}/targets/{id}/vm-scope`. This
  closes the last of the three engine gaps (domain/container/cloud already
  shipped) the Phase 1 foundation named. See `docs/roadmap.md`.
- Pentest module, Phase 4 (cloud engine): `app/core/cloud/` — read-only
  object-storage (S3) exposure inventory for a `TargetKind.CLOUD_ACCOUNT`
  target, gated on `asset_scope.provider`/`account_ref`/
  `credential_env_var`/`allowed_regions` and on `resolve_cloud_scope`'s hard
  refusal of anything but a read-only assessment. AWS ships fully
  implemented — exactly four read-only `boto3` S3 calls (`list_buckets`,
  `get_bucket_location`, `get_bucket_policy_status`, `get_bucket_acl`),
  never a write verb, enforced by a static test; Azure and GCP route
  correctly but report an explicit "not implemented yet" gap rather than a
  fabricated result. A bucket is judged public from both the bucket policy's
  `IsPublic` flag and ACL grants to `AllUsers`/`AuthenticatedUsers`;
  inventoried buckets are promoted to `DiscoveredAsset` rows
  (upsert-on-rerun). Configurable via `PUT
  /organizations/{id}/targets/{id}/cloud-scope`; `boto3` ships as an
  optional `cloud` extra. See `docs/roadmap.md`.
- Pentest module, Phase 3 (container engine): `app/core/container/` — an
  authorized live registry pull (`docker pull`, with the same
  allowlist-then-resolve-then-block-check pipeline `checkout.py` already
  applies to `git clone`, since a subprocess does not route through
  `GatedTransport`), scanned offline (`trivy image --image-src docker
  --skip-db-update --offline-scan`, reading the local Docker daemon rather
  than letting trivy make its own registry call), and always removed
  afterward. Gated on `asset_scope.allowed_registries` and
  `asset_scope.allow_live_pull` (`allow_live_pull` defaults to `False`), on
  a `TargetKind.CONTAINER` target, configurable via `PUT
  /organizations/{id}/targets/{id}/container-scope`. The first engine to
  actually populate `run_tool_invocations`, the table Phase 1's foundation
  added schema-only. Closes the gap the existing filesystem-mode
  `appsec.container.trivy` engine states plainly rather than fakes: that it
  "did not pull or examine the base image layers" because doing so needs an
  authorization decision it has no scope to make. See `docs/roadmap.md`.
- Pentest module, Phase 1 (foundation) and Phase 2 (domain/DNS engine): a
  generalized `asset_scope` column on Rules of Engagement plus four new
  target kinds (`container`, `cloud_account`, `virtual_machine`, `domain`);
  a `discovered_assets` inventory for scan-found-but-not-authorized assets,
  promoted to a real target only by explicit human action; a
  `run_tool_invocations` record of exactly which tool ran per assessment;
  five new reporting pillars (Container, Cloud, VM, Domain, Pentest); and
  the first working engine — `app/core/domain/` — doing subdomain discovery
  (certificate-transparency logs + a DNS wordlist), TLS certificate checks,
  and missing-security-header checks, wired into the run pipeline and
  configurable via `PUT /organizations/{id}/targets/{id}/domain-scope`. See
  `docs/roadmap.md`.
- Target, repository, run, and workflow management in the Next.js frontend
  (`frontend/app/(dashboard)/organizations/[id]/...`) — previously the only
  way to add a target, connect a repository, set Rules of Engagement, grant
  authorization, start a run, or trigger a workflow was the API or the CLI;
  the server-rendered dashboard at `/app` renders these as disabled buttons
  by design (`app/web/router.py`'s `_actions()`). The Next.js pages call the
  same existing REST endpoints, with a run's page live-polling its status and
  events until it reaches a terminal state.

- Postgres Row-Level Security as a second, independent tenant-isolation
  boundary behind the application's own `organization_id` filters, on the 14
  tenant-scoped tables (`app/db/tenant_context.py`, migration `b2e6f4a91c7d`).
  Defense in depth: a query that forgot its `organization_id` filter now fails
  closed (an empty result) rather than crossing tenants. Requires the runtime
  database role to be a non-superuser — see `docs/deployment.md`'s Database
  section.
- A cumulative, platform-wide daily cap on AI provider spend
  (`app/core/assistant/spend_cap.py`), on top of the existing $5.00
  per-interaction budget, plus real per-call cost estimation
  (`app/core/assistant/pricing.py`) — the per-interaction budget's cost
  dimension previously never actually moved, because every call passed
  `estimated_cost_usd=0.0`.
- Dark/light mode toggle, in both the Jinja2 dashboard and the Next.js
  frontend, remembered per browser via `localStorage` and applied before
  first paint to avoid a flash of the wrong theme.
- Responsive layout pass on the Jinja2 dashboard: header, cards, and tables
  now reflow at phone width; the Next.js frontend's existing Tailwind
  breakpoints were left as-is and its top nav made wrap-safe.
- `kervy-ai repo add|list|show|scan|remove` and
  `/organizations/{id}/repositories` — a lightweight path onto code scanning
  (SAST/SCA/secrets/IaC) for a repository someone already has read access
  to: a URL, a branch, and a self-affirmed consent, skipping the
  Rules-of-Engagement/Authorization-grant workflow a live network target
  needs. New `TargetKind.CODE_REPO` keeps it safe — no `DastCheck`, no AI
  check, only the AppSec engines against a checkout. See
  `docs/repositories.md`.
- A public, unauthenticated landing page (`frontend/app/page.tsx`), replacing
  the previous unconditional redirect to `/login`/`/dashboard`, plus
  `frontend/app/sitemap.ts`, an updated `frontend/public/robots.txt`, and
  meta/Open Graph/Twitter/JSON-LD tags targeting "AI security testing" / "AI
  red teaming". Uses a placeholder domain (`YOUR-DOMAIN.com`) throughout
  until a real one exists — see `docs/seo.md` for the swap-in checklist and
  Google Search Console submission steps.

### Fixed

- **Membership management was missing half its verbs, and the half that
  existed had a privilege-escalation gap.** There was no way to remove a
  member or change an existing member's role at all — only
  `POST /organizations/{id}/members` (invite) existed. Added
  `PATCH .../members/{member_id}` (change role) and
  `DELETE .../members/{member_id}` (remove), both `Role.ADMIN` minimum.
  The gap: `invite_member`'s `Role.ADMIN` minimum let an Admin grant
  `Role.OWNER` to anyone, including an account they control — owner is the
  single most senior role, and nothing should be able to mint one except an
  existing one. All three endpoints now require the caller to already be an
  owner before any operation that grants, changes, or removes `Role.OWNER`;
  an organization's last remaining owner additionally can never be demoted
  or removed, refused with `409` rather than merely discouraged. See
  `docs/security-model.md` guarantee #33.

- `target_kind_enum` was missing `WEB_APP` on any database built by running
  the migrations in order — only `Base.metadata.create_all()` (used by the
  test suite) ever produced it, so a `web_app` target could never actually
  be created against a properly migrated deployment. Found while adding
  `CODE_REPO` to the same enum; both are added by migration `c3f8a2e91b4d`.

- `kervy-ai target roe|adapter|code|runtime-protection` — a full audit pass
  found `target add` and `auth grant` covered by the CLI but the four
  PUT endpoints that finish configuring a target (rules of engagement, the
  adapter, the code scope, the runtime-protection declaration) had no CLI
  command at all, leaving no sanctioned way to complete a target's setup
  short of raw HTTP calls.
- The dashboard's base template requested no favicon, so every page load
  issued an unanswered `GET /favicon.ico` that surfaced as a browser console
  error; an explicit no-op `<link rel="icon">` suppresses the request.

### Documentation

- **A full documentation pass to match everything shipped since the last
  one.** Every one of the 43 files under `docs/`, plus `README.md`, was
  read against the current source it describes and corrected where it had
  drifted — not rewritten wholesale, and several files needed no change at
  all once actually checked. Recurring gaps: social OAuth login and TOTP
  2FA were undocumented in `docs/authentication.md`; owner-gating and the
  exploitation tier's dual control were missing from `docs/rbac.md` and
  `docs/guardrails.md`; `docs/csrf.md`'s own table contradicted a later
  section of itself about which routes carry a token; `docs/agent.md` still
  listed `AgentTool.minimum_role_override` enforcement as a stated future
  deferral after it had already shipped; `docs/cicd.md` and
  `docs/releasing.md` still described `container.yml`, `framework-drift.yml`,
  `lab-e2e.yml`, and `release.yml` as "not yet present" after all four had
  been built, and cited a wheel/repository name from before the Kervy
  rebrand and a later GitHub repository rename; `docs/integrations.md` was
  missing the two agent-investigation notification events; and the README's
  own backend test count was stale by nearly 3x. `docs/architecture.md`,
  `docs/configuration.md`, `docs/dashboard.md`, and
  `docs/authorization-and-scope.md` gained new sections for the exploitation
  tier's dual-control gate, human-verified duplicate linking, the two new
  OAuth/2FA Redis-backed stores, and the dashboard/CLI surfaces for all
  three. No application code changed as part of this pass.

## [0.1.0] — 2026-09-25

First release. A working, authorized-testing AI and API security platform with
an enforced safety boundary, measured findings, sealed evidence, and honest
reports.

### Safety boundary

- Scope engine as the single outbound control point, with a gated transport that
  is the only place in the codebase an HTTP client is constructed. A static test
  enforces it.
- Authorization grants as a first-class object — a named person, role, reference
  and validity window — digested onto every run and reproduced in every report.
  A run without one is refused.
- Rules of engagement: domains, IP ranges, paths, methods, forbidden headers,
  blackout windows, safe mode and budgets.
- DNS re-resolved at send time, so a rebind cannot move a request out of scope;
  redirects never followed, and a `Location` re-checked as a fresh target.
- Cloud metadata addresses refused unconditionally and not allowlistable.
- Redis-backed kill switch, honoured across processes.
- Append-only, hash-chained audit log mirrored from a file log.
- Scope-gated crawler and Nuclei/ZAP DAST adapters under safe mode (see
  `docs/limitations.md` for the one place DAST does not go through the
  gated transport).

### Account security

- Login and registration rate-limited on two dimensions (per-IP and
  per-identity), fail-open on Redis unavailability with Argon2id standing
  behind it either way.
- CSRF protection for every cookie-authenticated write, including a
  pre-session anonymous token (`docs/csrf.md`) so login and registration
  are covered too, not only requests made after one exists.
- Server-side JWT revocation: `/auth/logout` kills one token by its `jti`,
  `/auth/logout-all` kills every token issued before a durable Postgres
  cutoff. `GET /auth/sessions` lists what is currently active and
  `DELETE /auth/sessions/{id}` revokes one specific *other* session by
  name (`docs/revocation.md`).

### Engines

- **API security**: 18 probes covering authentication, transport, CORS, headers,
  debug endpoints, rate limiting, pagination, mass assignment (analysis mode),
  input validation, BOLA, function-level authorization and GraphQL.
- **AI security**: direct injection (six variants), sensitive disclosure, hidden
  context, insecure output handling, excessive agency and unbounded consumption
  — measured over trials against a control arm, with Wilson 95% intervals.
  Detection is marker-based; no harmful-content corpus ships.
- **AppSec**: Semgrep and Bandit (SAST), pip-audit (SCA), two secrets engines
  (working tree and git history), Checkov (IaC).
- **Supply chain**: end-of-life runtimes, dependency licence obligations,
  name-confusion and install-hook signals, known-malicious package
  identification against a vendored GHSA snapshot, and container package
  scanning.

### Findings, evidence and reports

- Ordinal risk model with generated severity rationale; stable fingerprints that
  never include response text or line numbers.
- Finding lifecycle with a restricted transition table, a remediation board, and
  a retest workflow reporting reproduced / not reproduced / **not tested**.
- Evidence redacted *before* it is written, content-addressed and hash-chained;
  verification re-walks the chain and re-hashes the files. Encryption at rest
  is opt-in (`KERVY_EVIDENCE_ENCRYPTION_KEY`, AES-256-GCM) — unset, a bundle is
  protected by filesystem permissions and redaction alone, same as before this
  existed (`docs/configuration.md`).
- Reports in Markdown, HTML, PDF, JSON, SARIF 2.1.0 and CSV, in four audience
  templates, each naming the framework categories that were **not** tested.

### Dashboard

- A read-only, server-rendered dashboard (`/app`) — overview, findings, runs,
  workflows, targets — authenticated by the same session cookie as the API,
  scoped by the same membership check. Findings and runs both page past their
  first 50 rows. Every visible write action is a disabled control naming the
  API or CLI call that performs it, not a hidden button.

### CI/CD and integrations

- `kervy-ai` CLI over the same API and scope engine as the UI.
- Scoped API keys, capped at security engineer so a CI credential can never
  grant authorization.
- Security gate with documented exit codes (0 pass, 1 gate failed, 2 config
  error, 3 auth error, 4 scope violation).
- Outbound notifications: Slack, Microsoft Teams, a signed generic webhook and
  SMTP email, with retry, dead-letter and an audit event per attempt.
- Pull-request publishing as a GitHub check run with inline annotations, sharing
  the gate's verdict. It cannot push, merge or edit — enforced three ways.

### Extensibility

- Entry-point plugins with an operator allowlist pinned by distribution hash,
  `--no-plugins`, and a startup banner. **No sandbox is claimed.**
- AI intelligence layer with an autonomy ladder, a deterministic fake provider
  for CI, and no path to execution. The full suite passes with no provider
  configured.

### Demo lab

- Ten seeded flaws across a vulnerable AI app, a hostile content server and a
  collaborator endpoint. Runs on an internal network with no gateway and no
  published ports, and refuses to start if any of thirteen provider credential
  variables is present.

### Known limitations at 0.1.0

Stated rather than discovered later; the full list is in `docs/limitations.md`.

- DAST exists (a scope-gated crawler, Nuclei and ZAP under safe mode) but is
  not gated at the socket the way every other outbound path is — the two
  scanners open their own connections. No browser, no client-side testing.
- The dashboard is read-only by scope decision; every write is API or CLI
  only.
- `docker compose up --build` is written but **unverified** — image pulls were
  blocked in the build environment. The direct-run path is verified end to end.
- No RASP agent, by decision (Phase 18 is extension points only).
- `retest.completed` and `gate.failed` are defined notification events that
  nothing emits yet.
- SMTP is adjudicated by the scope engine but not carried by the gated
  transport.
- Plugins are not sandboxed; the allowlist is the control.
- Evidence encryption at rest is opt-in, not the default; unset, filesystem
  permissions and redaction are what protect a bundle.
- Rate limiting covers login and registration only — no general throttling
  on the rest of the platform's own API.
- Malicious-package matching is against a small, vendored snapshot of
  published GHSA malware advisories (50 entries), not a live feed — absence
  from that table means "not in this sample", never "confirmed clean".
- No signature verification for plugins, and no container image signing —
  images are scanned, none is published or signed.
- No admin visibility into another user's sessions; `GET /auth/sessions` and
  `DELETE /auth/sessions/{id}` are scoped to the caller's own account.

[Unreleased]: https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform/releases/tag/v0.1.0
