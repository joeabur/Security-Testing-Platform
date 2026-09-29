# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
