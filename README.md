# Kervy Security

An open-source web platform for **authorized** security assessment of
Generative AI applications — their models, prompts, retrieval layers,
agents, tools, and supporting APIs — producing defensible, reproducible,
framework-mapped findings.

This is not a probe library and not a UI prototype. The full design —
mission, non-goals, safety/payload policy, the scope-and-authorization
engine, determinism/ASR methodology, domain model, and the phased build
plan — lives in **[`docs/BUILD_SPEC.md`](docs/BUILD_SPEC.md)**. Read that
first; this README is the practical "how do I run it" companion.

**Current status: v0.1.0 — the original 18-phase AppSec/API/AI platform is
complete**, and several later builds sit on top of it: a broader **pentest
module** (all 12 phases — containers, cloud, VMs, domains, a sequenced
pentest-tool adapter layer, multi-vendor AI throughout, Celery Beat
scheduling, an HMAC-signed inbound webhook, an organization-wide
security-operations dashboard, and a simulate-then-fire exploitation tier,
now itself requiring a second, different security engineer to approve
before anything real fires — `docs/roadmap.md` records each phase), a
**native AI agent** (all 7 phases plus a follow-up closing a dead-code gap
in its own permission model — a closed, typed tool registry with risk
tiers, an approval flow, and per-organization tool enable/disable and
minimum-role overrides that are now actually enforced, adding zero new
persistent storage beyond an explicit metrics allowlist, `docs/agent.md`),
a **frontend redesign** of the Next.js dashboard, and account-management
work (social OAuth login via Google/GitHub, TOTP two-factor authentication,
and membership controls — removing a member or changing their role, with
granting the Owner role itself restricted to existing Owners). A
whole-system review also closed the platform's last honest gap in
cross-engine finding correlation: an analyst can now explicitly record that
two findings from different engines describe the same underlying defect,
without any invented similarity heuristic. `docs/roadmap.md` records each
of these as its own entry. What works end to end today: the
scope/authorization engine and its gated transport (the single outbound
control point), target adapters and OpenAPI discovery, run orchestration
with cancellation and live progress, 16 API probes, 11 AI probes measured
with Wilson-interval attack success rates against their own controls, the
SAST/SCA/secrets/IaC engines plus supply-chain analysis (end-of-life
runtimes, licence obligations, dependency name confusion, container
packages), the AI assistant layer (drafts only, never execution),
risk-scored findings with stable fingerprints and human-verified
cross-engine duplicate linking, and content-addressed evidence plus reports
in Markdown, HTML, PDF, JSON, SARIF 2.1.0 and CSV, and a remediation board
with a retest workflow that reports reproduced / not reproduced / not
tested with the evidence from either side, now with a Wilson-interval
ASR-delta comparing the before/after attack success rate directly rather
than only presence/absence of the same fingerprint.

A later competitive-gap-closing pass (`docs/competitive-gap-analysis.md`
records what was audited, closed, narrowed, or honestly left open) added:
a DAST egress gateway that routes Nuclei/ZAP through the same scope engine
GatedTransport already enforces, a Playwright-driven browser crawl for
client-side-rendered pages, two new AI probe families (indirect/RAG
document injection and agent goal-hijacking, each a real but narrower
first technique rather than full category coverage), a multi-turn attack
orchestration engine, a `kervy-ai test ai [--ci]` regression command
comparing two runs' AI-probe results via the same Wilson-interval rule,
direct `osv.dev` vulnerability intelligence for npm dependencies, an
import-level reachability check for Python SCA findings, automatic
audit-log events for finding-status changes a scan (not a human) makes,
and dashboard UI for actions that previously existed only as a CLI
command or a raw API route (run cancel, retest trigger, remediation
assignment, evidence list/verify/download, workflow edit/delete, and
`kervy-ai apikey create/list/revoke`).

There is also an `kervy-ai` CLI and a CI security gate with documented exit
codes — see [`docs/cicd.md`](docs/cicd.md).

Findings and finished runs can be sent out to Slack, Microsoft Teams, a
signed generic webhook, or email, or opened as a ticket in Jira Cloud or
ServiceNow. A notification channel is not an exception to the outbound
rule: every delivery goes through the same scope-gated transport, under an
allowlist derived from the channel's resolved destination, and webhook
credentials are held by environment-variable reference rather than stored — see
[`docs/integrations.md`](docs/integrations.md).

Findings can also be posted back to a GitHub pull request as a check run with
inline annotations, sharing the CI gate's verdict so a pull request and a
pipeline cannot disagree. That integration reads the diff and writes a check
run — it cannot push, merge or edit, and the scope engine refuses the HTTP verbs
those would need. See [`docs/pull-requests.md`](docs/pull-requests.md).

There is an isolated, intentionally vulnerable demo lab in
[`demo-target/`](demo-target/), and a self-review of the platform's own
controls in [`docs/security-review.md`](docs/security-review.md).

Workflows are in: five stages (trigger, plan, actions, evidence, result)
whose plan is derived from the trigger and the target's configuration
alone, and whose gate decision an AI recommendation structurally cannot
alter; Celery Beat scheduling and an HMAC-signed, replay-protected inbound
webhook trigger them unattended, always pausing for human approval before
an unattended trigger's plan queues a scan — see
[`docs/workflows.md`](docs/workflows.md).

There are two dashboards, deliberately, for two audiences — see
[`docs/dashboard.md`](docs/dashboard.md). The **Next.js app in `frontend/`**
is the primary product UI: organizations, targets, runs, workflows,
repositories, the native AI agent workspace (including per-tool
enable/disable and minimum-role configuration), an organization-wide
security-operations overview (open findings by severity, coverage by
pillar, remediation and retest health, recent activity), finding
duplicate-linking, and the exploitation tier's authorization grant and
fire/approve/reject flow. A second, **server-rendered dashboard at `/app`**
is Jinja2 with optional HTMX, no build step, read-only because no write
actions are built yet (not, any longer, for lack of a CSRF token — see
`docs/csrf.md`), and every number on either dashboard is a real query
against the same core query module, never two independently-computed
answers to the same question.

Runtime protection is recorded as a *claim*, never a measurement, and no RASP
agent ships — this platform does not run inside anybody's process. See
[`docs/runtime-protection.md`](docs/runtime-protection.md). Releases are signed
keylessly with Sigstore and carry build provenance; verify one before running it
with the commands in [`docs/releasing.md`](docs/releasing.md).

Cookie-authenticated state changes require a CSRF token, bound to the session
so a planted cookie pair cannot forge one — and Bearer-authenticated API and
CLI callers are deliberately exempt, because they were never at risk. See
[`docs/csrf.md`](docs/csrf.md).

Authentication endpoints are rate limited — two dimensions, throttled never
locked out, and unable to tell a caller whether an account exists. See
[`docs/rate-limiting.md`](docs/rate-limiting.md).

A session can be killed server-side, not just its client cookie: `/auth/logout`
revokes one token, `/auth/logout-all` revokes every token a user has ever been
issued as an immediate response to a suspected leak. This is the one
Redis-backed control on the platform that fails *closed*, deliberately the
opposite of the rate limiter next to it. See
[`docs/revocation.md`](docs/revocation.md).

All eighteen phases of the original AppSec/API/AI platform are built, all
seven phases of the native AI agent are built, and all twelve phases of the
pentest module are built. [`docs/roadmap.md`](docs/roadmap.md) records
exactly what's built versus deferred, and why, phase by phase;
[`docs/limitations.md`](docs/limitations.md) says what the tool cannot detect
and where its false positives cluster.

## Why this exists

The open-source AI red-teaming space already has strong tools — garak,
PyRIT, promptfoo, DeepTeam, Giskard. None of them combine a hard
authorization/scope boundary, tamper-evident evidence, cross-tool finding
normalization, and statistically honest (ASR + confidence interval)
reporting into one assessment workflow. See `docs/BUILD_SPEC.md` §1.1 for
the full comparison, and [`docs/comparison.md`](docs/comparison.md) for where
those tools are still better.

## Architecture

```
Browser ──▶ Next.js ──▶ FastAPI ──▶ PostgreSQL
                             │
                             ▼
                           Redis ──▶ Celery Workers ──▶ Security Testing Engine ──▶ Authorized Target
```

- **Frontend:** Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS,
  TanStack Query, React Hook Form + Zod.
- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic,
  PostgreSQL, Redis, Celery, Argon2id password hashing, JWT sessions.
- **Deployment:** Docker Compose (`frontend`, `backend`, `worker`,
  `postgres`, `redis`).

Full layering rules and the reasoning behind PostgreSQL/Redis/Celery from
Phase 1 (rather than an MVP-first SQLite path) are in `docs/BUILD_SPEC.md`
§4 and `docs/decisions/0001-storage-and-product-shape.md`.

## Quickstart

Full instructions, including the two steps that are easy to miss, are in
**[`docs/installation.md`](docs/installation.md)**. The executable version is
[`docs/examples/quickstart.py`](docs/examples/quickstart.py) — the same script
used to verify this release.

```bash
cp .env.example .env
docker compose up --build          # see the note below
```

Then register, create an organization, register the demo lab as a target, and —
before anything reaches it — record an authorization grant and rules of
engagement. A run without a grant is refused with `409`. That refusal is the
product.

**Verified end to end for 0.1.0**, running the API, a Celery worker and the demo
lab directly (not under Docker):

```
run WITHOUT authorization        409  <- refused, as designed
run status                       completed
scan results                     10 results, 10 distinct codes
findings                         7
download report markdown/sarif/json  200
evidence chain verify            ok=True
```

The lab's planted AWS key and both static tokens appear in none of the three
report formats.

> **Docker is unverified.** The environment this was built in blocks Docker Hub
> blob downloads at the proxy (HTTP 403 from the registry CDN), so the images
> could not be pulled and `docker compose up --build` has never actually run.
> The compose file and Dockerfiles are written and reviewed but unexercised. The
> direct-run path below *is* verified.

### Local development without Docker

```bash
# Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
export DATABASE_URL=postgresql+asyncpg://<user>:<password>@localhost:5432/kervy
export REDIS_URL=redis://localhost:6379/0
alembic upgrade head
uvicorn app.main:app --reload

# Frontend (separate shell)
cd frontend
npm install
npm run dev
```

## Testing

```bash
make test-backend   # pytest, against a real Postgres — see backend/tests/conftest.py
make test-frontend  # vitest
make lint            # ruff + eslint
make typecheck       # mypy --strict + tsc --noEmit
```

Backend: 1,348 test functions across 103 files (`backend/tests/` and
`backend/tests/security/`), covering registration, login/logout, OAuth,
2FA, session cookies vs. bearer tokens, RBAC (owner/admin/
security_engineer/analyst/viewer) enforced via a pinned
`test_authorization_matrix.py` that fails the moment a new route omits an
explicit role, cross-organization tenant isolation, every engine, the
pentest module (including the exploitation tier's dual-control gate), and
the native agent (including tool enable/disable and role-override
enforcement). `ruff check` clean, `mypy --strict` clean.

Frontend: Vitest coverage of the Zod validation schemas and the login form's
client-side validation/submission behavior, `eslint` clean, `tsc --noEmit`
clean, `next build` succeeds.

## Security model (what exists today)

- Passwords are hashed with Argon2id; never stored or logged in plaintext —
  and are optional entirely for an account created via OAuth (Google or
  GitHub), whose `password_hash` stays null until it sets one.
- Sessions are httpOnly, `SameSite=Lax` cookies signed as JWTs; the frontend
  never reads or stores the token itself.
- Optional TOTP-based two-factor authentication: enabling it changes
  `/auth/login`'s own response shape (a short-lived challenge instead of a
  session) until `/auth/login/2fa` redeems it, with one-time recovery codes
  for a lost authenticator.
- RBAC (Owner/Admin/Security Engineer/Analyst/Viewer) is enforced
  **server-side only** — the frontend's UI is not a security boundary — and
  pinned by a test that fails the build the moment a new route omits an
  explicit role. Granting the Owner role itself is Owner-only; any member
  can be removed, but never demoted or removed by someone below Admin.
- A non-member accessing another organization's resources gets `404`, not
  `403`, so the organization's existence isn't confirmed to callers who have
  no legitimate reason to know it.
- Every auth and organization-membership action is written to an
  append-only, hash-chained audit log (`app/audit/service.py`), both as
  database rows and as a JSON-lines file.
- Structured error responses never leak stack traces or internal exception
  details to the client.
- The native AI agent's own permission model — which tools it may call, at
  what minimum role, and whether a tool is disabled for an organization —
  is enforced on every call, including a resumed investigation, where the
  configuration is re-loaded fresh rather than trusted from before an
  approval pause.
- The pentest module's exploitation tier never runs a real exploit from an
  ordinary scan — it only emits a "this would be eligible" marker. Actually
  firing one requires a second, different Security Engineer or above to
  approve a first person's request; the same person can never both request
  and approve.

- The scope engine is the single outbound control point: exclusions are
  checked before allowlists, DNS is re-resolved per request, private and
  cloud-metadata ranges are refused, and redirects are never followed
  automatically. `GatedTransport` is the only place an HTTP client may be
  constructed, and a static test greps `app/` to keep it that way.
- Evidence is redacted before it is written, stored content-addressed with a
  hash-chained manifest, and served only to a member of the owning
  organization — there are no public report or evidence URLs. It is **not**
  encrypted at rest; see `docs/roadmap.md`.
- The AI assistant layer can draft and recommend. It cannot start a scan,
  grant authorization, or change a finding's real fields under any
  configuration.
- Login and register are rate limited (per-identity and per-IP), cookie-
  authenticated writes require a session-bound CSRF token, and JWTs can be
  revoked server-side (per-session or "log out everywhere").

See [`docs/guardrails.md`](docs/guardrails.md) for the consolidated map of
every AI/LLM guardrail, human-in-the-loop checkpoint, and security control
above, each linked to its full mechanism and test. `docs/roadmap.md` has the
complete list of what is still deferred.

## Documentation

- [`docs/BUILD_SPEC.md`](docs/BUILD_SPEC.md) — the full, unified build
  specification (mission, safety policy, architecture, domain model, probe
  catalogue, risk scoring, reporting, phased plan, definition of done).
- [`docs/installation.md`](docs/installation.md) — install, quickstart, and
  what was verified for this release.
- [`docs/architecture.md`](docs/architecture.md) — shape, packages, and the
  decisions worth knowing.
- [`docs/authorization-and-scope.md`](docs/authorization-and-scope.md) — the
  safety model in full. Read this one if you read only one.
- [`docs/configuration.md`](docs/configuration.md) — every environment
  variable, and why credentials are held by reference.
- [`docs/authentication.md`](docs/authentication.md) and
  [`docs/rbac.md`](docs/rbac.md) — passwords, tokens, API keys, the role ladder.
- [`docs/scanning.md`](docs/scanning.md) — running a scan, what it needs, and
  the run lifecycle.
- [`docs/ai-security-testing.md`](docs/ai-security-testing.md) and
  [`docs/api-security-testing.md`](docs/api-security-testing.md) — what each
  engine tests, and what it does not.
- [`docs/detection-methodology.md`](docs/detection-methodology.md) — trials,
  baselines, Wilson intervals, fingerprints, and what a claim is worth.
- [`docs/risk-model.md`](docs/risk-model.md) — every number in the scoring
  tables.
- [`docs/reporting.md`](docs/reporting.md) — formats, audiences, redaction and
  access control.
- [`docs/frameworks.md`](docs/frameworks.md) — pinned editions with retrieval
  dates, and why CWE carries no version.
- [`docs/limitations.md`](docs/limitations.md) — what this cannot detect, and
  where false positives cluster.
- [`docs/comparison.md`](docs/comparison.md) — honest positioning against
  garak, PyRIT, promptfoo, DeepTeam, Aikido and ZAP, including where they win.
- [`docs/threat-model.md`](docs/threat-model.md) and
  [`docs/security-model.md`](docs/security-model.md) — who might attack this,
  and what holds.
- [`docs/guardrails.md`](docs/guardrails.md) — the consolidated map: AI/LLM
  guardrails, human-in-the-loop checkpoints, and the security controls
  already built in, each linked to its full mechanism.
- [`docs/agent.md`](docs/agent.md) — the native AI agent: multi-provider,
  permission-gated tool calling with zero persistence, the investigation
  approval flow, and the external MCP surface.
- [`docs/rate-limiting.md`](docs/rate-limiting.md),
  [`docs/csrf.md`](docs/csrf.md), and
  [`docs/revocation.md`](docs/revocation.md) — authentication rate limiting,
  CSRF protection, and server-side JWT revocation.
- [`docs/acceptable-use.md`](docs/acceptable-use.md) — the authorization rule,
  stated plainly.
- [`docs/deployment.md`](docs/deployment.md) and
  [`docs/troubleshooting.md`](docs/troubleshooting.md).
- [`docs/scaling-architecture.md`](docs/scaling-architecture.md) — the next
  step up: a reference architecture, component-by-component scaling design,
  and setup path for a cloud-hosted deployment handling many organizations
  and concurrent assessments.
- [`docs/third-party.md`](docs/third-party.md) — every integrated tool, its
  licence and how it is used.
- [`docs/decisions/`](docs/decisions/) — architecture decision records.
- [`docs/plugin-development.md`](docs/plugin-development.md) — writing a
  plugin, what the platform guarantees it, and what it explicitly does not
  (there is no sandbox, and the allowlist is the control).
- [`docs/security-review.md`](docs/security-review.md) — a self-review of the
  platform's own controls: how each was verified, and what is not covered.
- [`docs/pull-requests.md`](docs/pull-requests.md) — posting findings to a
  pull request: what that layer cannot do and how each boundary is enforced.
- [`docs/dast.md`](docs/dast.md) — the scope-gated crawler: why a discovered
  URL is checked before it is queued rather than before it is fetched, and what
  the scanner adapters cannot guarantee.
- [`docs/supply-chain.md`](docs/supply-chain.md) — end-of-life runtimes,
  licence obligations, name confusion and container scanning: why each exists
  where no CVE does, and what each deliberately does not claim.
- [`docs/integrations.md`](docs/integrations.md) — outbound notifications:
  why a channel cannot become an SSRF primitive, how credentials stay out of
  the database, the retry and dead-letter rules, and the webhook signing
  scheme.
- [`docs/cicd.md`](docs/cicd.md) — the `kervy-ai` CLI, API keys, and the CI
  security gate: its exit codes, and why it refuses to fail a build on an
  unstable finding.
- [`docs/roadmap.md`](docs/roadmap.md) — what's built, what's deferred, and
  why.

## Contributing and security

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — setup, the checks that must pass, and
  the eight rules that are not negotiable.
- [`SECURITY.md`](SECURITY.md) — reporting a vulnerability privately, and what
  is in and out of scope.
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`CHANGELOG.md`](CHANGELOG.md)
- [`docs/acceptable-use.md`](docs/acceptable-use.md) — **read this before
  pointing the tool at anything.**

## License

[Apache-2.0](LICENSE) — see
[`docs/decisions/0004-licence.md`](docs/decisions/0004-licence.md) for the
rationale (a patent grant matters for security tooling).
