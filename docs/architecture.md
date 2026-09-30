# Architecture

## Shape

```
                    ┌──────────────┐
   browser ────────▶│   frontend   │  Next.js — dashboard, targets, runs,
                    └──────┬───────┘  workflows, repositories, native agent
                           │ HTTP
   kervy-ai CLI ──────────▶│
   MCP client   ──────────▶│  (mcp_server/, stdio JSON-RPC)
   CI job       ──────────▶│
                    ┌──────▼───────┐      ┌──────────────┐
                    │   FastAPI    │◀────▶│  PostgreSQL  │◀── Row-Level
                    │   app/api    │      │  (RLS on)    │    Security,
                    └──────┬───────┘      └──────────────┘    defense in
                           │ Celery over Redis                depth behind
                    ┌──────▼───────┐                           app-level
                    │    worker    │──── evidence ──▶ EVIDENCE_ROOT (files) filters
                    │ app/workers  │
                    └──────┬───────┘
                           │
                    ┌──────▼────────────────────────────────┐
                    │  ScopeEngine + GatedTransport         │
                    │  the single outbound control point    │
                    └──────┬────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┬───────────────┐
        ▼                  ▼                  ▼               ▼
     target           AI provider        Slack / SMTP      api.github.com

   Celery Beat ──▶ dispatches scheduled workflow runs and inbound webhooks
                    (HMAC-signed, replay-protected) through the same
                    queue_run() the API and the agent both call — one path,
                    never two.

   app/web/  ──▶ a second, read-only Jinja2+HTMX dashboard served by the
                 same FastAPI app at /app/... — a lighter, no-JS-build
                 operational view alongside the Next.js frontend, not a
                 replacement for it.
```

Everything that leaves the process passes the box in the middle. That is the
architecture's one non-negotiable claim; `docs/authorization-and-scope.md`
explains how it is enforced rather than merely intended.

## Packages

Core engines and domain logic:

| Path | Responsibility |
|---|---|
| `app/core/scope/` | The safety boundary: engine, gated transport, budgets, DNS, kill switch |
| `app/core/targets/` | Adapters — how to talk to a target (`chat_http`, `openai_compatible`, `http_openapi`) |
| `app/core/discovery/` | OpenAPI parsing and attack-surface derivation |
| `app/core/orchestrator/` | Run composition: which checks, in what order, with what budget. Pure — no database |
| `app/core/probes/` | API security probes and the `ScanResult` contract |
| `app/core/measure/` | Trials, baselines, Wilson-interval attack success rates |
| `app/core/appsec/` | SAST, SCA, secrets, IaC, supply-chain and container-image engines |
| `app/core/domain/` | Domain/DNS engine — subdomain discovery via certificate-transparency logs and a DNS wordlist, TLS/header checks against RoE-authorized hosts only |
| `app/core/container/` | Container engine — live registry pulls, RoE-scoped |
| `app/core/cloud/` | Cloud engine — read-only AWS/Azure/GCP posture checks against an RoE-authorized account |
| `app/core/vm/` | VM engine — authorized port/service discovery |
| `app/core/pentest/` | The pentest-tool adapter layer: discovery, vulnerability assessment, validation kept as distinct, sequenced stages. The exploitation tier is simulate-then-fire: an ordinary run only ever emits an eligibility marker; firing a real exploit is a separate, dual-control action (`exploitation_service.py`) |
| `app/core/dast/` | DAST engine (Nuclei, ZAP) — the first engine that discovers its own targets rather than working from a document a human supplied; safe-mode gated |
| `app/core/rasp/` | Runtime-protection extension points only — deliberately no RASP-effectiveness engine (§4.5's own resolved conflict) |
| `app/core/risk/` | Ordinal scoring, banding, generated rationale |
| `app/core/findings/` | `ScanResult` → `Finding`: normalization, fingerprinting, lifecycle |
| `app/core/redaction/` | Secret detection: a detected secret is never persisted, only its hash, a masked preview, and its location |
| `app/core/evidence/` | Redaction-before-write, content addressing, hash chain |
| `app/core/reporting/` | Markdown, HTML, PDF, JSON, SARIF, CSV; four audience templates; the pillar-coverage table (`PILLAR_PREFIXES`) shared with the dashboard |
| `app/core/dashboard/` | Organization-wide query functions behind both dashboards (Next.js's summary endpoint and the Jinja2 page) — one implementation of "how many open findings", not two |
| `app/core/gate/` | The CI decision and its exit codes |
| `app/core/workflow/` | The five-stage workflow engine (trigger → plan → actions → evidence → result), Celery Beat scheduling, the inbound HMAC-signed webhook, and the approval gate for unattended triggers |
| `app/core/runs/` | `queue_run()` — the one path an assessment run is ever queued through, called by the API, the agent, and workflow automation alike |
| `app/core/repositories/` | Connecting a repository for code scanning without the live-target authorization workflow |
| `app/core/retest/` | Retest planning and verdicts — reproduced / not reproduced / not tested |
| `app/core/assistant/` | The AI *drafting* layer. Drafts only, never execution |
| `app/core/agent/` | The native AI *agent* layer: a closed, typed tool registry with risk tiers, permission checks, and an approval flow for sensitive actions — zero new persistent storage beyond an explicit metrics/config allowlist |
| `app/core/integrations/` | Outbound notifications, and the HMAC signing scheme the inbound webhook verifies against as a receiver |
| `app/core/vcs/` | Pull-request publishing |
| `app/core/csrf/` | CSRF tokens for the one place this platform uses cookie-based sessions (the browser-facing login flow) |
| `app/core/ratelimit/` | Login and per-route rate limiting |
| `app/core/revocation/` | Server-side JWT revocation — an authorization decision, fails closed |
| `app/core/oauth/` | Social login (Google, GitHub): a Redis-backed anti-CSRF state token, token exchange through its own gated egress context (never a bare `httpx` call), account linking to an existing email |
| `app/core/twofactor/` | TOTP enrollment and verification, plus one-time recovery codes for a lost authenticator |
| `app/plugins/` | Entry-point discovery, allowlist |
| `app/models/`, `app/schemas/`, `app/api/` | Persistence, wire shapes, routes |
| `app/web/` | The Jinja2+HTMX read-only dashboard — a second, no-JS-build presentation layer over the same core query modules |
| `app/workers/` | Celery tasks, including the Beat schedule (`dispatch_scheduled_workflows`) |
| `app/db/tenant_context.py` | Bridges the request-scoped organization id to Postgres's Row-Level Security session variable |
| `mcp_server/` | The external API/MCP surface: a stdio JSON-RPC transport over the same tool registry the native agent uses |
| `kervy_cli/` | `kervy-ai` — every command is a REST call; nothing reaches a target directly |

## Decisions worth knowing

**The orchestrator is pure.** It takes checks and a context and returns an
outcome; it does not touch the database. That is what makes run composition
testable without Postgres, and it is why the persistence lives in
`app/workers/tasks.py` instead.

**Probes and engines are explicitly registered.** `pip install` does not decide
what runs inside the scope engine's process. A plugin must additionally appear
in an operator allowlist (`docs/plugin-development.md`).

**`ScanResult` is the single wire shape.** An API probe, an AI probe and a
third-party SAST adapter all produce the same structure, which is what lets one
normalization, one fingerprint scheme, one risk model and one report renderer
serve all of them.

**Fingerprints never include response text.** They are computed from probe id,
normalized surface and an evidence signature. Including the response would make
one long-lived issue look like a new finding on every run.

**Evidence is redacted before it is written**, content-addressed, and chained.
`created_at` is part of the bundle's content, so re-writing the same bundle is
idempotent while two genuine observations stay two bundles.

**The AI layer is a leaf.** An import-linter rule confirms nothing in `core`
outside `assistant/`/`agent/` imports it, so with no provider configured the
whole system behaves identically.

**Tenant isolation is two independent boundaries, not one.** Every
organization-scoped query already filters by `organization_id` explicitly in
application code, and Postgres Row-Level Security enforces the same boundary
a second time from a session variable (`kervy.org_id`) set once per
request/task. RLS exists specifically for the bug class application-level
filtering cannot catch — a query that forgot the filter — and fails closed
(an unset session variable matches no rows) rather than leaking another
organization's data. See `app/db/tenant_context.py` and
`docs/security-model.md` guarantee #12.

**One path to queue a scan, however it was triggered.** A human calling
`POST /runs`, the native agent's `start_scan` tool, and an unattended
workflow trigger (Celery Beat or the inbound webhook) all call the same
`app/core/runs/service.py::queue_run()`. An unattended trigger whose plan
would touch a target always pauses for human approval first — the approval
is what supplies the `user_id` every queued run is attributed to, not a
bolted-on permission check. See `docs/workflows.md`.

**Two dashboards, one set of queries.** The Next.js frontend's summary
endpoint and the Jinja2+HTMX page both read `app/core/dashboard/queries.py`
rather than each computing counts independently, so "how many open findings"
can never quietly have two different answers depending on which UI asked.
See `docs/dashboard.md`.

**The native agent adds zero new persistent storage** beyond an explicit,
closed allowlist of operational configuration and metrics — no conversation
history, no stored transcript. Every tool it can call wraps a platform
capability reachable directly, at the same role and authorization checks;
the agent is a typed calling convention over existing capabilities, not a
new privilege surface. Per-organization tool `enabled`/`minimum_role_override`
configuration is enforced on every call, including a *resumed*
investigation, where it is re-loaded fresh rather than trusted from before
an approval pause. See `docs/agent.md`.

**Firing a real exploit requires two different people.** The exploitation
tier's simulate step is automatic and never runs real attack code; the fire
step is a separate action gated by three independent allowlists (operator
NSE-script allowlist, a target-specific `ExploitationAuthorization`, and the
run's own RoE `approved_modules`) plus dual control — the person who
requests a fire can never be the one who approves it, checked again by the
worker at execution time rather than trusted from the enqueue-time decision.
See `docs/authorization-and-scope.md`.

**A duplicate is a human's claim, never an inference.** Two engines finding
the same underlying defect get different `probe_id` prefixes and therefore
different fingerprints — `app/core/findings/service.py::link_duplicate`
lets an analyst explicitly record that one finding duplicates another (and
excludes it from default listings and report counts), but nothing computes
a similarity score or links anything automatically. The relationship is
two levels deep by construction: a duplicate cannot itself gain duplicates,
and a finding with duplicates cannot become one.

## Request lifecycle of a scan

1. API validates the request, checks RBAC, and confirms an authorization grant
   exists and is valid. No grant → `409`.
2. A run row is created and a Celery task queued (`queue_run()` — the same
   function whether the caller is a human, the native agent, or an
   unattended workflow trigger). The authorization and RoE digests are
   recorded on the run, so what it ran under is knowable later even if the
   target's configuration changes.
3. The worker resolves the target's adapter and attack surface, composes checks,
   and builds a `RunContext` — authorization window, RoE, budget tracker, kill
   switch.
4. Each check runs through `GatedTransport`. Every decision is audited; every
   observation that establishes a finding becomes a redacted, sealed evidence
   bundle.
5. `ScanResult`s are persisted, then promoted to `Finding`s: normalized,
   fingerprinted, scored, deduplicated against existing findings.
6. If the run was linked to a workflow, `gate_workflow_run_if_linked` gates
   the workflow's own outcome over the findings this run just produced —
   the same deterministic gate a manually-triggered workflow uses.
7. Reports render on demand from the stored findings and evidence; the
   dashboards' summary counts are live queries over the same tables, not a
   separate materialized view.
8. Notifications and pull-request publishing run out of band, so a Slack
   outage cannot fail a run.

## Storage

PostgreSQL for everything relational, with Row-Level Security enabled on
every tenant-scoped table as a second, independent boundary behind the
application's own `organization_id` filters; Redis for the Celery broker,
the kill switch, the rate limiter, JWT revocation, the AI spend cap, the
agent's paused-approval session store, the inbound-webhook replay guard,
the OAuth login flow's anti-CSRF state token, and the 2FA login-challenge
store — nine independent Redis-backed stores, each with its own stated fail
direction (most fail closed; the rate limiter deliberately fails open); the
filesystem under `EVIDENCE_ROOT` for evidence bundles. Evidence is
deliberately not in object storage by default and has no public URL — it is
the most sensitive artifact the platform holds.

See `docs/decisions/` for the ADRs behind storage, queue, naming
(including the Aegis → Kervy rebrand, ADR 0006), licence, and the
AppSec/AI layering.
