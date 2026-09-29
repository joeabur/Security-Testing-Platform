# Architecture

## Shape

```
                    ┌──────────────┐
   browser ────────▶│   frontend   │  Next.js — auth pages only today
                    └──────┬───────┘
                           │ HTTP
   kervy-ai CLI ──────────▶│
   CI job       ──────────▶│
                    ┌──────▼───────┐      ┌──────────────┐
                    │   FastAPI    │◀────▶│  PostgreSQL  │
                    │   app/api    │      └──────────────┘
                    └──────┬───────┘
                           │ Celery over Redis
                    ┌──────▼───────┐
                    │    worker    │──── evidence ──▶ EVIDENCE_ROOT (files)
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
```

Everything that leaves the process passes the box in the middle. That is the
architecture's one non-negotiable claim; `docs/authorization-and-scope.md`
explains how it is enforced rather than merely intended.

## Packages

| Path | Responsibility |
|---|---|
| `app/core/scope/` | The safety boundary: engine, gated transport, budgets, DNS, kill switch |
| `app/core/targets/` | Adapters — how to talk to a target (`chat_http`, `openai_compatible`, `http_openapi`) |
| `app/core/discovery/` | OpenAPI parsing and attack-surface derivation |
| `app/core/orchestrator/` | Run composition: which checks, in what order, with what budget. Pure — no database |
| `app/core/probes/` | API security probes and the `ScanResult` contract |
| `app/core/measure/` | Trials, baselines, Wilson-interval attack success rates |
| `app/core/appsec/` | SAST, SCA, secrets, IaC, supply-chain and container engines |
| `app/core/domain/` | Domain/DNS engine (pentest module) — subdomain discovery via certificate-transparency logs and a DNS wordlist, TLS/header checks against RoE-authorized hosts only |
| `app/core/risk/` | Ordinal scoring, banding, generated rationale |
| `app/core/findings/` | `ScanResult` → `Finding`: normalization, fingerprinting, lifecycle |
| `app/core/evidence/` | Redaction-before-write, content addressing, hash chain |
| `app/core/reporting/` | Markdown, HTML, PDF, JSON, SARIF, CSV; four audience templates |
| `app/core/gate/` | The CI decision and its exit codes |
| `app/core/assistant/` | The AI layer. Drafts only, never execution |
| `app/core/integrations/` | Outbound notifications |
| `app/core/vcs/` | Pull-request publishing |
| `app/plugins/` | Entry-point discovery, allowlist |
| `app/models/`, `app/schemas/`, `app/api/` | Persistence, wire shapes, routes |
| `app/workers/` | Celery tasks |

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
outside `assistant/` imports it, so with no provider configured the whole system
behaves identically.

## Request lifecycle of a scan

1. API validates the request, checks RBAC, and confirms an authorization grant
   exists and is valid. No grant → `409`.
2. A run row is created and a Celery task queued. The authorization and RoE
   digests are recorded on the run, so what it ran under is knowable later even
   if the target's configuration changes.
3. The worker resolves the target's adapter and attack surface, composes checks,
   and builds a `RunContext` — authorization window, RoE, budget tracker, kill
   switch.
4. Each check runs through `GatedTransport`. Every decision is audited; every
   observation that establishes a finding becomes a redacted, sealed evidence
   bundle.
5. `ScanResult`s are persisted, then promoted to `Finding`s: normalized,
   fingerprinted, scored, deduplicated against existing findings.
6. Reports render on demand from the stored findings and evidence.
7. Notifications and pull-request publishing run out of band, so a Slack outage
   cannot fail a run.

## Storage

PostgreSQL for everything relational; Redis for the Celery broker and the kill
switch; the filesystem under `EVIDENCE_ROOT` for evidence bundles. Evidence is
deliberately not in object storage by default and has no public URL — it is the
most sensitive artifact the platform holds.

See `docs/decisions/` for the ADRs behind storage, queue, naming, licence, and
the AppSec/AI layering.
