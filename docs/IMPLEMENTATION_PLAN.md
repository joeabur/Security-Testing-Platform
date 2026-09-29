# Implementation Plan — AppSec engines and the AI intelligence layer

Produced per the Implementation Specification §27, which requires inspecting
the repository and stating conflicts before any code is written. The
resolution table is `docs/BUILD_SPEC.md` §4.5; the reasoning behind the three
contested decisions is `docs/decisions/0005-appsec-engines-and-ai-layer.md`.

## 1. Current architecture

Phases 1–6 are shipped, merged and green: 276 tests, ruff clean, `mypy app`
clean, 95% statement coverage, scope engine at 100%.

```
backend/app/
  core/
    scope/          the safety boundary — engine, gated transport, budgets,
                    kill switch, DNS. The single outbound control point.
    targets/        adapters: chat_http, openai_compatible, http_openapi
    discovery/      hardened OpenAPI 3.x parser
    orchestrator/   runner, checks, probe_check, ai_check, context_builder
    probes/
      api/          16 API probes (OWASP API1–API9 + GraphQL)
      ai/           11 AI probes, trials/ASR driver, judge (disabled)
    measure/        Wilson intervals, decision rule, stability
    redaction/      secret detection, digests, masking
  models/           org, user, membership, target, authorization, RoE,
                    api_spec, surface_endpoint, synthetic_account,
                    assessment_run, run_event, scan_result
  api/v1/routers/   auth, organizations, targets, surface, runs
  workers/          Celery task, Redis cancellation
frontend/           Next.js — auth scaffold only, no dashboard
```

## 2. What is reused unchanged

Everything above. In particular:

- **The scope engine and gated transport.** Every new engine — including
  subprocess tools — routes through it. No second choke point is created.
- **`ScanResult` (§11.1) and `ScanResultRecord`.** All new engines normalize
  into the existing shape; nothing gets its own finding format.
- **The probe registry pattern.** `ProbeRegistry` and `ProbeCheck` already
  run a set of probes over a target, collect results, and turn a crashed
  probe into a visible gap. AppSec engines plug into the same mechanism.
- **The redaction module.** The standalone secrets engine wraps these
  detectors rather than adding a second implementation.
- **Run lifecycle, budgets, cancellation, SSE progress, audit log, RBAC,
  tenant isolation.**

## 3. Conflicts, and how they are resolved

Summarised here; full table in §4.5 of the build spec.

| Conflict | Resolution |
|---|---|
| Simplicity constraint vs. shipped Postgres/Redis/Celery | Keep — the "demonstrated requirement" clause is met and tested |
| Next.js vs. Jinja2 + HTMX | Move to Jinja2 + HTMX; the scaffold has no dashboard to lose |
| `kervy` vs. `kervy-ai` CLI name | `kervy`, with `kervy-ai` as an alias |
| Addendum phases 13–15 vs. v3.0's thirteen phases | One sequence; new work is 14–18 |
| MVP engine set: IaC vs. DAST vs. RASP | SAST/SCA/Secrets/IaC first, DAST next, RASP reduced to interfaces |
| Assistant may not execute vs. `EXECUTE` autonomy mode | Ladder implemented; `EXECUTE` never reaches a target or an authorization |
| Standalone secrets engine vs. existing redaction module | Reuse the detectors; one redaction policy only |

## 4. Phases

Each ends with a green suite, honest roadmap notes, and a push. Phase 14
before 16 before 18, per the later specification's own triage rule.

### Phase 14 — AppSec engines (SAST, SCA, Secrets, IaC)

The MVP engine set. Kervy orchestrates; it does not reimplement scanners.

- `Target.code` (`repo_ref`, `languages`, `build_manifest_paths`) and
  `RulesOfEngagement.code_scope` (allowed/excluded paths, size cap). Absent
  or ambiguous `code_scope` → refuse to run, the same fail-closed rule as §6.
- A `ToolAdapter` base handling subprocess invocation, graceful absence,
  version capture and SARIF/JSON normalization into `ScanResult`.
- Semgrep + Bandit (SAST), pip-audit + OSV (SCA), Gitleaks + the existing
  detect-secrets stack (Secrets), Checkov (IaC).
- Fingerprint on rule ID + normalized path + code-span signature, **not**
  line number, so an unrelated edit does not split one issue into many.
- A finding may only carry an identifier the upstream tool actually emitted.
  Normalization is not a licence to launder an invented CVE.

*Likely to change:* new `core/appsec/{sast,sca,secrets,iac}/`, new
`ToolAdapter`, `models/target.py`, `models/rules_of_engagement.py`, a
migration, `orchestrator/`, new lab fixture (a small vulnerable repo).

*Acceptance:* finds every seeded flaw in the vulnerable repo fixture, zero
against a hardened control, zero invented identifiers.

### Phase 15 — DAST

`kind: web_app`, a crawler whose every discovered URL is re-checked against
the RoE **before** being queued, ZAP and Nuclei adapters under `--safe`.

### Phase 16 — AI intelligence layer

- `AIService` with a small provider abstraction (`generate`,
  `structured_output`), OpenAI-compatible and local endpoints, credentials by
  reference only.
- A **deterministic fake provider** used by default in tests, so no test run
  spends tokens.
- Analysis: explanation, evidence interpretation, correlation, duplicate
  suggestions, prioritisation, posture summaries.
- Drafting into `draft_*` fields requiring an explicit accept; real fields
  are never written by the model.
- Autonomy ladder `OFF / ASSIST / RECOMMEND / APPROVAL_REQUIRED / EXECUTE`,
  defaulting to `ASSIST`, with `EXECUTE` unable to reach a target.
- Every interaction logs model, prompt template and version to the audit
  trail.
- Evidence fed to the assistant is **data, not instructions** — the same
  posture the platform tests for on the target side, applied to itself, with
  a release-blocking test.

*Acceptance:* with no provider configured, the entire existing suite passes
unchanged; import-linter proves nothing in `core` outside `assistant/`
imports it.

### Phase 17 — Workflows, dashboard, CI gate

Trigger→Plan→Actions→Evidence→Result persisted in the existing database;
Jinja2 + HTMX dashboard replacing the Next.js scaffold; a deterministic
GitHub Actions gate that an AI recommendation cannot alter.

### Phase 18 — RASP extension points and hardening

Interface only, no engine, no agent.

## 5. Dependencies actually required

New, and only these: `semgrep`, `bandit`, `pip-audit`, `osv-scanner`
(binary), `gitleaks` (binary), `detect-secrets`, `checkov` — all optional at
runtime and degrading gracefully; `jinja2` (already a FastAPI extra) and
HTMX/Alpine via CDN or vendored static files for the dashboard; an
OpenAI-compatible HTTP client, which is `httpx` through the existing gated
transport rather than a vendor SDK.

Explicitly **not** added: Kubernetes, Kafka, Elasticsearch, a vector
database, an event bus, a multi-agent framework, or a second SBOM generator.

## 6. What this plan does not do

- It does not rewrite the storage layer, the queue, or any shipped engine.
- It does not build a RASP agent, and no phase here produces one.
- It does not give the AI layer a route to the network that the scope engine
  does not gate.
