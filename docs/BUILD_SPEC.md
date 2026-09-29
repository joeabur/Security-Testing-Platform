# Build Specification — Kervy Security

**Generative AI Risk Identification & Security Testing Platform**

**Spec version:** 3.1 (unified)
**Written:** 2026-09-18
**Supersedes:** "Build Specification v2.0" (CLI/MVP-first spec) and "Master Build Prompt" (full-stack web-app spec), merged and reconciled in v3.0. v3.1 folds in two later documents: the **AppSec Addendum v2.1** (SAST/DAST/SCA/Secrets/RASP + AI-assistant layer) and the **Implementation Specification** (simplicity constraint, MVP engine set, AI as a first-class platform layer). Where any source documents conflicted, the conflict and its resolution are recorded explicitly in §4.4, §4.5 and in `docs/decisions/`.

**Precedence, highest first:** §2 (safety, legality, payload policy) and §6 (scope & authorization engine) — these are never relaxed by any later document, and any apparent conflict with them is a defect in the later document; then the Implementation Specification (latest, and explicitly takes precedence for the changes it names); then the AppSec Addendum v2.1; then this document's v3.0 body.

---

## 0. How you must work

(Unified from both sources — identical intent, no conflict.)

1. **Verify before you assert.** Every framework identifier, technique ID, CWE number, CVE, or control reference written into code, config, or docs must be checked against the upstream source in §3. If it cannot be verified, leave a `TODO(verify)` marker and list it in `docs/unverified-mappings.md`. **Never invent a mapping, technique ID, or CVE** — a fabricated `AML.T####` is a worse defect than a missing one.
2. **Framework data is ingested, not typed.** Where an upstream project publishes machine-readable data (MITRE ATLAS does), write an importer and pin the release. Do not transcribe by hand.
3. **Build in the phase order in §26.** At the end of each phase: run the full test suite, linters, and type checker, then stop and report what passes, what fails, and what was deferred. Do not begin the next phase with a red suite.
4. **Tests before implementation for the scope/authorization engine.** It is the safety boundary. Written test-first, no exceptions.
5. **No pseudocode in delivered modules.** If something cannot be implemented properly within a phase, omit it and record it in `docs/roadmap.md` with a reason. Do not silently stub it.
6. **Ask rather than assume** on: project/repo name availability, target Python/Node versions, whether a hosted LLM is available in the build environment, and licence posture. If asking isn't possible, pick the conservative option and document the choice in `docs/decisions/`.
7. **Small, conventional commits.** One logical change per commit, Conventional Commits format.
8. **Honesty in documentation.** README states real limitations, real false-positive behaviour, and what the tool does *not* detect. No marketing claims, no unmeasured coverage percentages.

---

## 1. Mission

Build an open-source platform that lets an **authorized** security professional assess a Generative AI application — its models, prompts, retrieval layer, agents, tools, and supporting APIs — through a real, usable **web application** (not a UI prototype, not mocked data), and produce defensible, reproducible, framework-mapped findings.

The product is not "a scanner." It is **an assessment workflow with a hard authorization boundary, reproducible evidence, normalized findings, and a team-usable interface.**

### 1.1 Why this exists (state honestly in the README)

| Tool | Strength | Gap this project addresses |
|---|---|---|
| garak (NVIDIA) | Broadest probe library, model-agnostic | No scope/authorization model; no finding lifecycle; no team workflow |
| PyRIT (Microsoft) | Multi-turn, adaptive attack orchestration (crescendo, TAP) | Library, not an assessment workflow; no reporting/evidence chain |
| promptfoo | YAML-driven, CI-native, agentic presets | Eval harness framing; shallow on API-layer testing |
| DeepTeam | OWASP-aligned vulnerability taxonomy | Tied to DeepEval stack |
| Giskard | Model + RAG scanning | Quality/robustness focus more than offensive security |
| ZAP / Nuclei | Mature web and API testing | No AI-layer awareness |

**The differentiator, and it must be real:**

1. **Fail-closed authorization and scope enforcement** — refuses to fire when authorization cannot be proven, enforced server-side, never trusting the browser.
2. **Evidence integrity** — every finding carries a tamper-evident, redacted, replayable evidence bundle.
3. **Normalization** — AI findings, API findings, and imported third-party tool output land in one schema with stable fingerprints and a lifecycle across repeat assessments, across a whole team/organization.
4. **Statistical honesty** — non-deterministic tests are reported as attack success rates with confidence intervals and named detector precision, not binary pass/fail.

If the result is a marginally-different probe library, or a dashboard with hardcoded numbers, the build has gone wrong.

### 1.2 Non-goals

- Not a guardrail / runtime defence product.
- Not a model-quality, bias, fairness, or hallucination-benchmarking tool. Misinformation (LLM07:2026) is in scope only where it is *security*-relevant (output driving an automated action).
- Not a training-pipeline or model-weights security tool. Data/model poisoning (LLM05:2026) is assessed by **questionnaire and supply-chain inspection**, not active testing.
- Not an unrestricted attack-automation framework (§2).
- Not a replacement for a human assessor.

---

## 2. Safety, legality, and payload policy

Both source documents agree in full here; this section is authoritative and non-negotiable.

### 2.1 Authorization is a hard gate

No test executes without a resolved, in-date, signed authorization record for the target, **verified server-side**. The engine **fails closed**: any ambiguity in scope resolution aborts the run with a non-zero exit / a blocked API response and a clear message. There is no `--force`, no `--yolo`, no global disable, and **the frontend is never trusted to enforce this** — every check is repeated on the backend/worker immediately before a request is made.

### 2.2 Payload policy

- **Marker-based detection, not harmful content.** A prompt-injection probe succeeds when the system emits an agreed canary marker (per-run random token) or takes a flagged benign action — never when it produces genuinely dangerous output.
- **No weaponized payloads in the repository.** No jailbreaks whose payoff is CBRN, weapons, CSAM, or targeted harassment content. Harm-category coverage, if any, checks only that a refusal occurred, using benign stand-in requests.
- **No live exploitation of downstream systems.** Insecure-output-handling tests identify dangerous *data flows* and stop at a proof-of-reachability marker. No RCE, no shell execution, no destructive SQL.
- **No privilege modification, no deletion, no state mutation** in safe mode (the default). BOLA/authorization checks read; they do not write.
- **Payload provenance.** Every probe declares `payload_source` (original / adapted-from-<citation> / generated) and a licence note.

### 2.3 Documented refusals

`SECURITY.md` and `docs/acceptable-use.md` state plainly: this tool is for authorized assessment; unauthorized use is likely criminal in most jurisdictions; maintainers will not accept feature requests for evasion of consent controls, scope bypass, or harmful-content generation.

### 2.4 Demo target isolation

The intentionally vulnerable demo app (`demo-target/`, §19) must: bind to loopback only by default, run on an isolated Docker network with no egress (`internal: true`), refuse to start if a real provider API key is present in the environment, use a local stub or tiny local model, contain only synthetic data, and print a banner identifying itself as intentionally vulnerable.

---

## 3. Framework baseline — verified current as of September 2026

Identical in both sources; kept verbatim as the more rigorous v2.0 treatment. **Verify each entry against its source before use** — this table is a starting point, not gospel.

### 3.1 AI / GenAI

| Framework | Version to target | Source of truth | Notes |
|---|---|---|---|
| OWASP Top 10 for LLM Applications | **2026 edition** (2026-08-04) | `github.com/GenAI-Security-Project/GenAI-LLM-Top10`, path `2026/final/` | Moved out of the legacy OWASP repo into the GenAI Security Project |
| OWASP Top 10 for Agentic Applications | **2026** (ASI01–ASI10, 2025-12-09) | genai.owasp.org | Extends, does not replace, the LLM Top 10 |
| MITRE ATLAS | latest calendar release (e.g. `v2026.09`) | `github.com/mitre-atlas/atlas-data` | YAML + STIX 2.1 + Navigator layers. **Import, do not transcribe.** IDs are renamed/retired between releases |
| NIST AI RMF 1.0 | AI 100-1 (2023) | nist.gov | Govern, Map, Measure, Manage |
| NIST GenAI Profile | AI 600-1 (2024-07-26) | nist.gov | |
| NIST foundation-model misuse guide | AI 800-1 | nist.gov | Optional |
| OWASP AISVS | current release | OWASP | Checklist-mode assessment fit |
| OWASP AIVSS | **v0.8** (2026-03-19) | aivss.owasp.org | Agentic risk scoring; v1.0 expected late 2026. **Optional, clearly labelled draft** |

**2026 LLM Top 10 ordering** (confirm against source before writing YAML):

```
LLM01 Prompt Injection
LLM02 Sensitive Information Disclosure
LLM03 Excessive Agency
LLM04 Supply Chain
LLM05 Data and Model Poisoning
LLM06 Unbounded Consumption
LLM07 Misinformation
LLM08 Hidden Context Exposure
LLM09 Vector and Embedding Weaknesses
LLM10 Improper Output Handling
```

*System Prompt Leakage* (LLM07:2025) was **retired**, absorbed into **Hidden Context Exposure** (LLM08:2026), which also covers retrieved documents, memory, user data, application state, and tool responses. *Insecure Output Handling* is LLM10, not LLM02. **Never carry 2023 or 2025 numbering into this codebase.**

### 3.2 API / application

| Framework | Version | Notes |
|---|---|---|
| OWASP API Security Top 10 | **2023** (API1–API10:2023) | Still current, no 2026 edition |
| OWASP Top 10 (web) | **2025** (finalized Jan 2026) | Software Supply Chain Failures at #3; Mishandling of Exceptional Conditions at #10; SSRF folded into Broken Access Control |
| OWASP ASVS | current release | Selective mapping only |
| CWE | current | Real CWE IDs or none |

### 3.3 Supporting

CIS Benchmarks, NIST CSF 2.0, ISO/IEC 27001, ISO/IEC 42001, CSA MAESTRO. Map selectively; a thin correct crosswalk beats a broad invented one.

### 3.4 Mapping mechanics (mandatory)

Each file in `framework-mappings/` carries a header:

```yaml
framework:
  id: owasp-llm-top10
  name: OWASP Top 10 for LLM Applications
  version: "2026"
  source_url: https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final
  retrieved_at: "2026-09-18"
  licence: CC-BY-SA-4.0
  attribution: "OWASP Foundation"
  verified_by: <who/what verified this>
```

- A JSON Schema validates every mapping file; CI fails on schema violation.
- `framework-drift.yml` (weekly) fetches upstream and fails when the pinned version is stale, opening an issue rather than silently updating.
- Findings reference framework entries by ID and mapping-file version, so a report stays reproducible after a framework update.
- `kervy-ai frameworks list` / `kervy-ai frameworks diff <from> <to>` are first-class CLI commands.

---

## 4. Product shape & architecture

### 4.1 What is being built

A **real, runnable, multi-user web application**, reachable at `http://localhost:3000` after `docker compose up --build`, backed by a real database, real background scan jobs, and a CLI/API for CI use. This resolves in favor of the Master Build Prompt's product framing: the platform is a team tool with organizations, roles, and a browser UI as the primary surface, with the CLI as a first-class secondary interface for CI/CD — not the other way around.

### 4.2 Stack decision (ADR — see §4.4 for the reconciliation)

**Frontend:** Next.js, React, TypeScript, Tailwind CSS, shadcn/ui, TanStack Query, React Hook Form, Zod, Recharts. Professional cybersecurity/SOC-style UI — not a generic SaaS landing page.

**Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic, PostgreSQL, Redis, Celery (or `arq` if Celery proves heavier than needed — decide in `docs/decisions/0002-task-queue.md` and hold to it), `httpx` (async, scope-gated only), `structlog`.

**CLI:** `kervy-ai`, Typer + Rich, talks to the same REST API a browser session would use (never a separate code path with weaker scope checks).

**Testing:** `pytest`, `pytest-asyncio`, `respx`, `hypothesis` (scope-engine property tests) on the backend; component/page/flow tests on the frontend; Playwright (or similar) for end-to-end flows.

```text
Browser ──▶ Next.js ──▶ FastAPI ──▶ PostgreSQL
                             │
                             ▼
                           Redis ──▶ Celery Workers ──▶ Security Testing Engine ──▶ Authorized Target
```

### 4.3 Layering

```
frontend/       Next.js app (routes, components, hooks — thin, calls the REST API only)
backend/app/
  api/            FastAPI routers; request/response models only
  auth/           authn, session/token handling, RBAC enforcement
  core/
    scope/        authorization + scope engine  (the safety boundary — built and tested first)
    orchestrator/  run lifecycle, budgets, concurrency, kill switch, Celery task glue
    targets/       target adapters
    probes/        probe registry + execution
    detect/        detectors, judges, calibration
    risk/          scoring
    findings/      normalization, fingerprinting, lifecycle, dedup
    evidence/      capture, redaction, sealing, retention
  frameworks/     importers + mapping resolution
  reporting/      renderers (json, sarif, html, md, csv, pdf)
  db/, models/, schemas/   SQLAlchemy models, Pydantic schemas, repositories, Alembic migrations
  audit/          append-only, hash-chained audit log
  workers/        Celery task definitions (thin — call into core/ services)
  policies/       organization/asset/assessment configuration hierarchy
cli/            Typer commands — thin, calls the REST API
plugins/        entry-point discovery + sandboxing policy
```

**Dependency rule** (unchanged from both sources, enforced by an import-linter contract in CI): `api`, `cli`, and `workers` may depend on `core`; `core` never imports from `api`, `cli`, `reporting`, or `workers`. Business logic lives in `core/` services; API routes and CLI commands are thin adapters over those services, so the web UI, the CLI, and CI all exercise identical logic — including identical scope enforcement.

### 4.4 Reconciling the two source specs — decisions

The two input documents disagree on fundamentals. Resolved here; each decision is also recorded as an ADR in `docs/decisions/`.

| Conflict | v2.0 spec said | Master Build Prompt said | Resolution |
|---|---|---|---|
| **Primary interface** | CLI-first; FastAPI only added in phase 7; dashboard "deliberately small," optional | Full Next.js web app is the primary product from Phase 1 | **Web app wins.** The moment the product has organizations, RBAC, multi-tenant assets, and real-time scan progress meant for a team, a CLI-first MVP under-serves the actual requirement. The CLI remains a first-class citizen for CI/CD, but is a client of the same REST API, not the initial deliverable. |
| **Storage/queue** | SQLite + in-process asyncio; Postgres/Redis/Celery deferred to an *optional* "scale profile" (`docker-compose.scale.yml`) | PostgreSQL + Redis + Celery from Phase 1, always | **Postgres/Redis/Celery from Phase 1.** v2.0's rationale for SQLite ("one engineer against one target") does not hold once organizations, concurrent users, and real-time browser progress are in scope — those require a real multi-writer database and a broker for background jobs regardless of scale. SQLite is not offered as a profile; it would only fragment testing effort. This reverses v2.0 §4.1's default. |
| **Project name** | Placeholder `kervy` pending a PyPI/npm/GitHub/trademark check ("make a rename a one-commit change") | Named product: **Kervy Security**, repo `kervy-security` | **Adopt "Kervy Security" / `kervy-security`**, but keep the name as a single constant/config value (`PRODUCT_NAME`, package name) exactly as v2.0 insisted, so a rename remains a one-commit change if the trademark/namespace check (still owed — recorded in `docs/decisions/0003-naming.md`) turns up a conflict. `kervy` alone is avoided for the PyPI/CLI binary name in favor of `kervy-ai` to reduce collision risk, per the Master Prompt's own naming. |
| **Finding schema depth** | Rich schema: `stability`, `attack_success_rate` with Wilson CI, `control_success_rate`, separate `cvss_v4`/`aivss`/internal risk score, `mapping_versions` | Simpler normalized scanner JSON (`id, title, category, severity, confidence, evidence, ...`) | **v2.0's rich schema is canonical** (§11). The Master Prompt's simpler JSON becomes the **wire format individual scanners/plugins emit** (`ScanResult`), which the findings service then promotes/enriches into the full `Finding` record (adds fingerprint, ASR/CI, risk score, lifecycle, mapping versions). This gives plugin authors a small, stable contract while keeping the stored model rigorous. |
| **Determinism/trials machinery** | Mandatory: N trials, control runs, Wilson-CI attack success rate, judge calibration published or judge disabled | Not specified; implies scans just "find" things | **v2.0's determinism machinery is mandatory and unchanged.** It is what makes the product statistically honest and is one of the four stated differentiators (§1.1). The web UI must surface ASR + CI on every probabilistic finding, not just a pass/fail badge. |
| **Scope engine strictness** | Extremely detailed pipeline + mandatory property-based test matrix (§6) | Similar pipeline, less detailed test matrix, adds explicit SSRF metadata-IP blocking language | **Union of both**, using v2.0's full test matrix as the release gate and folding in the Master Prompt's explicit SSRF/DNS-rebinding language (already compatible, not contradictory). |
| **Reporting** | JSON/SARIF/HTML/MD/CSV/PDF, one report structure, "coverage honesty" requirement | Same formats plus four **audience-specific templates** (Technical/Executive/Developer/Compliance) | **Union.** Keep v2.0's mandatory report sections and coverage-honesty rule; add the Master Prompt's four report templates as different renderings of the same underlying data — never different data. |
| **Third-party tool candidates** | ZAP, Nuclei, Trivy, Semgrep, Bandit, detect-secrets, Gitleaks, Presidio, garak, PyRIT, promptfoo, DeepTeam, cdxgen/Syft | Same list | No conflict — merged as-is (§16). |

Nothing in this reconciliation weakens §2 (safety/payload policy) or §6 (scope engine) — those sections are identical in both sources and are treated as absolute regardless of which product-shape decision wins.

---

### 4.5 Reconciling the AppSec Addendum and the Implementation Specification — decisions

Three documents now govern this build, written at different times with
different emphases. Where they disagree, this table is the resolution. Each
row states which document wins and why, so that a future reader can tell a
decision from an oversight.

| # | Conflict | Resolution | Reasoning |
|---|---|---|---|
| 1 | Impl Spec §3 says avoid PostgreSQL (prefer SQLite), Redis and Celery. Phases 1–6 shipped all three. | **Keep them.** | Impl Spec §3 bans *introducing* these "unless a demonstrated requirement in the existing codebase makes them necessary", and §1 says to reuse working architecture and not rebuild functioning components. The requirements are demonstrated and tested: multi-tenant row isolation and JSON/ENUM columns (Postgres), cross-process run cancellation (Redis), and out-of-request run execution with SSE progress (Celery). Rewriting them onto SQLite would delete six phases of tested behaviour to satisfy a constraint whose own escape clause is already met. A SQLite "local profile" is tracked as a later simplification, not a rewrite. |
| 2 | Impl Spec §3/§16 wants a Jinja2 + HTMX dashboard; Phase 1 shipped a Next.js app. | **Move to Jinja2 + HTMX.** | This is the one stack conflict where the Impl Spec plainly wins. The Next.js app is a thin auth-only scaffold (login, register, create-organization) with no dashboard built on it, so the sunk cost is small and the simplicity gain is real. The existing REST API is unchanged; the dashboard becomes a server-rendered consumer of it. |
| 3 | Impl Spec §19 and Addendum §6.4 call the CLI `kervy`; v3.0 §20 and ADR 0003 call it `kervy-ai`. | **`kervy`**, with `kervy-ai` kept as an alias. | Two later documents agree on the shorter name, and an alias costs one line while keeping every existing document's examples working. |
| 4 | Addendum §9 appends phases 13–15 assuming v2.0's twelve; v3.0 already has thirteen. Impl Spec §24 proposes its own ten-phase order. | **One sequence: v3.0 Phases 1–13 unchanged, then 14–18** (see §26). | Renumbering shipped phases would invalidate every commit message, roadmap entry and ADR that references them. The Impl Spec's ordering is honoured *within* the new phases: AppSec engines before assistant, RASP last and reduced. |
| 5 | Impl Spec §5 names the MVP engine set as SAST, SCA, Secrets, **IaC**; the Addendum names SAST, DAST, SCA, Secrets, **RASP**. | **SAST, SCA, Secrets, IaC first** (Phase 14); DAST second (Phase 15). | The Impl Spec is the later document and explicitly takes precedence for the changes it names. IaC is additive and cheap; DAST is request-heavy and needs the crawler scope work, so it earns its own phase. |
| 6 | Addendum §4.5 specifies a full RASP-effectiveness engine (its Phase 14); Impl Spec §7 says do **not** implement RASP in the MVP and keep it from complicating the architecture. | **Extension points only** (Phase 18, deferred). | The later and more restrictive document wins. The `runtime_protection` fields in §5.1 and the probe interface are enough to add the engine later without a rewrite, which is exactly what Impl Spec §7 asks for. Neither document permits shipping a RASP *agent*. |
| 7 | Addendum §6 forbids the assistant from executing anything; Impl Spec §11 lists `EXECUTE` among the autonomy modes. | **Both, scoped:** the autonomy ladder is implemented, and `EXECUTE` may never cover authorization, scope, or any action that touches a target. | The documents are reconcilable: `EXECUTE` applies to artifact generation (reports, summaries, drafts). Anything that would consume budget, send a request, grant authorization or change a finding's real fields stays at `APPROVAL_REQUIRED` or above, per Addendum §6.3 and §28. §2 and §6 outrank both documents anyway. |
| 8 | Addendum §4.4 promotes secret detection to a standalone engine; Phase 6 already shipped `core/redaction/secrets.py`. | **Reuse the existing detector stack**, wrapped by a new scan surface. | The detectors, digests and masking rules are already written and tested. A second implementation would be a second redaction policy, which is precisely how the §13 "never persist a secret" invariant gets broken. |

---

## 5. Domain model

The flat "Target" object naively conflates several distinct concerns; keep them separate (v2.0 §5), now nested under multi-tenancy (Master Prompt §7–9).

```
Organization        the tenant boundary; every object below belongs to exactly one
User / Membership / Role   identity and RBAC within an organization
Target               what is being tested (technical description) — the Master Prompt calls this "Asset"; use Target/Asset interchangeably in docs, Target in code
Authorization        who said you may test it, and until when
RulesOfEngagement    how you may test it (budgets, methods, exclusions)
AssessmentRun         one execution; immutable once complete — the Master Prompt calls this "Assessment"
Attempt              one probe execution against one surface, one trial
Observation          what came back (request/response pair, redacted)
Detection            a detector's verdict on an Observation, with confidence
Finding              an aggregated, deduplicated, scored conclusion
Evidence             the sealed bundle supporting a Finding
RemediationTask      a Finding turned into tracked work (Master Prompt §26)
Report               a generated document over a Run's findings
ApiKey               scoped credential for CI/CD use
AuditEvent           append-only record of security-sensitive actions
```

Every `Target`, `AssessmentRun`, `Finding`, `RemediationTask`, `Report`, and `AuditEvent` carries an `organization_id`. Cross-organization access is a release-blocking test (§24), not an afterthought.

### 5.1 Target / Asset

```yaml
target:
  id: uuid
  organization_id: uuid
  name: demo-ai-app
  environment: staging        # staging | test | dev | production (production requires extra confirmation)
  kind: llm_app               # llm_app | agent | rag | api | web_app | mcp_server | model_endpoint
                              # web_app added by Addendum v2.1 §4.2 for classic DAST targets
  code:                       # Addendum v2.1 §3 — present only for SAST/SCA/Secrets/IaC scanning
    repo_ref: git+https://github.com/example/app.git#main   # or a local path under an explicit allowlist
    languages: [python, typescript]
    build_manifest_paths: ["pyproject.toml", "package.json"]
  runtime_protection:         # Addendum v2.1 §3 — RASP-effectiveness assessment only (deferred, see §4.5)
    claimed_controls: [waf, rasp_agent, input_validation_middleware]
    vendor: string | null
    telemetry_endpoint: keyring://...
  adapters:
    - type: http_openapi
      base_url: https://ai.example.test
      spec_ref: ./openapi.yaml
    - type: chat_http
      endpoint: /api/chat
      request_template: ./templates/chat.json
      response_path: $.message.content
  model:
    provider: unknown | openai | anthropic | azure | self_hosted | ...
    identifier: string
    reported_by: header | api | operator_supplied
  auth:
    scheme: bearer | api_key | oauth2 | session | none
    credential_ref: keyring://kervy-ai/demo-ai-app/token   # NEVER an inline secret
  accounts:                   # for BOLA / privilege testing — synthetic test accounts only
    - role: user_a
      credential_ref: keyring://...
    - role: user_b
      credential_ref: keyring://...
```

Credentials are **never** stored in the database or a YAML file in plaintext. Store a reference resolved at runtime from the OS keyring, an env var, or an external secrets manager. The config loader rejects any value that looks like a live secret (entropy + prefix heuristics) with an actionable error.

### 5.2 Authorization

```yaml
authorization:
  target_id: uuid
  authorized_by: { name: string, role: string, email: string }
  reference: "TICKET-1234 / signed SOW 2026-09-01"
  valid_from: 2026-09-17T00:00:00Z
  valid_until: 2026-09-24T00:00:00Z
  scope_digest: sha256:...
  signature: { method: minisign | age | gpg | none, value: ... }
  attestation_accepted_by: operator-local-username
  accepted_at: timestamp
```

- Expiry enforced at **every** request. A run crossing `valid_until` halts mid-flight.
- `production` environment requires an interactive typed confirmation of the target name, plus an explicit "I confirm that I am authorized to test this target" checkbox in the assessment wizard (Master Prompt §14) and, for CLI, `--i-have-written-authorization`. This is logged, never a bypass.
- The authorization record and RoE are hashed into every report and every evidence bundle.

### 5.3 Rules of Engagement

```yaml
rules_of_engagement:
  allowed_domains: ["ai.example.test", "*.ai.example.test"]
  excluded_domains: ["*.openai.com", "*.anthropic.com", "*.googleapis.com", "*"]  # exclusions win
  allowed_ip_ranges: ["10.20.0.0/24"]
  allowed_paths: ["/api/chat", "/api/search", "/api/v1/*"]
  excluded_paths: ["/admin/*", "/payments/*", "/api/*/delete"]
  allowed_methods: [GET, POST]
  forbidden_headers: ["X-Internal-Admin"]
  budgets:
    max_requests: 500
    max_concurrency: 3
    requests_per_second: 2.0
    max_tokens_sent: 100000
    max_tokens_received: 200000
    max_estimated_cost_usd: 5.00
    max_wall_clock_minutes: 30
  behaviour:
    safe_mode: true
    allow_state_mutation: false
    allow_multi_turn: true
    max_turns_per_conversation: 6
  blackout_windows:
    - { from: "2026-09-20T00:00:00Z", to: "2026-09-21T00:00:00Z" }
  contact:
    escalation: "secops@example.test"
```

A web UI (Master Prompt §12) manages this configuration; the underlying enforcement is identical whether the RoE was edited via browser or YAML upload.

---

## 6. Scope & authorization engine — the safety boundary

Unchanged from v2.0 §6, union'd with the Master Prompt's SSRF language (§37) where it added detail. **Build this first. Test it hardest. It gates the entire product regardless of interface.**

### 6.1 Required pipeline

Every outbound request — from the API, from a Celery worker, from the CLI, from a plugin — passes through a single choke point. There is no code path that constructs and sends a request without it.

```
resolve authorization  → expired/absent            → ABORT RUN
resolve RoE            → unparseable/ambiguous     → ABORT RUN
resolve URL            → DNS + IP after resolution → check allowlist
                       → redirect target           → re-check, do not follow off-scope
check domain           → exclusion list first, then allowlist
check path + method
check budgets          → requests / tokens / cost / wall clock / concurrency
check blackout window
check kill switch
─────────────────────────────────────────────
send                   → record Observation
                       → redact
                       → seal into evidence
                       → decrement budgets atomically
```

### 6.2 Specific requirements

- **Exclusions are evaluated before allowlists and always win.**
- **Resolve DNS and check the resulting IP**, not just the hostname, re-checked on every request (defeats DNS rebinding). Block RFC1918/loopback/link-local/metadata addresses (169.254.169.254, fd00:ec2::254) unless explicitly allowlisted.
- **Never auto-follow redirects.** A 3xx to an off-scope host is a finding (potential SSRF surface) and a hard stop.
- **Budgets are atomic**, checked pre- and post-flight. Token budgets use provider-reported usage when available, else a tokenizer estimate — documented as an estimate.
- **Kill switch:** a sentinel + SIGTERM handler (CLI/worker) and an authenticated "cancel assessment" action (API/UI) that both stop new requests within one request-interval, drain in-flight work, and write a partial-but-valid report.
- **Dry run** (`--dry-run` / a "preview" step in the assessment wizard) shows the exact request plan — method, URL, masked headers, body shape, probe IDs, projected budget consumption — and sends nothing.
- **Audit log** is append-only, one JSON object per line, hash-chained (each record includes the SHA-256 of the previous record), written before the request is sent. Records every allow *and* every deny with the rule that fired. Also mirrored into the `audit_logs` table for the UI's Audit Log screen (Master Prompt §28), with the file-backed chain as the tamper-evidence source of truth.
- **Fail closed on internal error.** If the scope engine raises, the run aborts. Never default-allow.
- **This logic must live in `core/scope/` and be identical whether invoked via FastAPI route, Celery task, or CLI command** — there is exactly one scope engine, not one per interface.

### 6.3 Mandatory tests (`tests/security/test_scope_controls.py`)

Release-blocking. Property-based where possible.

```
out-of-scope domain                     → BLOCKED
subdomain not covered by wildcard       → BLOCKED
IDN / punycode homograph of allowed dom → BLOCKED
URL with userinfo (user@evil.test)      → BLOCKED
DNS rebinding (host allowed, IP is not) → BLOCKED
redirect to off-scope host              → BLOCKED + finding
cloud metadata IP                       → BLOCKED
excluded path under allowed prefix      → BLOCKED
method not in allowed_methods           → BLOCKED
request budget exceeded                 → BLOCKED, run halts
token budget exceeded                   → BLOCKED, run halts
cost budget exceeded                    → BLOCKED, run halts
wall-clock exceeded                     → BLOCKED, run halts
authorization expired mid-run           → BLOCKED, run halts
authorization absent                    → RUN REFUSED
RoE fails schema validation             → RUN REFUSED
scope engine raises internally          → RUN REFUSED (fail closed)
kill switch during run                  → drains, partial report valid
concurrency cap                         → never exceeded under load
cross-organization target access        → BLOCKED (multi-tenant addition)
```

A CI check greps the codebase for direct `httpx` client construction outside the scope-gated transport and fails the build if any exists.

---

## 7. Determinism and measurement

v2.0 §7, unchanged and mandatory — this is one of the four stated differentiators and must be visible in the web UI, not just in raw JSON.

### 7.1 Trials and baselines

- Every AI probe runs **N trials** (default 5, configurable, budget-permitting) plus a **control** (same request, no adversarial component).
- Report **attack success rate** `ASR = successes / trials` with a **Wilson score 95% confidence interval**.
- A finding requires ASR meaningfully above the control rate. Default rule: lower bound of the ASR interval exceeds the control's upper bound — explicit, configurable, and printed in the report methodology section and shown in the finding detail UI.

### 7.2 Reproducibility

Record for every attempt: probe ID and version, exact payload, seed, temperature/top-p if controllable, model identifier as reported, timestamp, full redacted request/response pair. `kervy-ai replay <finding-id>` (and an equivalent "Retest" button, §27) re-runs the exact attempt under the same scope checks and reports whether it reproduced.

### 7.3 Judges

- Optional, off by default; deterministic detectors must carry the tool alone.
- Judge model, prompt, and version recorded in evidence.
- Ship a labelled fixture set and a `make calibrate` target reporting the judge's **precision and recall**. Publish those numbers. **An uncalibrated judge does not ship.**
- Judge output is a `Detection`, never a `Finding` directly — a human or deterministic corroborator promotes it.
- The judge must never be the target model.

### 7.4 Flakiness reporting

Findings carry `stability`: `deterministic` (ASR = 1.0), `probabilistic` (ASR + CI shown), `single-shot` (ASR unavailable, confidence capped at Medium).

---

## 8. Target adapters

v2.0 §8, unchanged.

```python
class TargetAdapter(Protocol):
    id: str
    async def send(self, turn: Turn, ctx: RunContext) -> Observation: ...
    async def capabilities(self) -> Capabilities: ...
    async def reset(self) -> None: ...
```

| Adapter | Purpose |
|---|---|
| `chat_http` | Arbitrary HTTP chat endpoint, JSON request template, JSONPath response extractor |
| `openai_compatible` | `/v1/chat/completions` and `/v1/responses` shaped APIs |
| `http_openapi` | Generic REST surface driven by an OpenAPI 3.x spec |
| `graphql` | GraphQL endpoint |
| `mcp` | MCP server over stdio and HTTP — enumerate tools/resources/prompts, inspect tool descriptions for injected instructions, detect tool-definition drift |
| `websocket` | Streaming chat |
| `cli_subprocess` | Local agent binaries (lab use only, disabled unless explicitly enabled) |

Document this layer thoroughly — it is the primary plugin extension point.

---

## 9. AI probe catalogue

v2.0 §9, unchanged; category descriptions from the Master Prompt (§17) are equivalent restatements, not additions, and are folded in as UI-facing copy only.

```python
@dataclass(frozen=True)
class ProbeMeta:
    id: str                    # "ai.injection.direct.instruction_override"
    version: str               # semver; bump on payload or logic change
    name: str
    category: ProbeCategory
    description: str
    mappings: Mappings         # owasp_llm, owasp_asi, atlas, cwe, nist_ai_rmf
    safe_mode: bool
    mutates_state: bool
    requires: Capabilities
    default_trials: int
    payload_source: str
    cost_class: Literal["low", "medium", "high"]

class Probe(Protocol):
    meta: ProbeMeta
    async def plan(self, target: Target, ctx: RunContext) -> list[Attempt]: ...
    async def run(self, attempt: Attempt, ctx: RunContext) -> Observation: ...
    def detect(self, obs: Observation, baseline: Observation) -> Detection: ...
```

- **LLM01 direct injection** — instruction override, role/persona manipulation, delimiter/formatting confusion, context-window manipulation, instruction-hierarchy conflict, encoding/obfuscation, language switching, multi-turn escalation (gated by `allow_multi_turn`). Marker-based detection only (`KERVY-CANARY-<random>`).
- **LLM01 indirect/cross-domain injection** — full path `external content → retriever → context → LLM → agent → tool → downstream effect`; carriers: HTML, Markdown, PDF, DOCX, CSV, `.eml`, JSON, image-with-text; hiding techniques: HTML comments, `display:none`, white-on-white, PDF invisible layer, unicode tags, alt text, spreadsheet formulas. Served from the local `content-server` lab component only. High-or-above severity requires reaching a privileged action or exfiltration channel.
- **LLM02 sensitive information disclosure** — `detect-secrets`, Gitleaks rulesets, Presidio, entropy analysis, org-supplied regex packs; cross-tenant leakage test with two authorized test accounts; redaction before persistence (store `sha256(secret)` + masked preview + byte offset, never the value).
- **LLM03 excessive agency / ASI01–ASI10** — enumerate tool surface (MCP adapter, app manifest, or operator declaration — never guessed); build and render a permission graph (`user → agent → tool → resource → effect`) as Mermaid; classify tools read/write, reversible/irreversible, internal/external; test tool-selection manipulation, out-of-model authorization checks, talk-past-confirmation, single-high-privilege-credential patterns. Architectural findings without live testing are valid, tagged `confidence: design_review`.
- **LLM06 unbounded consumption** — tiny self-capped budget (≤20 requests, ≤5% of run token budget); measure cost slope, not exhaustion; report extrapolated cost with the extrapolation shown.
- **LLM08 hidden context exposure** — system instructions, retrieved documents, cross-session memory, tool definitions/responses, application state; marker planting in the lab, structural/statistical similarity against real targets.
- **LLM09 vector/embedding weaknesses** — retrieval-boundary testing across tenants, retrieval poisoning via an authorized lab ingestion path only, vector-store reachability exposure check, metadata-filter bypass. Active poisoning strictly lab-only.
- **LLM10 improper output handling** — sinks: HTML/DOM, JS, SQL, shell, template engines, Markdown renderers, URL construction, file writes, JSON/YAML parsers, downstream API calls; benign structural markers per sink; never execute; report "dangerous flow reachable," exploitability unconfirmed.
- **LLM04/LLM05 supply chain & poisoning** — assessment only: inventory models/datasets/adapters/plugins/MCP servers and provenance; ML-BOM generation; unpinned/unsigned artifact detection; unsafe deserialization (pickle) flags; slopsquatting exposure check; questionnaire-driven where vendor disclosure is required.

---

## 10. API security engine

Merged v2.0 §10 and Master Prompt §18 — identical intent, Master Prompt adds synthetic-account and GraphQL emphasis, folded in.

Drive from OpenAPI/GraphQL spec where available; otherwise operator-declared endpoints. Map to API1:2023–API10:2023.

- **Authentication** — unauthenticated access to authenticated endpoints; expired/`alg:none`/unsigned JWT acceptance; weak/absent token expiry; key material in URLs/logs; missing TLS.
- **Authorization (highest-value area)** — BOLA via **two dedicated, authorized synthetic test accounts** and real object IDs, never a stranger's data; broken function-level authorization; horizontal/vertical escalation. Read-only: confirm the authorization *decision*, then stop.
- **Mass assignment (API3)** — submit `role`/`is_admin`/`tenant_id`, verify by reading back state; if acceptance would grant privilege, **abort the write and report the schema weakness** rather than completing it. Under `--safe` (default), analysis-only against the spec.
- **Resource consumption (API4)** — rate-limit presence, pagination limits, oversized-payload handling.
- **SSRF (API7)** — parameters accepting URLs: scope-controlled local `collaborator` in the lab; non-resolving canary domain against real targets; **never** point a target at a third party.
- **Misconfiguration/inventory (API8/9)** — security headers, CORS, verbose errors, exposed debug routes, spec/production drift, stale API versions.
- **Input validation** — generated from the OpenAPI schema (type confusion, missing/unexpected params, boundary values, malformed JSON, schema violations), not a static list.
- **GraphQL** — introspection exposure, query depth/complexity limits, aliasing/batching amplification, field-level authorization, error verbosity.

---

## 11. Finding model

Canonical schema is v2.0 §11, extended with the organization boundary and remediation/report linkage from the Master Prompt. This is the *stored* model — see §11.1 for the smaller wire format plugins/scanners actually emit.

```yaml
id: AEG-2026-0001
organization_id: uuid
fingerprint: sha256:...           # probe_id + normalized surface + canonicalized evidence signature — NOT response text
title: string
category: ai | api | infra | design
probe_id: ai.injection.indirect.html_comment
probe_version: 1.2.0

severity: informational | low | medium | high | critical
severity_rationale: string        # REQUIRED; generated from risk-model inputs so it always matches the score
confidence: low | medium | high | design_review
stability: deterministic | probabilistic | single_shot
attack_success_rate: { successes: 4, trials: 5, rate: 0.8, ci95: [0.38, 0.96] }
control_success_rate: { successes: 0, trials: 5, rate: 0.0, ci95: [0.0, 0.43] }

affected: { target_id: uuid, surface: "POST /api/chat", component: "retrieval pipeline" }

impact: string
likelihood: string
risk_score: { model: kervy-v1, value: 7.4, inputs: {...} }
cvss_v4: { vector: "CVSS:4.0/...", score: 8.1 }      # ONLY when the finding genuinely fits CVSS
aivss: { version: "0.8-draft", score: 6.9, note: "draft methodology" }   # optional

mappings:
  owasp_llm_2026: [LLM01]
  owasp_asi_2026: [ASI02]
  owasp_api_2023: []
  mitre_atlas: [AML.T####]         # only if verified against the pinned release
  cwe: [CWE-####]
  nist_ai_rmf: [MEASURE 2.7]
  nist_ssdf: [PW.4, PS.1]          # Addendum v2.1 §5 — SAST/SCA/Secrets; verify against nist.gov first
  mapping_versions: { owasp_llm_2026: "2026", mitre_atlas: "v2026.09" }

evidence_ref: sha256:...
reproduction: [ordered steps]
remediation: { summary: str, steps: [...], references: [...] }
remediation_task_id: uuid | null   # link into RemediationTask once triaged

lifecycle:
  status: new | confirmed | false_positive | accepted_risk | in_remediation | remediated | retest_required | closed
  first_seen: ts
  last_seen: ts
  owner: str
  resolution: str
  retest_result: str

source: native | "<tool>@<version>"   # native probe or an imported third-party tool result
scanner: { name: kervy-ai, version: 0.1.0, run_id: uuid }
```

**Fingerprinting** makes the lifecycle work across runs: same issue, two runs, varying response text → one Finding with two `last_seen` values, not two Findings. This is a mandatory automated test.

### 11.1 Wire format (`ScanResult`) — what a probe/plugin/scanner actually returns

The smaller shape from the Master Prompt (§55) is the contract every native probe, plugin, and third-party tool adapter emits. The Findings service (`core/findings/`) is the only thing that promotes a `ScanResult` into a full `Finding` — adding fingerprint, ASR/CI aggregation across trials, risk score, mapping versions, and lifecycle state. Plugin authors only ever see this simple shape:

```json
{
  "id": "KERVY-AI-001",
  "title": "Potential Prompt Injection",
  "category": "AI_SECURITY",
  "severity": "HIGH",
  "confidence": "HIGH",
  "asset_id": "...",
  "endpoint": "/api/chat",
  "description": "...",
  "evidence": "...",
  "impact": "...",
  "remediation": "...",
  "frameworks": []
}
```

---

## 12. Risk scoring

v2.0 §12, unchanged.

```
risk = impact × likelihood × confidence_weight × exposure_modifier
```

- Each input is an ordinal with a published numeric table in `docs/risk-model.md` and the report appendix.
- `likelihood` incorporates the measured ASR lower bound for probabilistic findings.
- `confidence_weight` down-weights judge-only detections.
- `exposure_modifier` accounts for authentication requirement, internet reachability, environment.
- Severity is derived from the score by a published banding; `severity_rationale` is generated from the inputs, always matching the number.

**Three scoring systems, never blended:**
1. **Kervy risk score** — always present, fully documented, our model.
2. **CVSS 4.0** — only for findings that genuinely fit CVSS. Never manufacture a vector for "the model followed an injected instruction."
3. **AIVSS v0.8** — optional, off by default, visibly labelled "draft methodology, v0.8, subject to change before v1.0."

---

## 13. Evidence

v2.0 §13, unchanged, plus Master Prompt's UI actions.

- Evidence bundle = request + response + headers + timing + probe metadata + adapter config + model identifier + detector verdict + judge transcript (if used) + canary values.
- Redaction runs **before write**, using the LLM02 detector stack plus RoE-supplied custom patterns. Authorization headers and cookies always masked.
- Bundles are content-addressed (SHA-256), referenced by hash from findings. A per-run manifest is hash-chained, so an altered bundle is detectable.
- Storage: local filesystem (default), optional encryption-at-rest using a run key (age/libsodium) — document the key-management model honestly.
- Retention configurable per run; `kervy-ai evidence purge --run <id>` performs a genuine delete, recorded in the audit log.
- `kervy-ai evidence verify --run <id>` validates the hash chain.
- UI (finding detail page, §21): Copy Evidence, Download Evidence — both sanitized, both audit-logged, both authorization-checked (no public report/evidence URLs by default, per Master Prompt §49).

---

## 14. Reporting

Merged v2.0 §14 with the Master Prompt's audience templates (§24–25) — same underlying data, different renderings, never different facts.

Formats: **JSON** (canonical, JSON-Schema-validated), **SARIF 2.1.0**, **HTML**, **Markdown**, **CSV**, **PDF** (via WeasyPrint from the HTML — no headless-browser dependency).

Required report sections (all templates draw from this set; templates differ in which sections are emphasized/omitted, not in the facts reported):

```
Executive summary                  (non-technical, ≤1 page, no probe IDs)
Authorization & scope              (who authorized, when, RoE digest, what was excluded)
Methodology                        (trials, thresholds, judge calibration numbers, limitations)
Attack surface                     (adapters, endpoints, tools, retrieval, permission graph)
Risk summary                       (counts + risk model explanation)
Findings by severity               (rationale, evidence ref, reproduction, remediation)
AI findings / API findings         (grouped views)
Framework coverage                 (tested AND not tested, with reasons)
Remediation plan                   (prioritized, effort-estimate bands)
Retest results                     (delta vs previous run, by fingerprint)
Appendix                           (risk model tables, mapping versions, tool versions, raw config)
```

**Templates** (Master Prompt §25), each a projection of the above:
- **Technical** — full detail, all evidence references.
- **Executive** — summary + risk summary + remediation plan only, no probe IDs.
- **Developer** — findings + reproduction + remediation, filtered to a given asset/component.
- **Compliance** — framework coverage + mappings, organized by framework rather than by severity.

**Coverage honesty** is mandatory: the report states which framework categories were not tested and why. Reports may be generated but are never publicly reachable by default; every report fetch is authorization-checked and audit-logged.

---

## 15. Third-party tool integration

Identical in both sources; merged as-is (v2.0 §15 / Master Prompt §56).

Candidates: ZAP, Nuclei, Trivy, Semgrep, Bandit, detect-secrets, Gitleaks, Presidio, garak, PyRIT, promptfoo, DeepTeam, cdxgen/Syft.

- Verify each tool's licence before integrating; record in `docs/third-party.md`. Prefer subprocess/REST invocation over vendoring — do not assume a licence from memory.
- Each adapter is optional; a missing tool degrades gracefully, never crashes.
- Imported findings pass through the **same** scope engine, redaction, and normalization as native ones (emit the §11.1 `ScanResult` shape), tagged `source: <tool>@<version>`.
- If an external tool would issue a request the RoE forbids, the adapter prevents it by passing explicit scope configuration, or refuses to run the tool at all if it cannot be constrained — document any such tool and mark its adapter experimental.
- garak and PyRIT are Python libraries and integrate in-process; promptfoo is Node and runs subprocess-only.

Added by the AppSec Addendum v2.1 §8 and the Implementation Specification §5. Every
rule above applies unchanged — verify the licence first, prefer subprocess/REST over
vendoring, degrade gracefully when the tool is absent, and refuse or mark experimental
any tool that cannot be constrained to the RoE:

| Tool | Pillar | Integration mode |
|---|---|---|
| Semgrep | SAST | Subprocess; SARIF parsed and normalized |
| Bandit | SAST (Python) | Subprocess |
| CodeQL | SAST (optional) | Subprocess — **verify licence before enabling; mark experimental** |
| OWASP ZAP | DAST | REST API in daemon mode, scope configured before launch |
| Nuclei | DAST | Subprocess; template allowlist derived from the RoE |
| pip-audit | SCA | Subprocess |
| OSV-Scanner | SCA | Subprocess |
| Gitleaks | Secrets | Subprocess |
| detect-secrets | Secrets | In-process library call |
| Checkov / tfsec | IaC | Subprocess |

**The static no-ungated-HTTP check of §6.3 extends to these tools.** A subprocess that
makes its own network calls is an outbound path like any other, so each adapter must
launch its tool with an explicit, scope-derived allow/deny configuration, or refuse to
launch it at all. A tool that cannot be constrained is not integrated.

---

## 16. Plugin architecture

Merged v2.0 §16 and Master Prompt §54 — same design, Master Prompt's example is the canonical shape for the simplified test-plugin interface, v2.0's rigor around entry points and sandboxing is retained.

- Discovery via Python entry points (`kervy.probes`, `kervy.detectors`, `kervy.adapters`, `kervy.reporters`).
- Plugins validated against the `ProbeMeta` schema at load; invalid metadata fails loudly.
- **Third-party plugins are untrusted code** — no false sandbox claimed. Provide: signed/allowlist mode (`plugins.allowlist` of package name + hash), `--no-plugins`, and a startup banner listing loaded third-party plugins.
- Plugins cannot bypass the scope engine: they receive a `RunContext` whose transport is already gated, with no route to a raw HTTP client. Tested explicitly.
- `docs/plugin-development.md` with a complete, working example probe (~80 lines) and its tests, using the simplified interface for the common case:

```python
class SecurityTest:
    id: str
    name: str
    category: str

    async def run(self, target, context):
        ...   # returns a ScanResult (§11.1); the findings service promotes it
```

---

## 17. Multi-tenancy, authentication, and RBAC

New section — this is the Master Prompt's biggest addition over v2.0, which assumed a single local operator. It now underlies everything above.

### 17.1 Authentication

Real authentication: registration, login, logout, Argon2id password hashing (never plaintext), password validation, session/token management, protected routes, account profile, password change, account deletion, authentication audit events. CSRF protection where cookie-based sessions are used, secure cookies, `SameSite` configuration, secure headers, login rate limiting, failure logging.

### 17.2 RBAC

```
Owner    — everything, including billing/deletion of the organization
Admin    — manage users, assets, assessments, configuration; grant authorization records
Security Engineer — create assessments, run scans, review/retest findings, generate reports
Analyst  — view assessments, investigate findings, add notes
Viewer   — read-only
```

Only `Admin`/`Owner` may grant an `Authorization` record (this is a deliberate, security-relevant restriction, not a convenience default). **RBAC is enforced server-side on every route; the frontend's role-based UI hiding is cosmetic only** — this must be covered by tests that call the API directly as a lower-privileged role and expect a 403.

### 17.3 Organizations

`Organization`, `User`, `Membership`, `Role` models. A user may belong to multiple organizations. Every `Target`, `AssessmentRun`, `Finding`, `Report`, `AuditEvent` belongs to exactly one organization. Cross-organization data access is blocked server-side and covered by an automated tenant-isolation test suite (§24).

### 17.4 API keys

Organizations create scoped API keys for CI/CD (create, revoke, rotate, last-used, expiration, scopes). The key is shown once at creation and never again; only a secure hash is stored.

---

## 18. Web application (frontend)

New section from the Master Prompt (§10, 16, 20, 42–44) — the primary user surface.

### 18.1 Navigation

`Dashboard · Assets · Assessments · Findings · Remediation · Reports · Frameworks · Audit Logs · Team · Settings`

### 18.2 Dashboard

Real data only, never hardcoded: total assets, active/completed assessments, open/critical/high/medium/low findings, AI vs API finding counts, remediation rate, recent assessments/findings, risk trends, framework coverage. Charts: findings by severity, findings over time, findings by category/framework, remediation status.

### 18.3 Asset management

Add/edit/delete/archive/view/test. Fields per §5.1 plus `owner`, `tags`, `status`, timestamps. Application types: LLM Application, RAG Application, AI Agent, AI API, Chatbot, AI SaaS, ML API, Other.

### 18.4 Scope UI

A form over the RoE in §5.3 — same enforcement as YAML/CLI, edited through the browser.

### 18.5 OpenAPI import

Upload `openapi.yaml|.yml|.json` / `swagger.json`; parse endpoints, methods, parameters, schemas, auth/security requirements; display the discovered surface; allow enabling/disabling individual endpoints. Validate file type/size, sanitize filenames, store outside executable paths, never execute an uploaded file, prevent path traversal.

### 18.6 Assessment wizard

`Select Asset → Verify Authorization → Configure Scope → Select Test Categories → Configure Test Limits → Review Rules of Engagement → Start`, gated by the explicit "I confirm that I am authorized to test this target" checkbox (§5.2), which is stored with who/when.

### 18.7 Real-time scan progress

Server-Sent Events or WebSockets, driven by real Celery task state — never faked. Shows endpoints/AI-tests/API-tests completed, requests used against budget, running severity counts.

### 18.8 Findings, remediation, reports UI

Table with filters (severity/status/framework/probe/date/surface), search, pagination; finding detail page (Overview, Description, Impact, Evidence, Reproduction, Affected Assets, Framework Mapping, Risk Analysis, Remediation, Comments, Activity, Retest History) with Copy/Download Evidence, Mark False Positive, Assign, Change Status, Create Retest actions — every one functional, none a dead button. Remediation task board per §5. Report generation/download per §14.

### 18.9 Design & accessibility

Dark/light mode, clear severity indicators (never color-only), high information density, responsive desktop/tablet/mobile, keyboard navigation, semantic HTML/ARIA, visible focus states, WCAG 2.2 AA target. Professional SOC aesthetic, minimal animation. Every visible action works or is explicitly disabled with a reason — no silently-dead buttons, no blank screens (loading/empty/error/unauthorized/forbidden/not-found/validation/network/scan-failure/scope-violation/rate-limit/server-error states all handled).

---

## 19. Demo target lab

Merged v2.0 §17 and Master Prompt §33 — identical intent.

`demo-target/` (repo-root name; equivalent to v2.0's `labs/`) containing:

1. **`vulnerable-ai-app`** — small FastAPI app with a stubbed/tiny local model. Seeded flaws: weak prompt isolation, recoverable system prompt, unauthorized "tools" endpoint, over-broad agent tool surface, raw-HTML-rendered model output, cross-tenant RAG index, no rate limiting, mass-assignment on `/api/users`, BOLA on `/api/orders/{id}`, verbose errors.
2. **`content-server`** — serves injection carriers for indirect-injection testing.
3. **`collaborator`** — local out-of-band listener for SSRF/exfiltration detection.
4. **Synthetic data generator** — deterministic, obviously fake (`user@example.invalid`, `AKIAEXAMPLEEXAMPLE1`).

Isolation per §2.4. `docker compose --profile demo up` launches everything on an internal, egress-free network. The lab doubles as the integration-test fixture: CI runs a real end-to-end assessment against it and asserts on the resulting findings (`lab-e2e.yml`).

---

## 20. CLI

Merged v2.0 §18 and Master Prompt §31 — union of both command sets under the single binary name `kervy-ai`, all calling the same REST API a browser session uses.

```bash
kervy-ai login
kervy-ai init
kervy-ai target add|list|show|rm --config target.yaml
kervy-ai auth grant --target X --file authorization.yaml [--sign]
kervy-ai auth verify --target X
kervy-ai scope validate X
kervy-ai scope explain X --url https://...
kervy-ai discover X
kervy-ai scan X [--safe] [--profile ai|api|full] [--dry-run] [--trials N]
kervy-ai test X --probe ai.injection.direct.* --trials 10
kervy-ai replay <finding-id>
kervy-ai findings list [--severity high] [--status new] [--framework LLM01]
kervy-ai findings set-status <id> --status confirmed --owner alice
kervy-ai retest X --since <run-id>
kervy-ai report X --format html,sarif,json --output ./reports/
kervy-ai evidence verify|purge --run <id>
kervy-ai frameworks list|show|diff|update
kervy-ai probes list [--category ai] [--safe-only]
kervy-ai gate --run <id> --config security-gate.yaml
kervy-ai kill
kervy-ai ci --target staging-ai --fail-on critical,high
```

`--safe` is the default; `--unsafe` requires interactive confirmation and is logged. Every command exits non-zero on refusal, with documented, distinct exit codes so CI can tell "found issues" apart from "refused to run":

```
0 = pass
1 = security gate failed
2 = configuration error
3 = authentication error
4 = scope violation
```

---

## 21. REST API

Merged v2.0 §19 and Master Prompt §29–30.

FastAPI, OpenAPI-documented, versioned `/api/v1/` (`/auth`, `/users`, `/organizations`, `/assets`, `/scopes`, `/assessments`, `/scans`, `/findings`, `/reports`, `/frameworks`, `/remediation`, `/audit`, `/health`), docs at `/api/docs` and `/api/redoc`.

Platform security: API-key or OIDC authentication, RBAC (§17.2), per-route rate limiting, strict security headers, CSRF protection for cookie-authenticated browser sessions, request-size limits, structured audit logging of every state change, no secrets in logs or error responses.

`docs/threat-model.md` states plainly: this API launches network requests on behalf of its caller — it is SSRF-shaped by design, and the scope engine is the only thing standing between it and abuse. Deploy on a restricted network segment.

---

## 22. Notifications and webhooks

From the Master Prompt §52–53; not present in v2.0.

Events: assessment completed/failed, critical/high finding discovered, retest completed. In-app notifications initially; email- and webhook-ready architecture without requiring an external email provider for local dev. Webhooks (`assessment.completed`, `finding.created`, `finding.critical`, `retest.completed`) signed with a per-organization secret, with retry handling.

---

## 23. CI/CD, supply chain, and the security gate

Merged v2.0 §21 and Master Prompt §32/61–62.

```
ci.yml               ruff · mypy --strict · pytest · coverage gate · frontend lint/typecheck/test
security.yml         Semgrep · Bandit · Gitleaks · detect-secrets
codeql.yml           CodeQL
deps.yml             pip-audit · npm audit · Dependabot config · OSV scan
container.yml        Trivy (image + config + secrets), fail on HIGH+
sbom.yml             CycloneDX 1.7 SBOM + ML-BOM for lab models
lab-e2e.yml          launch demo lab · run a real assessment · assert findings · upload SARIF
framework-drift.yml  weekly upstream framework version check, opens an issue on drift
release.yml          semver tag · signed artifacts (Sigstore/cosign) · provenance attestation
```

Least-privilege `permissions:` blocks, pinned action SHAs. Containers run as non-root, minimal base images, pinned dependencies, health checks, dropped capabilities, read-only filesystem where practical, resource limits, never contain secrets.

**Security gate** (`kervy-ai gate` / `kervy-ai ci`):

```yaml
security_gate:
  fail_on: [critical, high]
  max_high: 0
  max_medium: 5
  min_confidence: medium
  require_stability: [deterministic, probabilistic]   # never gate on single-shot results
  ignore:
    - fingerprint: sha256:...
      reason: "accepted risk, TICKET-987"
      expires: 2026-12-31
```

Gating on unstable, low-confidence AI findings makes pipelines flaky and gets the tool disabled by the first adopting team — `docs/cicd.md` explains this explicitly.

---

## 24. Testing

Merged v2.0 §22 and Master Prompt §45–46.

```
backend/tests/unit/          every module; ≥85% coverage on core/, ≥95% on core/scope/
backend/tests/security/      §6.3 scope tests — release-blocking, plus tenant-isolation tests
backend/tests/integration/   against the demo lab, real HTTP
backend/tests/property/      hypothesis: URL/scope matching, budget arithmetic, fingerprint stability
backend/tests/golden/        report snapshots (JSON, SARIF, Markdown)
backend/tests/fixtures/      labelled detection corpus for judge calibration
frontend/tests/              component, page, form, auth-flow, assessment-flow tests
e2e/                          register → login → create org → add asset → configure scope →
                              import OpenAPI → create assessment → run safe scan → view findings →
                              inspect evidence → create remediation → retest → generate report
```

Release-blocking security assertions:

```
out-of-scope target      → BLOCKED
out-of-scope endpoint    → BLOCKED
unauthorized user        → BLOCKED
wrong organization       → BLOCKED
expired assessment       → BLOCKED
request limit exceeded   → BLOCKED
token budget exceeded    → BLOCKED
```

Plus: redaction-never-leaks property test, fingerprint-stability test, determinism harness (stubbed adapter with configurable success probability, verifying ASR/CI math and threshold boundaries), self-assessment (platform's own API scanned against itself in CI, lab-scoped), import-linter layering contract, no-ungated-HTTP static check.

Coverage targets: backend ≥80% overall / ≥95% on `core/scope/`; frontend critical paths covered; security controls comprehensive. Never inflate coverage artificially.

---

## 25. Documentation

Merged v2.0 §23 and Master Prompt §58–59, deduplicated.

```
README.md
SECURITY.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
CHANGELOG.md
docs/architecture.md
docs/installation.md
docs/configuration.md
docs/authentication.md
docs/rbac.md
docs/authorization-and-scope.md      (safety model in full, with §6.3 as evidence)
docs/scanning.md
docs/ai-security-testing.md
docs/api-security-testing.md
docs/risk-model.md                   (every number in the scoring tables)
docs/detection-methodology.md        (trials, baselines, ASR, judge calibration results)
docs/reporting.md
docs/frameworks.md
docs/plugin-development.md
docs/deployment.md
docs/troubleshooting.md
docs/threat-model.md
docs/security-model.md
docs/ci-cd.md
docs/acceptable-use.md
docs/limitations.md                  (what the tool cannot detect, where false positives cluster, why)
docs/third-party.md                  (every integrated tool with licence and version)
docs/comparison.md                   (honest positioning vs garak/PyRIT/promptfoo/DeepTeam, incl. where they're better)
docs/decisions/                      (ADRs: storage/queue, naming, concurrency, scoring, judge usage)
docs/security-review.md              (final self-review, §26 Phase 11)
```

README: overview, honest "why this exists," architecture diagram, framework versions with dates, install, 5-minute quickstart against the demo lab, CLI examples, sample report screenshot, CI integration, authorization model, limitations, roadmap, contributing, licence.

**Licence:** Apache-2.0 (patent grant matters for security tooling — note the choice in an ADR).

---

## 26. Phased delivery with acceptance criteria

The two source phase lists are nearly isomorphic; merged into one sequence carrying v2.0's acceptance-criteria discipline and the Master Prompt's full web-app scope per phase. **Each phase ends with a green suite, a manual verification pass, and a written status report. Do not proceed past a red phase.**

| Phase | Scope | Acceptance criteria |
|---|---|---|
| **1. Foundation** | Repo layout; `docker-compose.yml` (frontend/backend/worker/postgres/redis); FastAPI + Next.js skeletons; Postgres + Alembic; Redis; Celery wired but idle; config loader; structlog; CI skeleton; auth (register/login/logout, Argon2id); Organizations/Membership/Role models; RBAC scaffolding | `docker compose up --build` serves the frontend at :3000 and a user can register, log in, and create an organization; migrations up/down clean; CI green |
| **2. Safety boundary** | `Target`, `Authorization`, `RoE` models; scope engine; gated transport; audit log (file hash-chain + DB mirror); kill switch; dry-run; asset CRUD + scope UI; OpenAPI upload with validation | **Every test in §6.3 passes.** `kervy-ai scope explain` correct on 20 hand-written cases. No ungated HTTP client anywhere in the codebase. Cross-organization access blocked and tested |
| **3. Adapters & discovery** | Adapter protocol; `chat_http`, `openai_compatible`, `http_openapi`; OpenAPI parsing; attack-surface discovery UI | Discovers the demo lab's surface correctly; handles malformed specs without crashing |
| **4. Assessment engine** | Assessment wizard; Celery task lifecycle (Queued/Running/Completed/Failed/Cancelled/Expired); SSE/WebSocket progress; cancellation; timeouts; budget enforcement in workers | A safe scan against the demo lab runs end-to-end with real progress in the browser and halts cleanly on cancel/timeout/budget exhaustion |
| **5. API security engine** | Auth, BOLA, function-level authz, mass assignment (analysis mode), input validation, misconfig, GraphQL testing | Finds every seeded API flaw in the demo lab; zero findings against a hardened control app |
| **6. AI security engine** | Direct/indirect injection, hidden context, disclosure, output handling, agency, consumption; trials/baseline/ASR machinery; judge (optional, calibrated or disabled) | Finds every seeded AI flaw in the demo lab; ASR machinery verified by the determinism harness; judge calibration numbers published or judge disabled |
| **7. Findings & risk** | Normalization (`ScanResult` → `Finding`), fingerprinting, lifecycle, risk model, framework resolution, findings UI | Fingerprint-stability test passes; every finding has a generated `severity_rationale` matching its score |
| **8. Evidence & reporting** | Redaction, sealing, hash chain, JSON/SARIF/HTML/MD/CSV/PDF, four report templates | Redaction property test passes; SARIF validates against 2.1.0 schema; golden snapshots stable; reports downloadable and access-controlled from the UI |
| **9. Remediation & retest** | Remediation task board; retest workflow; before/after evidence comparison | A finding can be assigned, moved through remediation states, retested, and shown as reproduced/not-reproduced with evidence |
| **10. CLI, API keys & CI/CD gate** | `kervy-ai` CLI (full command set, §20); API keys; `kervy-ai ci`/`gate` with documented exit codes; GitHub Actions (§23) | CLI exercises the same API/scope engine as the UI (no parallel weaker path); a seeded critical finding fails the gate with the documented exit code |
| **11. Plugins & third-party adapters** | Entry points, allowlist, 2–3 tool adapters (e.g. Semgrep, Gitleaks, detect-secrets) | Example plugin from the docs loads and runs; a test proves a plugin cannot bypass the scope engine |
| **12. Demo lab & hardening** | Full `demo-target/` isolation, SBOM/ML-BOM, Trivy/Semgrep/Gitleaks/CodeQL/pip-audit clean, Sigstore signing, tenant-isolation and authz penetration pass against the platform itself | `lab-e2e.yml` green; SBOM attaches to release; all supply-chain CI workflows green; `docs/security-review.md` complete |
| **13. Documentation & release** | All of §25; v0.1.0 tag | A fresh clone, following the quickstart verbatim, reaches a scanned demo lab and a downloaded report in under 10 minutes, without editing source code |
| **14. AppSec engines (SAST/SCA/Secrets/IaC)** | `code_scope` model; Semgrep + Bandit (SAST), pip-audit + OSV (SCA), Gitleaks/detect-secrets over repos and images (Secrets), Checkov/tfsec (IaC); `nist_ssdf` mapping key | Finds every seeded flaw in an extended lab fixture (a small vulnerable repo alongside the existing app fixtures); zero findings against a hardened control repo; every finding carries a real upstream rule ID, CVE or GHSA — zero invented identifiers; `code_scope` absent or ambiguous → refuses to run |
| **15. DAST engine** | `kind: web_app`; scope-gated crawler (each discovered URL re-checked *before* it is queued); ZAP baseline/active and Nuclei adapters under `--safe` | Crawls and tests a lab web app without ever fetching an out-of-scope URL discovered mid-crawl; destructive templates excluded unless `allow_state_mutation` is explicitly set |
| **16. AI intelligence layer** | `AIService` provider abstraction (OpenAI-compatible + local endpoints), deterministic fake provider for CI, analysis (explanation, correlation, prioritisation) and drafting, autonomy ladder `OFF/ASSIST/RECOMMEND/APPROVAL_REQUIRED/EXECUTE` | Every test in the assistant matrix passes; with no provider configured the entire existing suite still passes unchanged; import-linter confirms nothing in `core` outside `assistant/` imports it; no path exists by which the assistant grants authorization, changes a finding's real fields, or executes a scan |
| **17. Workflows, dashboard & CI gate** | Trigger→Plan→Actions→Evidence→Result workflow persisted in the existing database; Jinja2 + HTMX dashboard replacing the Next.js scaffold; GitHub Actions gate | A repository-change workflow runs the AppSec engines, normalises, correlates and gates deterministically; an AI recommendation cannot alter a gate decision |
| **18. RASP extension points & hardening** | `runtime_protection` interface only, no engine; the §12 hardening pass | A RASP-effectiveness engine can be added without touching the orchestrator or the scope engine; no RASP agent ships, and a static check proves no unsafe-mode path exists for that interface |

If full delivery exceeds the available budget, **ship Phases 1–8 plus 12–13 as v0.1.0** (a rigorous safety boundary, a working multi-tenant web app, working AI/API engines, and honest reports), deferring remediation/retest polish, the full CLI/CI gate, and the plugin system to v0.2.0 — recorded deliberately in `docs/roadmap.md`, never left as broken stubs.

---

## 27. Definition of done

```
[ ] Fresh clone → .env.example → docker compose up --build → browser → register/login →
    create organization → register demo asset → configure scope → import OpenAPI →
    create assessment → run safe scan → watch real progress → real findings →
    inspect evidence → create remediation → retest → generate report → download report,
    all without modifying source code, in under 10 minutes
[ ] Every §6.3 scope test passes; no ungated HTTP path exists anywhere (CLI, API, worker, plugin)
[ ] Authorization absent/expired → run refused, non-zero exit / blocked API response, clear message
[ ] Cross-organization access blocked and covered by automated tests
[ ] Every framework mapping traceable to a pinned upstream version with a retrieval date
[ ] Zero TODO(verify) markers remaining, or all listed in docs/unverified-mappings.md
[ ] Every finding: severity rationale, mapping versions, evidence hash, reproduction steps
[ ] Probabilistic findings carry ASR + CI; single-shot findings capped at Medium confidence
[ ] Judge calibration precision/recall published, or judge disabled
[ ] Redaction property test passes; no plaintext secret on disk anywhere
[ ] Evidence hash chain verifies; purge genuinely deletes
[ ] SARIF validates; JSON validates against the published schema
[ ] Report states untested framework categories explicitly; no public report URLs by default
[ ] Demo lab runs with no network egress and refuses to start with a real provider API key present
[ ] No hardcoded dashboard values — every number is a real query
[ ] Every visible UI action works or is explicitly disabled with a reason; no dead buttons, no blank error screens
[ ] ruff/mypy --strict/ESLint/TypeScript strict all clean; coverage gates met
[ ] All CI workflows green: Trivy, Semgrep, Gitleaks, CodeQL, pip-audit, npm audit
[ ] SBOM (CycloneDX 1.7) generates and attaches to the release
[ ] Release tagged, artifacts signed

--- added by the AppSec Addendum and the Implementation Specification ---

[ ] Every SAST/DAST/SCA/Secrets/IaC finding traceable to a real upstream rule ID,
    CVE/GHSA or CWE — zero invented identifiers
[ ] code_scope absent or ambiguous → SAST/SCA/Secrets-in-source refuse to run (fail closed)
[ ] AI layer fully absent/unconfigured → 100% of the existing test suite still passes
[ ] Every AI-drafted artifact is a draft field until a human explicitly accepts it
[ ] The AI layer cannot grant authorization, modify scope, change a finding's real
    fields, or auto-execute a scan — each covered by a release-blocking test
[ ] A deterministic fake AI provider exists; no test run consumes paid API tokens
[ ] nist_ssdf mappings verified against a pinned source, same discipline as §3.4
[ ] Report's framework-coverage section names SAST/DAST/SCA/Secrets/IaC/RASP
    explicitly whenever any of them were not run
[ ] Software SBOM and ML-BOM ship as separate labelled components of one release
    artifact, never merged into one undifferentiated bill of materials
[ ] No RASP agent ships; the platform tests runtime protections, it does not become one
[ ] README limitations section is real and specific; docs/comparison.md acknowledges where existing tools are better
```

---

## 28. Do not

Union of both sources' guardrails, deduplicated.

- Do not write a framework mapping you have not verified against the pinned source.
- Do not use 2023 or 2025 OWASP LLM numbering.
- Do not construct an HTTP request outside the scope-gated transport, in the API, a worker, the CLI, or a plugin.
- Do not add a flag, env var, or config key that disables scope enforcement.
- Do not trust the frontend to enforce authorization, scope, or RBAC — every check is repeated server-side.
- Do not ship weaponized payloads, harmful-content jailbreaks, or exploit code.
- Do not execute model output, mutate target state in safe mode, or complete a privilege-granting write.
- Do not persist an unredacted secret, even temporarily; never log a secret or API key.
- Do not report a single successful stochastic attempt as a confirmed finding.
- Do not blend CVSS, AIVSS, and the internal risk score into one number.
- Do not put business logic in API routes or frontend components — it lives in `core/` services.
- Do not claim coverage you have not measured.
- Do not build a thin wrapper around garak or promptfoo and call it a platform.
- Do not hardcode dashboard metrics or fake scan results outside the labelled demo environment.
- Do not leave a visible button disconnected from real functionality.
- Do not allow real user data or arbitrary real accounts into authorization/BOLA testing — synthetic test accounts only.

Added by the AppSec Addendum v2.1 §11 and the Implementation Specification §10/§23:

- Do not ship a RASP agent that runs inside a customer's production process. This
  platform tests runtime protections; it does not become one.
- Do not let the AI layer execute a scan, grant authorization, or modify a finding's
  real (non-draft) fields under any configuration or autonomy mode.
- Do not add an "assistant mode", or any other flag, that routes around the
  scope-gated transport. This is the §28 scope-bypass rule above, restated because a
  new subsystem is the most likely place for it to be reintroduced by accident.
- Do not treat SARIF or advisory data from a third-party tool as verified without
  checking it carries a real rule ID, CVE or GHSA — normalization is not a licence to
  launder an invented identifier through the pipeline.
- Do not fold the software SBOM and the ML-BOM into one undifferentiated bill of
  materials; keep them as clearly labelled components of one release artifact.
- Do not let a RASP-effectiveness finding read as a vulnerability in a third-party
  WAF/RASP vendor's product; it is a defence-in-depth gap for the assessed target.
- Do not let AI-generated text replace, alter or stand in for evidence. Evidence is
  what a tool observed; AI output is analysis of it, and the two are never merged.
- Do not let an AI recommendation override, soften or silently alter a deterministic
  security gate decision.
- Do not expose arbitrary database access or shell execution to a model; the AI layer
  reaches data only through explicit, reviewed application functions.
- Do not consume paid AI provider tokens in the normal test run — CI uses the
  deterministic fake provider.
- Do not introduce microservices, Kubernetes, Kafka, Elasticsearch, a separate vector
  database, an event bus, or a multi-agent framework without a demonstrated
  requirement in this codebase (Implementation Specification §3).

---

## 29. Decisions requiring follow-up (not blocking, but tracked)

1. **Project/repo naming** — "Kervy Security" / `kervy-security` adopted per the Master Prompt, but the PyPI/npm/GitHub/trademark check v2.0 called for is still owed before a public release. Track in `docs/decisions/0003-naming.md`.
2. **Task queue: Celery vs `arq`** — defaulting to Celery per the Master Prompt's explicit mandate; `arq` remains a lighter-weight fallback if Celery's operational overhead proves disproportionate during Phase 1. Track in `docs/decisions/0002-task-queue.md`.
3. **Hosted LLM availability in the build/CI environment** — unknown until Phase 6 (AI security engine); if no hosted LLM is reachable in CI, the AI engine's live-target tests run only against the local demo lab's stub model, and this limitation is stated in `docs/limitations.md` rather than assumed away.
