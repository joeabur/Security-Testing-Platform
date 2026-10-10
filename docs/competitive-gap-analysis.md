# Competitive gap analysis

This document is the output of a direct repository audit (not a plan, not
aspirational), conducted against the brief: bring this platform closer to
the capabilities of garak, PyRIT, promptfoo, DeepTeam, ZAP, Nuclei, Semgrep,
Snyk and Aikido, without weakening this platform's own differentiators
(authorization as a first-class object, strict scope enforcement, a single
outbound control point, measured AI findings with confidence intervals,
tamper-evident evidence, honest coverage reporting, multi-tenancy/RBAC,
lifecycle management, audit-ready reporting).

Every row below is backed by a file:line citation found in the codebase at
audit time, not by what the docs claim. Several existing docs
(`docs/limitations.md`, `docs/comparison.md`) were found to be **stale** in
places — written before later phases shipped dashboard write-actions — and
this document corrects those specific claims where the code has since moved
past them.

## How to read the Priority column

- **P0** — a real security boundary gap, or the single most-requested gap in
  the brief. Fix before anything else.
- **P1** — a real product/capability gap with no workaround today.
- **P2** — a real gap, but there is a working CLI/API path today; only the
  UI/convenience surface is missing.
- **Already solid** — audited and found to already meet or exceed the bar;
  listed so it isn't "fixed" a second time by mistake.

---

## 1. DAST / egress security architecture

| Capability | Current state | Gap | Priority | Implementation |
|---|---|---|---|---|
| Scope engine core (DNS rebinding, private/loopback/link-local/CIDR blocking, metadata-endpoint blocking, redirect re-validation, IDN homograph defense, budgets, kill switch) | **Already solid.** `backend/app/core/scope/` — `transport.py` is the sole `httpx.AsyncClient` construction site, enforced by a static test (`tests/security/test_scope_controls.py:541-562`) that greps all of `app/` for stray client construction. DNS is re-resolved per check, never cached (`dns.py:13-31`, `engine.py:154-182`). Metadata endpoints (`169.254.169.254`, `fd00:ec2::254`) are blocked **unconditionally**, not overridable by any allowlist (`hostmatch.py:33-38,85-87`). Redirects are not followed by the client; a 3xx `Location` is re-validated through the same scope check (`transport.py:100`, `engine.py:244-252`). | None found. | — | No action. |
| **Nuclei / ZAP egress containment** | **Gap, confirmed by code.** Both tools are launched as OS subprocesses (`backend/app/core/appsec/tooling.py:89-144`, `asyncio.create_subprocess_exec`). Once the binary starts, it performs its own DNS resolution and opens its own sockets — entirely outside `GatedTransport`'s visibility. Nuclei (`nuclei.py:70-99`) and ZAP (`zap.py:73-89`) module docstrings state this plainly: "not routed through `GatedTransport`." ZAP additionally spiders autonomously from a single seed URL — nothing re-validates pages it discovers mid-crawl. No DNS pinning, proxy injection, network namespace, or firewall rule constrains either tool today (confirmed absent by direct inspection of `tooling.py`). | A DNS-rebinding host that was clean when the crawler checked it minutes earlier can resolve to a private IP / the metadata endpoint by the time Nuclei or ZAP actually connects, and both tools would follow it with no re-check. | **P0** | Implemented this pass — see "DAST egress gateway" below. |
| Browser-based DAST | **Not present at audit time.** Confirmed zero hits for `playwright`/`selenium`/`puppeteer` in application code (`docs/dast.md` already stated this as the largest gap). | No JS execution, no SPA crawling, no authenticated browser sessions. | P1 | Implemented in a later pass, correctly sequenced after the egress gateway above — see "Browser-based DAST (Playwright)" below. |

### DAST egress gateway — what was implemented

The smallest safe fix that reuses the existing engine rather than re-implementing scope logic in a second place: a local forward proxy process, started per-run, that intercepts every CONNECT/request Nuclei or ZAP makes and runs it through the *same* `ScopeEngine`/DNS-re-resolution logic `GatedTransport` already uses, before allowing the TCP connection to proceed. Both tools support pointing at a proxy (Nuclei: `-proxy`; ZAP: `-config network.connection.httpProxy.*` / `http_proxy` env for the baseline/full-scan wrapper scripts), so this closes the gap without patching either binary.

See `backend/app/core/dast/egress_proxy.py` (new) and the wiring in `nuclei.py`/`zap.py`/`tooling.py`. Full detail in `docs/egress-security.md`.

### Browser-based DAST (Playwright) — what was implemented

An opt-in alternative crawler (`DastTarget.use_browser`), not a replacement for the regex-based one: `backend/app/core/dast/browser.py`'s `BrowserCrawler` drives a real, headless Chromium through Playwright and reads the *rendered* DOM, so a link a client-side router injects after load is found — the concrete case the regex crawler cannot see. Launched with its traffic pointed at the same `EgressGateway` Nuclei and ZAP use, exactly the ordering this row called for: the browser engine never runs outside this run's own scope-checking proxy. "Authenticated browser session" support is scoped honestly to one thing — `DastTarget.storage_state` carries an operator-supplied Playwright storage state through every navigation; it does not drive a login form itself.

See `backend/app/core/dast/browser.py` (new) and the wiring in `engine.py`. Full detail in `docs/dast.md`'s "Browser-based crawl (Playwright)" section. Verified end to end against a real pre-installed Chromium in `tests/test_dast_browser.py`, including a negative control proving the regex crawler genuinely cannot see a script-injected link that the browser crawler does.

---

## 2. Operational dashboard completeness

`docs/limitations.md`'s claim that "the web dashboard is read-only... starting a run, changing a finding's status is API/CLI only" is **stale** — later phases (tasks #171-178, #197-199 in this project's own history) wired real write actions into the Next.js frontend. Audited actual current state:

| Resource | Action | UI (Next.js)? | CLI? | Gap? | Citation |
|---|---|---|---|---|---|
| Target | create, RoE/authorization/scope/adapter edit | Yes | Yes | None | `frontend/components/targets/create-target-form.tsx:79`, `authorization-grant-form.tsx` |
| Repository | add, scan | Yes | Yes | None | `frontend/components/repositories/add-repository-form.tsx:31` |
| Run | start, view status/progress/logs | Yes | Yes | None | `frontend/components/runs/start-run-form.tsx:33`, `run-detail.tsx:46-54` |
| Run | **cancel** | **Yes** *(closed)* | Yes | None | `components/runs/cancel-run-button.tsx`, calling the existing `POST /runs/{id}/cancel` route |
| Finding | status change, duplicate link/unlink, filter/paginate | Yes | Yes | None | `finding-status-form.tsx:53`, `finding-duplicate-form.tsx:40,85` |
| Finding | **trigger retest** | **Yes** *(closed)* | Yes (`cmd_retest`) | None | `components/findings/retest-finding-button.tsx`, same `SECURITY_ENGINEER`+ gate as the CLI |
| Finding | **remediation assignment (owner/due date)** | **Yes** *(closed)* | **No** | None (UI path covers it) | `components/remediation/remediation-task-form.tsx` against `PUT`/`GET .../findings/{id}/remediation`. No dedicated `kervy_cli` subcommand exists for this — an earlier pass's roadmap note claiming one did was itself wrong, corrected here. |
| Report | generate/download (md/html/pdf/json/sarif/csv) | Yes | Yes | None | `report-download.tsx:46-47` |
| Evidence | list/verify/download | **Yes** *(closed)* | Yes (`cmd_evidence_list/verify`) | None | `components/evidence/evidence-panel.tsx` against `GET .../evidence` and `GET .../evidence/verify`, plus a per-entry download reusing `clientApiDownload` |
| Exploitation | authorization grant, fire, approve/reject | Yes | Partial | None | `exploitation-fires.tsx:144,165,238` |
| Workflow | create, run now | Yes | Yes | None | `create-workflow-form.tsx` |
| Workflow | **edit, delete** | **Yes** *(closed)* | Yes (`cmd_workflow_update/delete`) | None | `components/workflows/edit-workflow-form.tsx` against `PATCH`/`DELETE .../workflows/{id}` |
| Workflow | **webhook-secret rotate, approve/reject gate** | **No** | Yes (`cmd_workflow_webhook_secret/approve/reject`) | **Yes — P2** | still CLI-only; no dashboard surface for either action |
| **API keys** | **create, list, revoke** | **No** | **Yes** *(closed)* | **Yes — P2** *(downgraded from P1)* | `kervy_cli`'s `apikey` command group now covers `create`/`list`/`revoke` over `api_keys.py:29,85,101`; only the web UI is still missing |

**Verified not a security issue**: client-side `ALLOWED_FINDING_TRANSITIONS` in `frontend/lib/types.ts:439-450` mirrors the backend enum purely to grey out invalid dropdown options; the server independently re-validates every transition (`findings.py`). This is UI affordance, not a trust boundary.

### Implemented across this and later passes

- **CLI**: `kervy_cli` gained an `apikey` command group (`create`/`list`/`revoke`) over the existing `api_keys.py` routes.
- **Run cancel** button added to the run detail page, calling the existing `POST /runs/{id}/cancel` route.
- **Retest trigger** button added to the finding detail page, calling the existing retest route, gated the same as the CLI (`SECURITY_ENGINEER`+).
- **A later pass** ("Dashboard convenience gaps: remediation assignment, evidence list/verify, workflow edit/delete", `docs/roadmap.md`) closed three more rows: remediation assignment, evidence list/verify/download, and workflow edit/delete — all frontend-only, no backend changes needed. That pass's own roadmap write-up claimed all three "already had... a working `kervy_cli` command" before the UI was added; for remediation assignment specifically, that claim is **wrong** — no `remediation` subcommand exists anywhere in `kervy_cli/main.py` (confirmed by direct grep), only the backend API did. Corrected here and in `docs/roadmap.md` rather than left standing.

Still open, genuinely P2 convenience rather than a capability gap (a CLI path exists for both): workflow webhook-secret rotation and gate approve/reject have no dashboard surface.

---

## 3. AI security engine taxonomy

| Taxonomy area | Status | Citation |
|---|---|---|
| Direct prompt injection (override, role, delimiter, hierarchy, encoding, language-switch) | **Already solid** | `probes/ai/direct_injection.py:138,179,217,256,290,334` |
| Indirect injection | **Implemented** — `ai.injection.indirect.document_injection` (`KERVY-AI-008`, `probes/ai/rag_injection.py`) | `docs/ai-security-testing.md`'s "RAG and agent security" section |
| Multi-turn injection / any multi-turn attack | **Partial** — `app/core/probes/ai/multiturn/` is a real conversation-state engine now (closing the structural "single `ask()` call, no state" gap), but it ships only two concrete multi-turn techniques (`ai.jailbreak.instruction_chaining`, `ai.agent.goal_hijacking`); cross-user leakage and a broader multi-turn taxonomy are still open | P2 (downgraded from P1 — the hard structural gap is closed, remaining work is breadth) |
| Jailbreak: encoding, obfuscation, translation | **Already solid** | `direct_injection.py:290,334` |
| Jailbreak: instruction chaining | **Implemented** — `ai.jailbreak.instruction_chaining` (`KERVY-AI-007`, `probes/ai/multiturn/instruction_chaining.py`), verified end to end against the real lab app | `tests/test_multiturn_engine.py` |
| Data leakage: system prompt / secret / sensitive-info extraction | **Already solid** | `disclosure.py:49,170` |
| Cross-user leakage | **Implemented** — `ai.disclosure.cross_user_leakage` (`KERVY-AI-013`, `app/core/probes/ai/cross_identity/`), reusing the same operator-declared `SyntheticAccount`s the REST BOLA probe already uses | — |
| Excessive agency | **Partial** — permission-graph design review flags unconfirmed/irreversible tools structurally; nothing attempts a live unauthorized call | P1 (deliberately conservative by design — see `docs/limitations.md`'s own stated single-shot-confidence-cap philosophy; raising this requires either careful live-fire design or stays design-review by policy) |
| RAG security (document injection, retrieval/context poisoning, cross-tenant retrieval, malicious documents) | **Partial** — document injection covered (see Indirect injection above); retrieval/context poisoning and cross-tenant retrieval still have no coverage, since neither has a real retrieval-corpus/multi-tenant-store target abstraction to test against | P1 (downgraded from "zero coverage") |
| Agent security (goal hijacking, tool manipulation, memory poisoning, chain manipulation) | **Partial** — goal hijacking covered (`ai.agent.goal_hijacking`, `KERVY-AI-034`, new `ProbeCategory.AGENT`); tool manipulation, memory poisoning, and chain manipulation remain uncovered, needing visibility into actual tool invocation/persisted memory this platform doesn't yet model | P1 (downgraded from "zero coverage") |
| Output security: XSS, SQL injection | **Already solid** | `output_handling.py` |
| Output security: command injection sink | **Gap** — four sinks exist (html/markdown-image/template/sql); no shell/command sink | P2 |
| garak / PyRIT integration | **Not present** — zero code references; `docs/BUILD_SPEC.md:1109` explicitly and deliberately declines to "build a thin wrapper around garak or promptfoo and call it a platform" | See adapter architecture below — implemented as a clean interface, not a wrapper |
| Multi-turn attack orchestration framework | **Implemented** — `app/core/probes/ai/multiturn/` (`contract.py`'s `MultiTurnProbe`, `runner.py`'s orchestrator) is a real conversation-state class/engine | `docs/ai-security-testing.md`'s "Multi-turn attack orchestration" section |
| Regression CLI (`kervy test ai [--ci]`) | **Implemented** — new `kervy-ai test ai` command (`--target`/`--current`, `--baseline`, `--ci`, `--report`) over `app/core/measure/regression.py` | `docs/roadmap.md`'s "`kervy-ai test ai [--ci]` regression command..." section |
| Cross-version/run statistical comparison | **Implemented** — same `app/core/measure/regression.py` as the row above: matches two runs by fingerprint (fallback probe_id+endpoint) and classifies REGRESSED/IMPROVED/UNCHANGED/NEW_PROBE/REMOVED_PROBE via a Wilson-interval non-overlap rule. (Distinct from "Retest ASR-delta" in section 4 below, which is about one finding's own before/after retest, not a cross-run AI-probe comparison — both are now implemented, by two different pieces of work.) | same section as above |
| `ProbeMeta` metadata completeness | **Partial** — `id`, `category`, `description`, OWASP/MITRE-ATLAS/CWE/NIST-AI-RMF mappings, required capabilities all present (`contract.py:54-93`); `severity`, `attack_type`, `turn_count`, `remediation` exist only as per-probe class attributes, not on the metadata model itself | P2 |

**Why this was originally sequenced as P1, not P0, despite being section 6-9 of the brief**: none of these were security *boundary* gaps — they were coverage/breadth gaps, the same category the platform's own `docs/comparison.md` already and correctly concedes to garak/PyRIT. Most of the P1 rows above have since been closed or narrowed in later passes (see each row's citation); what remains open (RAG retrieval/context poisoning, agent tool-manipulation/memory-poisoning/chain-manipulation, command-injection sink, `ProbeMeta` completeness) is listed in Remaining Gaps below.

### Implemented across this and later passes

- `docs/ai-security-testing.md` updated with this honest taxonomy table (now current — see individual row citations above for later additions).
- A **garak/PyRIT adapter interface** (`backend/app/core/probes/ai/external/`) — see section "Plugin/adapter architecture" below — giving external engines a place to plug in without the platform executing them outside its own authorization/egress model. The adapters themselves (actually shelling out to garak/PyRIT) remain **not implemented**; only the clean interface + the refusal-to-run-ungated-execution guard is, which is explicitly what the brief allows ("If direct integration is unsafe or impractical, implement a clean adapter architecture and document it").
- **Multi-turn attack orchestration engine** (`docs/roadmap.md`'s own section), shipping `ai.jailbreak.instruction_chaining`.
- **RAG security + agent security probe families** (`docs/roadmap.md`'s own section), shipping `ai.injection.indirect.document_injection` and `ai.agent.goal_hijacking`.
- **`kervy-ai test ai [--ci]` regression command + cross-run statistical comparison** (`docs/roadmap.md`'s own section).
- **Cross-user AI data-leakage probe** (`docs/roadmap.md`'s own section), shipping `ai.disclosure.cross_user_leakage`.

### Not implemented (honestly deferred, not claimed)

Retrieval/context poisoning and cross-tenant retrieval (RAG), tool manipulation/memory poisoning/chain manipulation (agent security), and a broader multi-turn attack taxonomy beyond the two techniques shipped. Each still needs a target abstraction (a real retrieval corpus, a multi-tenant document store, visibility into tool invocation or persisted memory) this platform does not yet model — not a probe-writing gap but a missing foundation, the same reasoning that gated the earlier work. These are listed as such in Remaining Gaps.

---

## 4. Finding lifecycle, evidence, audit trail, vulnerability intelligence

| Area | Verdict | Detail |
|---|---|---|
| Evidence (redaction-before-write, content-addressing, hash chain, tamper verification) | **Already solid** | `backend/app/core/evidence/bundle.py:124-190`, `store.py:58-120,162-208`. Verified by tests that edit a stored bundle / remove a manifest entry and confirm verification fails (`tests/test_evidence.py:223,238`). |
| SARIF export | **Already solid** | `backend/app/core/reporting/sarif.py` — SARIF 2.1.0, carries `ruleId`, `level`, `locations`, `partialFingerprints` (stable fingerprint), platform-specific fields in `properties` so strict SARIF consumers still round-trip cleanly. |
| RBAC / multi-tenancy, DB-side isolation | **Already solid** | Roles: `OWNER`/`ADMIN`/`SECURITY_ENGINEER`/`ANALYST`/`VIEWER` (`organization.py:15-26`). Postgres **RLS with FORCE** on 14 tenant-scoped tables (`alembic/versions/b2e6f4a91c7d_row_level_security.py:46-81`), fail-closed (no GUC set → policy matches zero rows). `tests/security/test_authorization_matrix.py` walks the *live* FastAPI route table (not a hand-maintained list) asserting 401/404/403 across 15 routers. |
| Finding lifecycle states | **Mostly already solid, naming differs from the brief** | Actual enum (`models/finding.py:45-56`): `NEW`→`CONFIRMED`→`IN_REMEDIATION`→`REMEDIATED`→`RETEST_REQUIRED`→`CLOSED`, plus `FALSE_POSITIVE`/`ACCEPTED_RISK`. Maps onto the brief's requested `OPEN→TRIAGED→CONFIRMED→REMEDIATION→READY_FOR_RETEST→RETESTED→RESOLVED` with two real gaps: no standalone `TRIAGED` state (direct `NEW→CONFIRMED` jump), and `RETESTED`/`DUPLICATE` are modeled as data (a `RetestResult` row, a `duplicate_of_finding_id` field) rather than status values — which is arguably the *more correct* design (a duplicate finding keeps its real status; collapsing that into a status value would lose information), so this is flagged but not necessarily a defect. | P2 |
| Audit trail coverage | **Implemented — both real gaps closed** | `AuditEvent` is itself hash-chained (`audit.py:12-47`) and covers authorization/scope/target changes, run creation/cancellation, manual finding-status changes, report/evidence access, membership changes. **First gap, closed**: worker-side run execution (start/complete/fail inside the Celery task) now also calls `app.audit.service.record_event`, alongside the existing operational `RunEvent` log (`workers/tasks.py`). **Second gap, closed**: automatic finding-status changes now carry an audit event too — `findings/service.py`'s `promote_run_results` auto-reopen path (`action="finding.status.auto_reopened"`, `user_id=None`) and `retest/service.py`'s `_apply` on both status-changing verdict branches (`action="finding.status.auto_retest_verdict"`), via `docs/roadmap.md`'s "Automatic finding-status-change audit events" section. |
| Retest statistical rigor | **Implemented** | `app.core.measure.asr.asr_delta()` now compares a finding's before/after `attack_success_rate` using the same Wilson-interval non-overlap rule `measure()` already used for attack-vs-control, reusing it symmetrically for earlier-vs-later rate instead. `RetestResult` gained `before_attack_success_rate`/`after_attack_success_rate` columns and a computed `attack_success_rate_delta`, rendered in the markdown report. See `docs/roadmap.md`'s "Retest ASR-delta / confidence-interval comparison" section. (Distinct from the AI regression CLI in section 3 above — that compares two whole *runs*' probe results; this compares one *finding's* own two retest evidence snapshots.) |
| Vulnerability intelligence (OSV/NVD/GHSA) | **Partial — npm now direct, Python/other ecosystems still delegated** | A new `OsvEngine` (`app/core/appsec/osv/`) calls `osv.dev`'s batch/vulns API directly through `GatedTransport` for npm lockfiles, closing real zero-coverage there. Python SCA remains `pip-audit` (its own embedded advisory data); container is still Trivy; IaC is still Checkov. No direct GHSA or NVD client exists (GHSA's npm advisories are already re-served by osv.dev, narrowing but not closing that specific gap). | P2 (downgraded from P1 — the highest-value ecosystem, npm, is now direct) |
| Reachability analysis | **Partial — import-level foundation now exists for Python** | `app/core/appsec/reachability/python_imports.py`'s `assess()` does AST-based static-import detection (IMPORTED/NOT_FOUND/NOT_ASSESSED), wired into the pip-audit engine's normalization to replace a blanket "not assessed" disclaimer with a concrete file:line or stated absence. Explicitly not done: symbol/call-graph-level reachability (the deeper question), non-Python ecosystems, and dynamic imports (`importlib.import_module`) are a named false-negative class. See `docs/roadmap.md`'s "Reachability analysis foundation (import-level, Python)" section. | P2 (downgraded from P1 — import-level foundation exists; deeper reachability is the remaining work) |

### Implemented across this and later passes

- **Audit-trail gaps closed for run execution and automatic finding-status changes** — see the "Audit trail coverage" row above; both were listed as the two real gaps in this area and both are now closed.
- **Retest ASR-delta / confidence-interval comparison** — see the "Retest statistical rigor" row above.
- **Direct OSV.dev integration (npm)** and **reachability analysis foundation (import-level, Python)** — see their rows above; both narrow rather than fully close their respective gaps, as stated.

### Not implemented (honestly deferred, not claimed)

Direct NVD/GHSA clients, OSV/direct-advisory coverage for non-npm ecosystems (Python, Go, Rust, Java, etc.), symbol/call-graph-level reachability analysis, reachability for non-Python ecosystems, and a standalone `TRIAGED` finding status. These are real, scoped items for the next increment — see Remaining Gaps.

---

## 5. Docker reliability

`docker compose config` **passed** cleanly once a `.env` exists (copied from `.env.example` — and `docs/installation.md:20` already states `cp .env.example .env` as the explicit first command; the audit agent that produced the first draft of this row claimed otherwise, and that claim was wrong — corrected here rather than left standing). `docker compose build` failed in this sandbox specifically on `apt-get update` against `deb.debian.org` returning HTTP 403 over plain HTTP — this is this sandbox's own egress policy blocking a non-HTTPS mirror, not a defect in `Dockerfile.backend`/`Dockerfile.worker` that could be identified from the Dockerfile content itself. `docker compose up` was not reached. (`docs/installation.md` itself separately notes `docker compose up --build` has never run in *its own* build environment either, for a different reason — Docker Hub blob pulls blocked at that environment's proxy. Two different sandboxes, two different network-policy blocks, same honest "unverified" conclusion.)

**Verdict**: the compose file and startup wiring are valid; the "`docker compose up --build` is unverified" claim in `docs/installation.md`/`docs/limitations.md` **remains honestly true** — it could not be fully verified end-to-end in this environment, and that should not be overstated as fixed.

### Implemented this pass

- Nothing — no defect was found to fix. `docs/installation.md` already documents the `.env` step explicitly; no Dockerfile/compose change was warranted since the only failure found was this sandbox's own network policy, not the files.

### Not implemented this pass

An actual verified `docker compose up --build` end-to-end pass, and the requested smoke test (containers start → DB initializes → backend/frontend respond → worker connects → one API call succeeds). This needs an environment with unrestricted apt-mirror egress; flagged for the user to run or for a follow-up session with different sandbox network policy.

---

## 6. CI/CD

Already comprehensive and **already platform-agnostic at the product level**, contrary to an implicit assumption in the brief that CI/CD support needs to be built from scratch. `.github/workflows/` (`ci.yml`, `security.yml`, `codeql.yml`, `deps.yml`, `container.yml`, `sbom.yml`, `lab-e2e.yml`, `release.yml`, `framework-drift.yml`) are this repository's own GitHub-specific CI, testing the platform itself. Separately, `docs/cicd.md` documents the `kervy-ai ci`/`kervy-ai gate` CLI — a plain pip-installed, env-var-and-exit-code-driven tool (exit codes 0/1/2/3/4 for pass/fail/config-error/auth-error/scope-violation) that any CI runner (GitHub, GitLab, Jenkins, Azure DevOps) can invoke identically, with a YAML gate config supporting `fail_on`/`max_high`/`min_confidence`/`require_stability`/time-boxed `ignore` entries. **Verdict: already solid** — the brief's "at minimum implement generic CI functionality first" is already met by the CLI's design; what's missing is example GitLab/Jenkins/Azure DevOps *pipeline snippets* in the docs, not new product capability.

### Implemented this pass

Nothing — correctly deprioritized below the P0/P1 items above, since the underlying capability already exists.

### Not implemented this pass

Example pipeline YAML/Jenkinsfile snippets for GitLab/Jenkins/Azure DevOps in `docs/cicd.md`. Low effort, low risk, genuinely P2 — listed in Remaining Gaps.

---

## Plugin/adapter architecture

A clean interface for external attack engines was added at
`backend/app/core/probes/ai/external/` (protocol + registration point),
matching the brief's explicit permission to implement "a clean adapter
architecture and document it" rather than executing garak/PyRIT directly
this pass. The platform remains responsible for authorization, scope,
execution lifecycle, evidence, findings, normalization, reporting and audit
— exactly as the brief requires — and no adapter in this interface is
permitted to make an outbound call outside `GatedTransport`; the interface
itself enforces this the same way the plugin system already proves a
third-party plugin cannot bypass the scope engine (`docs/plugin-development.md`,
task #80 in this project's history). See `docs/ai-security-testing.md`'s
"External attack engines" section and `docs/egress-security.md`.

---

## Remaining gaps (priority order; items struck through are now implemented — see the dated notes)

1. ~~**Browser-based DAST (Playwright)**~~ — **Implemented** (see "Browser-based DAST (Playwright) — what was implemented" above). Correctly sequenced after the egress gateway landed, so the browser engine inherits containment from day one instead of repeating the Nuclei/ZAP mistake.
2. ~~**RAG security + agent security probe families**~~ — **Implemented, narrower than full coverage**: one RAG technique (`ai.injection.indirect.document_injection`) and one agent-security technique (`ai.agent.goal_hijacking`) now ship — see section 3's "RAG security"/"Agent security" rows above. Retrieval/context poisoning, cross-tenant retrieval, tool manipulation, memory poisoning, and chain manipulation remain open; each needs a target abstraction (a real retrieval corpus, a multi-tenant store, tool-invocation/memory visibility) this platform doesn't yet model — carried forward below as item 2.
3. ~~**Multi-turn attack orchestration engine**~~ — **Implemented** (`app/core/probes/ai/multiturn/`, `docs/ai-security-testing.md`'s "Multi-turn attack orchestration" section). Ships two probes, `ai.jailbreak.instruction_chaining` and `ai.agent.goal_hijacking`; was needed before indirect/chained/multi-turn injection probes could exist at all.
4. ~~**`kervy test ai [--ci]` regression command + cross-run/version statistical comparison**~~ — **Implemented** (`app/core/measure/regression.py`, new `kervy-ai test ai` CLI command; `docs/roadmap.md`'s own section). No stated deferral — fully closes this item.
5. ~~**Direct OSV/NVD/GHSA integration**~~ — **Implemented for npm**, still delegated elsewhere: new `OsvEngine` (`app/core/appsec/osv/`) calls `osv.dev` directly for npm lockfiles. Python SCA (pip-audit), container (Trivy), and IaC (Checkov) still delegate to their own embedded data, and no direct NVD/GHSA client exists — carried forward below as item 5.
6. ~~**Reachability analysis foundation**~~ — **Implemented for Python imports**: `app/core/appsec/reachability/python_imports.py` does AST-based static-import detection, wired into the pip-audit engine. Symbol/call-graph-level reachability and non-Python ecosystems remain open — carried forward below as item 6.
7. ~~**Automatic finding-status-change audit events**~~ — **Implemented**, both the auto-reopen path (`findings/service.py::promote_run_results`) and the automatic-retest-verdict path (`retest/service.py::_apply`) now call `record_event`. No stated deferral.
8. ~~**Retest ASR-delta / confidence-interval comparison**~~ — **Implemented** (`app.core.measure.asr.asr_delta()`, new `RetestResult` columns and computed delta, rendered in the markdown report). No stated deferral.
9. ~~**Remaining dashboard convenience gaps**~~ — **Implemented**: remediation-assignment UI, evidence list/verify UI, workflow edit/delete UI, workflow webhook-secret rotation and gate approve/reject UI, and API key create/list/revoke UI (`docs/roadmap.md`'s "Dashboard convenience gaps" section and its later addition). No stated deferral.
Still open — some are the narrower remainder of a row struck through above, not new discoveries:

10. **RAG retrieval/context poisoning, cross-tenant retrieval; agent tool-manipulation, memory-poisoning, chain-manipulation** (the narrower remainder of item 2) — each needs a target abstraction (real retrieval corpus, multi-tenant store, tool-invocation/memory visibility) this platform doesn't yet model; not a probe-writing gap but a missing foundation.
11. ~~**Cross-user leakage probe**~~ — **Implemented** (`ai.disclosure.cross_user_leakage`, `KERVY-AI-013`, `app/core/probes/ai/cross_identity/`, `docs/roadmap.md`'s own section). Reuses the same operator-declared `SyntheticAccount`s the REST BOLA probe already uses, extended to the AI/conversational engine via a new per-identity `Ask` dispatch in `AiSecurityCheck.run`.
12. **Direct NVD/GHSA clients, and OSV/direct-advisory coverage for non-npm ecosystems** (Python, Go, Rust, Java) (the narrower remainder of item 5).
13. ~~**Symbol/call-graph-level reachability analysis, and reachability for non-Python ecosystems**~~ — **Implemented, narrower than full coverage**: single-file symbol-*usage* reachability now ships — `python_imports.py`'s `assess()` distinguishes "imported" from "imported and a call to a name it bound was also found in the same file" (`ReachabilityVerdict.IMPORTED_AND_CALLED`, `docs/roadmap.md`'s own section). This is not the deeper, true call-graph question the item named (tracing to the *specific* vulnerable function, with type resolution across module boundaries) — that needs a type-inference dependency this platform does not have and a vulnerable-function data source that does not exist for PyPI advisories either way, so it remains out of reach rather than attempted and overclaimed. Non-Python ecosystems also remain open. Both carried forward below as item 18.
14. ~~**A dashboard surface for workflow webhook-secret rotation and gate approve/reject**~~ — **Implemented**: `RotateWebhookSecretButton` on the workflows list, and a new nested `workflows/[workflowId]` run-history page with `ApproveRejectRunButtons` on `awaiting_approval` runs (`docs/roadmap.md`'s own section). The CLI's `cmd_workflow_webhook_secret`/`approve`/`reject` call the same REST endpoints the new UI does.
15. ~~**Dashboard UI for API key create/list/revoke**~~ — **Implemented**: a new `api-keys` organization tab, `CreateApiKeyForm`, and `RevokeApiKeyButton` (`docs/roadmap.md`'s own section). The CLI's `apikey` group calls the same REST endpoints the new UI does.
16. ~~**GitLab/Jenkins/Azure DevOps example snippets**~~ — **Implemented**: a new `## GitLab CI, Jenkins, Azure DevOps` section in `docs/cicd.md`, right after its existing GitHub Actions "short version." No CLI change needed — `kervy-ai` was already plain exit-code-contract CI tooling with nothing GitHub-specific in it; only the examples were missing.
17. **A real, unrestricted-egress environment to actually complete the `docker compose up --build` verification and smoke test.**
18. **True call-graph-level reachability (tracing to the specific vulnerable function, with type resolution), and reachability for non-Python ecosystems** (the narrower remainder of item 13) — the former needs a type-inference dependency this platform does not have, and a vulnerable-function-level data source that does not exist for PyPI advisories; the latter is parsing a different language's import/call syntax, not new architecture, and is left for a later increment rather than attempted speculatively alongside the Python path.

None of these were skipped because they're hard to justify — the first nine items above were each sequenced behind the P0 egress fix and the smallest, highest-confidence fixes, and all nine have since been closed or narrowed across several later passes (see each struck-through item's own note). What's left is the genuinely harder, foundation-shaped remainder: target abstractions this platform doesn't model yet (a retrieval corpus, a multi-tenant document store, tool-invocation/memory visibility, a multi-user session concept), plus the smaller, already-scoped convenience and CI-snippet items.
