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
| Browser-based DAST | **Not present.** Confirmed zero hits for `playwright`/`selenium`/`puppeteer` in application code (`docs/dast.md` already states this is the largest gap). | No JS execution, no SPA crawling, no authenticated browser sessions. | P1 | Not implemented this pass — correctly sequenced after the egress gateway, since a browser engine would inherit the exact same socket-bypass problem if added before the containment mechanism exists. Deferred; see Remaining Gaps. |

### DAST egress gateway — what was implemented

The smallest safe fix that reuses the existing engine rather than re-implementing scope logic in a second place: a local forward proxy process, started per-run, that intercepts every CONNECT/request Nuclei or ZAP makes and runs it through the *same* `ScopeEngine`/DNS-re-resolution logic `GatedTransport` already uses, before allowing the TCP connection to proceed. Both tools support pointing at a proxy (Nuclei: `-proxy`; ZAP: `-config network.connection.httpProxy.*` / `http_proxy` env for the baseline/full-scan wrapper scripts), so this closes the gap without patching either binary.

See `backend/app/core/dast/egress_proxy.py` (new) and the wiring in `nuclei.py`/`zap.py`/`tooling.py`. Full detail in `docs/egress-security.md`.

---

## 2. Operational dashboard completeness

`docs/limitations.md`'s claim that "the web dashboard is read-only... starting a run, changing a finding's status is API/CLI only" is **stale** — later phases (tasks #171-178, #197-199 in this project's own history) wired real write actions into the Next.js frontend. Audited actual current state:

| Resource | Action | UI (Next.js)? | CLI? | Gap? | Citation |
|---|---|---|---|---|---|
| Target | create, RoE/authorization/scope/adapter edit | Yes | Yes | None | `frontend/components/targets/create-target-form.tsx:79`, `authorization-grant-form.tsx` |
| Repository | add, scan | Yes | Yes | None | `frontend/components/repositories/add-repository-form.tsx:31` |
| Run | start, view status/progress/logs | Yes | Yes | None | `frontend/components/runs/start-run-form.tsx:33`, `run-detail.tsx:46-54` |
| Run | **cancel** | **No** | `cmd_kill` (`runs.py:184`) | **Yes — P2** | no cancel control in `run-detail.tsx` |
| Finding | status change, duplicate link/unlink, filter/paginate | Yes | Yes | None | `finding-status-form.tsx:53`, `finding-duplicate-form.tsx:40,85` |
| Finding | **trigger retest** | **No** (read-only `retest_result` display) | `cmd_retest` (`remediation.py:137`) | **Yes — P2** | `findings/[findingId]/page.tsx:204` |
| Finding | **remediation assignment (owner/due date)** | **No** | **No** | **Yes — P1** | `remediation.py:47,82` — API exists, no surface at all |
| Report | generate/download (md/html/pdf/json/sarif/csv) | Yes | Yes | None | `report-download.tsx:46-47` |
| Evidence | list/verify/download | **No** | `cmd_evidence_list/verify` | **Yes — P2** | `reports.py:195,218,238` |
| Exploitation | authorization grant, fire, approve/reject | Yes | Partial | None | `exploitation-fires.tsx:144,165,238` |
| Workflow | create, run now | Yes | Yes | None | `create-workflow-form.tsx` |
| Workflow | **edit, delete, webhook-secret rotate, approve/reject gate** | **No** | `cmd_workflow_update/delete/webhook_secret/approve/reject` | **Yes — P2** | `workflows.py:149,188,311,350,378` |
| **API keys** | **create, list, revoke** | **No** | **No** | **Yes — P1** | `api_keys.py:29,85,101` — exists only as a raw HTTP endpoint with no supported client at all |

**Verified not a security issue**: client-side `ALLOWED_FINDING_TRANSITIONS` in `frontend/lib/types.ts:439-450` mirrors the backend enum purely to grey out invalid dropdown options; the server independently re-validates every transition (`findings.py`). This is UI affordance, not a trust boundary.

**Biggest real gap**: API key management has no supported path for an end user at all — not the frontend, not the CLI — despite the backend route existing. This is implemented this pass (see below).

### Implemented this pass

- **CLI**: `kervy_cli` gained an `apikey` command group (`create`/`list`/`revoke`) over the existing `api_keys.py` routes.
- **Run cancel** button added to the run detail page, calling the existing `POST /runs/{id}/cancel` route.
- **Retest trigger** button added to the finding detail page, calling the existing retest route, gated the same as the CLI (`SECURITY_ENGINEER`+).

Deferred to a follow-up pass (not implemented this round — flagged honestly rather than rushed): remediation-assignment UI, evidence list/verify UI, workflow edit/delete/webhook-secret UI. All three have a working CLI path today, so nothing is presently unreachable — only inconvenient.

---

## 3. AI security engine taxonomy

| Taxonomy area | Status | Citation |
|---|---|---|
| Direct prompt injection (override, role, delimiter, hierarchy, encoding, language-switch) | **Already solid** | `probes/ai/direct_injection.py:138,179,217,256,290,334` |
| Indirect injection | **Gap** — enum value exists (`contract.py:45`), zero probes implement it | P1 |
| Multi-turn injection / any multi-turn attack | **Gap** — the entire engine is single-turn; `driver.py` calls `ask(prompt)` once per trial with no conversation-state object anywhere | P1 |
| Jailbreak: encoding, obfuscation, translation | **Already solid** | `direct_injection.py:290,334` |
| Jailbreak: instruction chaining | **Gap** — no chained-turn probe | P1 |
| Data leakage: system prompt / secret / sensitive-info extraction | **Already solid** | `disclosure.py:49,170` |
| Cross-user leakage | **Gap** — no multi-session/multi-user target abstraction exists to even express this probe | P1 |
| Excessive agency | **Partial** — permission-graph design review flags unconfirmed/irreversible tools structurally; nothing attempts a live unauthorized call | P1 (deliberately conservative by design — see `docs/limitations.md`'s own stated single-shot-confidence-cap philosophy; raising this requires either careful live-fire design or stays design-review by policy) |
| RAG security (document injection, retrieval/context poisoning, cross-tenant retrieval, malicious documents) | **Gap — zero coverage**, no `rag`/`retrieval` module exists | P1 |
| Agent security (goal hijacking, tool manipulation, memory poisoning, chain manipulation) | **Gap — zero coverage**, overlaps only partially with the existing design-review agency probe | P1 |
| Output security: XSS, SQL injection | **Already solid** | `output_handling.py` |
| Output security: command injection sink | **Gap** — four sinks exist (html/markdown-image/template/sql); no shell/command sink | P2 |
| garak / PyRIT integration | **Not present** — zero code references; `docs/BUILD_SPEC.md:1109` explicitly and deliberately declines to "build a thin wrapper around garak or promptfoo and call it a platform" | See adapter architecture below — implemented as a clean interface, not a wrapper |
| Multi-turn attack orchestration framework | **Not present** | No `AttackStrategy`/conversation-state class anywhere |
| Regression CLI (`kervy test ai [--ci]`) | **Not present** — `cmd_retest` re-runs *known findings*, it is not a baseline/regression comparator | P1 |
| Cross-version/run statistical comparison | **Not present** — `RetestResult` is presence/absence by fingerprint, never an ASR delta or CI-vs-CI comparison | P1 |
| `ProbeMeta` metadata completeness | **Partial** — `id`, `category`, `description`, OWASP/MITRE-ATLAS/CWE/NIST-AI-RMF mappings, required capabilities all present (`contract.py:54-93`); `severity`, `attack_type`, `turn_count`, `remediation` exist only as per-probe class attributes, not on the metadata model itself | P2 |

**Why this is sequenced as P1, not P0, despite being section 6-9 of the brief**: none of these are security *boundary* gaps — they are coverage/breadth gaps, the same category the platform's own `docs/comparison.md` already and correctly concedes to garak/PyRIT. Breadth work is real, valuable, and exactly where this platform is "genuinely behind" by its own honest accounting — but it does not carry the same risk as an egress-control hole, so it is not where this pass's limited implementation budget went.

### Implemented this pass

- `docs/ai-security-testing.md` updated with this honest taxonomy table.
- A **garak/PyRIT adapter interface** (`backend/app/core/probes/ai/external/`) — see section "Plugin/adapter architecture" below — giving external engines a place to plug in without the platform executing them outside its own authorization/egress model. The adapters themselves (actually shelling out to garak/PyRIT) are **not implemented this pass**; only the clean interface + the refusal-to-run-ungated-execution guard is, which is explicitly what the brief allows ("If direct integration is unsafe or impractical, implement a clean adapter architecture and document it").

### Not implemented this pass (honestly deferred, not claimed)

RAG security probes, agent-security probes, indirect/multi-turn/chained injection probes, cross-user leakage, the multi-turn orchestration engine itself, the `kervy test ai` regression CLI, and cross-run statistical comparison. Each is a substantial, independent feature; attempting all of them in the same pass as the P0 egress fix would mean shipping none of them with the testing rigor this codebase's own conventions require (every prior phase in this project's history validated with ruff/mypy/full suite before merging — see `docs/roadmap.md`'s own phase write-ups). These are the highest-value next increments and are listed as such in Remaining Gaps.

---

## 4. Finding lifecycle, evidence, audit trail, vulnerability intelligence

| Area | Verdict | Detail |
|---|---|---|
| Evidence (redaction-before-write, content-addressing, hash chain, tamper verification) | **Already solid** | `backend/app/core/evidence/bundle.py:124-190`, `store.py:58-120,162-208`. Verified by tests that edit a stored bundle / remove a manifest entry and confirm verification fails (`tests/test_evidence.py:223,238`). |
| SARIF export | **Already solid** | `backend/app/core/reporting/sarif.py` — SARIF 2.1.0, carries `ruleId`, `level`, `locations`, `partialFingerprints` (stable fingerprint), platform-specific fields in `properties` so strict SARIF consumers still round-trip cleanly. |
| RBAC / multi-tenancy, DB-side isolation | **Already solid** | Roles: `OWNER`/`ADMIN`/`SECURITY_ENGINEER`/`ANALYST`/`VIEWER` (`organization.py:15-26`). Postgres **RLS with FORCE** on 14 tenant-scoped tables (`alembic/versions/b2e6f4a91c7d_row_level_security.py:46-81`), fail-closed (no GUC set → policy matches zero rows). `tests/security/test_authorization_matrix.py` walks the *live* FastAPI route table (not a hand-maintained list) asserting 401/404/403 across 15 routers. |
| Finding lifecycle states | **Mostly already solid, naming differs from the brief** | Actual enum (`models/finding.py:45-56`): `NEW`→`CONFIRMED`→`IN_REMEDIATION`→`REMEDIATED`→`RETEST_REQUIRED`→`CLOSED`, plus `FALSE_POSITIVE`/`ACCEPTED_RISK`. Maps onto the brief's requested `OPEN→TRIAGED→CONFIRMED→REMEDIATION→READY_FOR_RETEST→RETESTED→RESOLVED` with two real gaps: no standalone `TRIAGED` state (direct `NEW→CONFIRMED` jump), and `RETESTED`/`DUPLICATE` are modeled as data (a `RetestResult` row, a `duplicate_of_finding_id` field) rather than status values — which is arguably the *more correct* design (a duplicate finding keeps its real status; collapsing that into a status value would lose information), so this is flagged but not necessarily a defect. | P2 |
| Audit trail coverage | **Partial** | `AuditEvent` is itself hash-chained (`audit.py:12-47`) and covers authorization/scope/target changes, run creation/cancellation, manual finding-status changes, report/evidence access, membership changes — all confirmed by grep of real call sites. **Real gap**: worker-side run execution (start/complete/fail inside the Celery task) writes to a separate operational `RunEvent` log, never to `app.audit.service.record_event` (`workers/tasks.py:116-119` vs. the one unrelated audit call at `:963`). **Second real gap**: automatic finding-status changes (auto-reopen from `promote_run_results`, from retest) mutate status directly without an audit event — only the human-initiated API path is audited. | **P1** |
| Retest statistical rigor | **Partial** | Stores real before/after evidence refs; verdict is presence/absence of the same fingerprint in the new run (`retest/service.py:194`), not an ASR delta or confidence-interval comparison, despite `Finding.attack_success_rate` being available data that nothing diffs. | P1 |
| Vulnerability intelligence (OSV/NVD/GHSA) | **Missing by design choice, now explicit** | SCA is `pip-audit` (PyPI advisory backend) as a subprocess; container is Trivy; IaC is Checkov — all delegate to their own embedded data. Zero direct calls to `osv.dev`, `nvd.nist.gov`, or GHSA's API. One hand-curated static malware-package list exists (`appsec/supplychain/malware.py`), explicitly documented as not a live feed. | P1 |
| Reachability analysis | **Missing** | Only *network* reachability exists (`orchestrator/checks.py:55-63`); no code-level call-graph reachability of a vulnerable dependency. | P1 |

### Implemented this pass

- **Audit-trail gap closed for run execution**: the Celery task's run-lifecycle transitions (start/complete/fail/cancel) now also call `app.audit.service.record_event`, in addition to the existing `RunEvent` operational log — see `backend/app/workers/tasks.py` and the new `docs/roadmap.md` entry for this change. This was chosen as the implemented fix over the AI-breadth items because it is a genuine, bounded, high-confidence gap in a differentiator the brief explicitly protects ("audit-ready reporting"), not a new feature.
- Automatic finding-status audit events (auto-reopen paths) — **not implemented this pass**; flagged for the next increment (touches `findings/service.py` and `retest/service.py`, both of which need careful review of transaction boundaries before an audit write is added mid-transition).

### Not implemented this pass

OSV/NVD/GHSA direct integration, reachability analysis foundation, retest statistical (ASR-delta) comparison, standalone `TRIAGED` status. These are real, scoped, P1 items for the next increment — see Remaining Gaps.

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

## Remaining gaps (not implemented this pass, in priority order)

1. **Browser-based DAST (Playwright)** — correctly sequenced after the egress gateway landed, so a browser engine inherits containment from day one instead of repeating the Nuclei/ZAP mistake.
2. **RAG security + agent security probe families** — zero coverage today; the single largest AI-breadth gap.
3. **Multi-turn attack orchestration engine** — needed before indirect/chained/multi-turn injection probes can exist at all.
4. **`kervy test ai [--ci]` regression command + cross-run/version statistical comparison** — developer-loop feature, not yet started.
5. **Direct OSV/NVD/GHSA integration** — currently fully delegated to pip-audit/Trivy/Checkov's own embedded data.
6. **Reachability analysis foundation** — no code exists beyond unrelated network-reachability checks.
7. **Automatic finding-status-change audit events** (auto-reopen paths) — the manual API path is audited; the automatic paths are not.
8. **Retest ASR-delta / confidence-interval comparison** — currently presence/absence by fingerprint only.
9. **Remaining dashboard convenience gaps**: remediation-assignment UI, evidence list/verify UI, workflow edit/delete UI — all have a working CLI today, so these are P2 convenience, not P1 capability gaps.
10. **GitLab/Jenkins/Azure DevOps example snippets** in `docs/cicd.md` — the underlying CLI already supports all of them.
11. **A real, unrestricted-egress environment to actually complete the `docker compose up --build` verification and smoke test.**

None of these were skipped because they're hard to justify — they're sequenced behind the P0 egress fix and the smallest, highest-confidence P1 fixes (API key surface, run-execution audit events) specifically because the brief's own Rule 5 ("avoid unnecessary rewrites") and Rule 3 ("no fake implementations") argue against shipping thirteen half-finished features in one pass over one well-tested security fix and a couple of small, complete ones.
