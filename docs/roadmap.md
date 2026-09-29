# Roadmap

This file tracks what was deliberately deferred rather than silently stubbed,
per `docs/BUILD_SPEC.md` §0 rule 5 ("if you cannot implement something
properly within the phase, do not stub it silently — omit it, and record it
here with a reason").

## Phase 1 — Foundation (this build)

Delivered: repo layout, Docker Compose (postgres/redis/backend/worker/frontend),
FastAPI + Next.js skeletons, Argon2id auth (register/login/logout/me),
Organizations/Memberships/Roles with server-enforced RBAC, hash-chained
append-only audit log, Alembic migrations, Celery wired to Redis with a
placeholder task, and a real browser-driven register → create-organization
flow. Backend: 19/19 tests passing, ruff clean, mypy --strict clean, 92%
statement coverage. Frontend: ESLint, `tsc --noEmit`, Vitest (10/10), and
`next build` all clean.

Deferred out of Phase 1, with reasons:

- **`kervy-ai seed` / demo account seeding** — the Makefile intentionally has
  no `seed` target yet rather than one pointing at a module that doesn't
  exist. Lands with the demo lab (`docs/BUILD_SPEC.md` §19, Phase 12).
- **CLI (`kervy-ai`)** — Phase 10 per the merged phase plan
  (`docs/BUILD_SPEC.md` §26). The web app and REST API are the Phase 1–9
  surface; the CLI is a client of the same API, not a separate path.
- **GitHub Actions SHA-pinning** — `.github/workflows/ci.yml` pins actions to
  version tags (`@v4`), not commit SHAs. Full SHA-pinning
  (`docs/BUILD_SPEC.md` §23) is a Phase 11 supply-chain hardening item;
  fabricating an unverified SHA here would risk silently breaking CI, which
  is worse than a correctly-behaving version tag pending that pass.
- **Audit log table's append-only invariant is enforced by application code
  only** — no database-level `REVOKE UPDATE, DELETE` on the `audit_logs`
  table yet for the app's database role. Tracked for Phase 11 hardening
  alongside the rest of the security review.
- **Docker image builds were not verified end-to-end in this build
  environment** — `docker compose config` validates the compose file's
  syntax and service graph, and the Dockerfiles were reviewed by hand, but
  actually building `Dockerfile.backend`/`Dockerfile.worker`/
  `Dockerfile.frontend` requires pulling `python:3.12-slim` /
  `node:22-slim` / `postgres:16-alpine` / `redis:7-alpine` from Docker Hub,
  which this sandbox's network policy blocks (confirmed via the agent
  proxy's status endpoint: `connect_rejected — 403 to CONNECT — policy
  denial`, not a transient failure). The application itself **was**
  validated end-to-end for real: the backend was run under `uvicorn` against
  a live PostgreSQL + Redis, the frontend was built and run under `next
  start` against that backend, and a real browser-equivalent HTTP flow
  (register → session cookie → server-rendered dashboard → create
  organization → dashboard reflecting it → unauthenticated redirect) was
  driven with `curl` and passed. Building the container images themselves
  should be verified in an environment with Docker Hub access before first
  use (e.g. by the CI workflow, which runs in GitHub's own runners).
- **Rate limiting on auth endpoints** (`docs/BUILD_SPEC.md` §17.1: "login
  rate limiting") is not implemented in Phase 1. Noted here rather than
  silently skipped; add alongside the Phase 8 REST API hardening pass.
- **JWTs are not revocable server-side** — `auth.logout` only clears the
  session cookie; a bearer token obtained before logout remains valid until
  it expires (12 hours by default). This is a real limitation to carry into
  `docs/limitations.md` once that file exists (Phase 12/13 documentation
  pass), not something to silently fix with an unscoped session-blacklist
  abstraction in Phase 1.

## Phase 2 — Safety boundary (this build)

Delivered, test-first per `docs/BUILD_SPEC.md` §0 rule 4: the scope and
authorization engine (`app/core/scope/`) — the choke point every outbound
request must pass through. `RulesOfEngagement`/`Authorization`/`Budgets` as
pure, DB-independent dataclasses; `ScopeEngine.check()` (real pipeline,
consumes budget, halts the run on any hard violation) and
`ScopeEngine.explain()` (the dry-run/`scope explain` preview — identical
decision logic, never reserves budget or halts); `BudgetTracker` (atomic
request/token/cost/wall-clock reservation plus a concurrency semaphore);
`KillSwitch` (in-memory trip + sentinel-file check); `GatedTransport` (the
only place `httpx.AsyncClient`/`httpx.Client` may be constructed anywhere in
`app/`, enforced by a static test that greps the codebase and fails the
build otherwise — verified to actually catch a violation, not just pass
vacuously). `Target`/`Authorization`/`RulesOfEngagementRecord` persisted
models plus a REST API (target CRUD, RoE config, authorization grant
restricted to Owner/Admin per §17.2, and a `/scope/explain` dry-run
endpoint) — all RBAC-gated and cross-organization-isolated the same way
Phase 1's organizations API is.

Every case in the §6.3 mandated test matrix has its own test (not combined),
plus additional coverage beyond the minimum: IDN/punycode homographs,
userinfo-in-URL, DNS rebinding (proven by asserting the resolver was called
twice, not cached), cloud metadata IPs, RFC1918/loopback/link-local ranges,
explicit private-range allowlisting, path/method/header rules, all four
budget dimensions plus wall-clock and concurrency-under-load, blackout
windows, authorization absent/expired/not-yet-valid, RoE schema validation
failure, kill switch (in-memory and sentinel-file), and fail-closed behavior
on an internal exception — 84/84 backend tests passing, ruff clean,
mypy --strict clean, 99% statement coverage on `core/scope/` (target: ≥95%),
95% overall (target: ≥85%).

Deferred out of Phase 2, with reasons:

- **Redirect-target IP pinning (same-request DNS-rebinding TOCTOU)** — the
  engine re-resolves DNS fresh on every `check()` call, which catches a
  host's records changing *between* requests in a run (the DNS-rebinding
  test proves this). It does not pin the validated IP for the actual
  connection within a single request — `GatedTransport` lets `httpx`
  re-resolve DNS itself when it connects, which reopens a narrower,
  same-request TOCTOU window. Closing that requires connecting directly to
  the checked IP while preserving the original Host/SNI, a meaningfully
  larger piece of `httpx`/`httpcore` transport-level work. Tracked for the
  Phase 11 SSRF hardening pass rather than implemented partially or claimed
  as solved.
- **RPS (requests-per-second) pacing is not implemented** — `Budgets`
  carries `requests_per_second`, but only the request-count, token, cost,
  wall-clock, and concurrency dimensions are actually enforced in Phase 2.
  Actual rate-shaping (a token-bucket delay) plus a timing-based test would
  be inherently more flake-prone in CI than the other budget tests; add it
  deliberately in Phase 4 alongside the orchestrator's real request pacing,
  not as a rushed addition here.
- **Only one Authorization/RulesOfEngagement record per target** — granting
  a new authorization or setting a new RoE replaces the existing one
  wholesale rather than versioning a history. Simpler and safer than a
  half-built versioning model; revisit if the findings/evidence work in
  later phases needs to reference "the RoE that was active at scan time"
  for more than the most recent grant.
- **`/scope/explain` uses real system DNS in production** (`SystemDnsResolver`
  via a FastAPI dependency, overridden with a fake resolver only in tests)
  — this means a dry-run preview against a real target does a live DNS
  lookup, same as a real request would. That's intentional (an explain that
  used stale/cached data could mislead an operator about what would
  actually happen) but means `/scope/explain` is not fully side-effect-free
  at the network level, only budget/state-free.
- **No frontend UI for assets/scope yet** — Phase 2 is backend/API-only;
  targets, RoE, and authorization are managed via the REST API. The web UI
  for this (§18.3–18.6 in the spec) is deferred to land alongside Phase 3's
  adapter/discovery UI so it's built once against a more complete API
  surface rather than twice.
- **OpenAPI spec upload/parsing** — not part of Phase 2 despite appearing
  adjacent to "asset CRUD" in earlier phase-table drafts; it belongs with
  attack-surface discovery in Phase 3 (`docs/BUILD_SPEC.md` §26), which is
  where it's actually implemented.

## Phase 3 — Adapters & discovery (this build)

Delivered: the adapter layer (`app/core/targets/`) and OpenAPI attack-surface
discovery (`app/core/discovery/`).

- **Adapter protocols**, split into `ConversationalAdapter` (`send(turn)`)
  and `RestSurfaceAdapter` (`operations()` / `send_operation(...)`) over a
  shared `TargetAdapter` base. The spec (§8) defines a single chat-shaped
  protocol; that shape does not fit `http_openapi`, where the unit of work
  is "call operation X with parameters". Splitting it beat inventing a fake
  `Turn` for every REST call — recorded here as a deliberate deviation.
- **`chat_http`** (JSON request template + JSONPath extraction),
  **`openai_compatible`** (`/v1/chat/completions` and `/v1/responses`
  shapes), **`http_openapi`** (spec-driven REST). All send exclusively
  through `GatedTransport`, so the Phase 2 static check still proves no
  ungated HTTP path exists.
- **Provider-reported token usage feeds `BudgetTracker.reconcile()`**, so
  §6.2's "use reported usage when available, estimate otherwise" is real
  rather than aspirational — the estimate is replaced by the truth before
  the next budget check.
- **OpenAPI 3.x parser** treating uploads as hostile input: `yaml.safe_load`
  only, remote `$ref`s refused rather than fetched (an SSRF primitive aimed
  at the scanner host), cycle-safe and depth-capped local ref resolution,
  document-size and operation-count caps, malformed path entries skipped
  rather than aborting the whole import.
- **Surface API**: spec upload (extension/size/filename validation, stored
  in the database rather than the filesystem so path traversal is
  structurally impossible), endpoint listing, and per-endpoint enable/
  disable that survives a spec re-upload.

155/155 backend tests passing, ruff clean, mypy --strict clean, 94% overall
coverage (91% across the new `core/targets` + `core/discovery` modules;
`core/scope` still at 99%).

Deferred out of Phase 3, with reasons:

- **Real tokenizer** — `app/core/targets/tokens.py` is an explicit
  ~4-chars-per-token heuristic, not a tokenizer, and says so. It is only
  used for the pre-flight estimate that reported usage then replaces.
  Adding `tiktoken` (or equivalent) is a dependency decision worth making
  deliberately alongside the AI engine in Phase 6, not smuggled in here.
- **`graphql`, `mcp`, `websocket`, `cli_subprocess` adapters** — §8 lists
  seven adapters; Phase 3's acceptance criterion names three, and those
  three are what the API/AI engines in Phases 5–6 need. The remaining four
  land when there is an engine that actually exercises them, rather than
  shipping four untested integration surfaces now.
- **Live discovery (probing well-known spec paths on a target)** — surface
  discovery is currently spec-upload-driven only. Fetching
  `/openapi.json` from a live target is a scope-gated request like any
  other and is straightforward to add; it is deferred to Phase 4, where the
  orchestrator that would run it exists.
- **Request-body parameter schemas are captured as content types only** —
  the parser records *which* media types an operation accepts, not the full
  inlined body schema. Generating valid/invalid request bodies from those
  schemas is the input-validation probe's job (§10, Phase 5), which is
  where the schema walk belongs.
- **No frontend UI for surface review yet** — same reasoning as Phase 2's
  scope UI deferral: both land together against a settled API surface.

## Phase 4 — Assessment engine (this build)

Delivered: `AssessmentRun`/`RunEvent` models with an append-only, sequenced
event log; a DB-free orchestrator (`app/core/orchestrator/`) that turns a
list of checks into a terminal run status; a Celery task that executes a run
in a worker process and persists progress as it goes; cross-process
cancellation carried over Redis into a latching `KillSwitch`; and the runs
REST API (create, list, get, events, cancel, and SSE progress). Backend:
184/184 tests passing, ruff clean, `mypy app` clean, 96% statement coverage
(scope engine still 100%, runs router 100%).

Two design points worth stating, because both are honesty requirements from
the spec rather than implementation details:

- **A halt is not automatically a failure.** Budget exhaustion ends a run as
  `completed` with a `halted_reason`, because the run did everything its
  budget permitted and the report must say so; an operator cancellation ends
  it `cancelled`; an authorization that lapses mid-run ends it `expired`.
  Only a check that raises produces `failed`.
- **Progress is never faked.** The SSE stream replays persisted `RunEvent`
  rows and nothing else, so a browser can never show progress ahead of the
  work, and it closes only once the run has reached a terminal status.

Two bugs found by running a real Celery worker rather than only the test
suite, both fixed here and both now covered by `tests/test_workers.py`:

- The worker registered no assessment task at all (`include=` was missing
  from the Celery app), so it started cleanly and discarded every queued run
  as "unregistered task" while the API kept reporting those runs as queued.
- Each Celery task runs under its own `asyncio.run`, and an asyncpg
  connection belongs to the loop that opened it, so the *second* run in any
  worker process died with "attached to a different loop". The task now
  disposes the engine before its loop closes.

Deferred out of Phase 4, with reasons:

- **The acceptance criterion "runs end-to-end against the demo lab" is met
  against a mocked target, not a lab.** The demo lab is Phase 12
  (`docs/BUILD_SPEC.md` §19, §26) and does not exist yet. The full path —
  API create → broker → worker → scope-gated requests → persisted events →
  terminal status — is exercised in `tests/test_runs_api.py` with the
  network faked at the `httpx` boundary (so the scope engine, budgets and
  transport are all real), and was additionally driven through a live Celery
  worker against Postgres and Redis by hand during this build. That is not
  the same as a lab, and is recorded here as the gap it is.
- **Only one check ships (`core.reachability`).** It issues one request per
  enabled endpoint and records the status or the scope rule that refused it.
  It is deliberately not a security test: the AI and API probe catalogues
  are Phases 5–6, and inventing probes now would pre-empt that work with
  untested ones. The check protocol it implements is what those catalogues
  plug into.
- **Live discovery (probing well-known spec paths) did not land here** — it
  was deferred *to* Phase 4 in the Phase 3 notes above. The orchestrator now
  exists, but the useful form of it is a check in the catalogue rather than
  a one-off, so it moves to Phase 5 with the API engine.
- **Runs are not resumable and there is no retry policy.** A worker killed
  mid-run leaves the run in `running`; nothing currently reaps it. A
  heartbeat plus a reaper is an operational concern that belongs with the
  Phase 11 hardening pass, and inventing a half-reaper now would make stale
  runs *look* handled.
- **`requests_per_second` is still not enforced** (carried from Phase 2).
  Concurrency, request count, tokens, cost and wall-clock all are; pacing
  needs a limiter shared across worker processes, which arrives with the
  rate-limiting work in Phase 11.
- **No frontend UI for runs yet** — the runs API and its SSE stream are
  complete and exercised, but the dashboard surface lands with the scope and
  surface UIs, against a settled API.
- **Cancellation fails open if Redis is unreachable.** `is_cancellation_requested`
  returns `False` on a `RedisError` rather than stopping every run, which is
  the documented trade-off in `app/workers/cancellation.py`: a genuine
  cancellation also writes a terminal status to Postgres, and the run stays
  bounded by its budgets, authorization window and wall clock regardless.

## Phase 5 — API security engine (this build)

Delivered: a probe contract (`ScanResult` per §11.1, a `Probe` protocol and
an explicit registry), sixteen API probes covering OWASP API2 (authentication,
transport, key material in URLs), API1/API5 (BOLA and function-level
authorization via authorized synthetic accounts), API3 (mass assignment),
API4 (rate-limit advertisement, pagination limits), API8/API9
(security headers, CORS, verbose errors, debug endpoints, input validation)
and GraphQL (introspection, depth/aliasing cost, error verbosity);
credential *references* with worker-side resolution; a `ScanResultRecord`
table; probe execution wired into the orchestrator; and `GET
/runs/{id}/results`. Backend: 227/227 tests passing, ruff clean, `mypy app`
clean, 95% statement coverage (scope engine still 100%).

Four decisions worth stating, because each is a deliberate limit rather than
an oversight:

- **Mass assignment is analysis-only, in every mode.** §10 requires that
  under safe mode, and safe mode is what runs ship with. Confirming mass
  assignment means writing `is_admin: true` to a real record; a tool that
  does that to prove a point has caused the incident it was hired to find.
  The specification already says whether the field is bindable, so the probe
  reports it at `DESIGN_REVIEW` confidence, clearly labelled, and never as a
  confirmed exploit. With safe mode off it says explicitly that live
  confirmation is not implemented rather than quietly behaving the same way.
- **Authorization probes need a control, and say so when they cannot get
  one.** A BOLA test asks the owning account for its own object first. Without
  that, a 404 to the second account would be reported as "correctly denied"
  when the object may simply not exist, and an endpoint that returns 200 to
  everyone would be reported as BOLA. Where no synthetic accounts are
  configured, the probe emits an explicit "not tested" result — silence
  would read as a pass on the single highest-value check in the engine.
- **A credential is never stored.** The database holds the *name* of an
  environment variable, validated to look like one so a token cannot be
  pasted in by mistake; the worker resolves it at run time into a
  `CredentialSet` that exposes it only as a request header. A test asserts
  no credential value appears in any field a report is built from.
- **A crashed probe is a visible gap, not a silent pass.** A probe that
  raises produces an `KERVY-API-099` informational result and the run
  continues. Without it, a probe failing on every endpoint would look
  identical to a probe that found nothing — the most dangerous false
  negative a scanner can have.

Deferred out of Phase 5, with reasons:

- **The acceptance criterion is met against fixture apps, not the demo
  lab.** §26 asks for "every seeded API flaw in the demo lab; zero findings
  against a hardened control app". The lab is Phase 12 and does not exist, so
  `tests/lab/` contains two in-process applications — one carrying 17 seeded
  flaws, one built correctly — served through the real `GatedTransport` and
  the real scope engine with only the socket replaced. The engine finds all
  17 and reports nothing against the control, and removing a single
  hardening measure from the control app was checked to make that test fail.
  That is a genuine test of the engine; it is not a deployable, isolated lab,
  and this entry is the record of that difference.
- **SSRF (API7) is not implemented.** §10 requires a scope-controlled local
  collaborator in the lab, or a non-resolving canary domain against real
  targets, and is explicit that a target must never be pointed at a third
  party. The collaborator is lab infrastructure that arrives in Phase 12;
  shipping an SSRF probe without it would mean either no way to observe the
  callback, or pointing someone's API at a host we do not control. Neither is
  acceptable, so the probe waits for the lab.
- **JWT-specific authentication tests are not implemented** — `alg:none`,
  unsigned tokens, absent expiry. These need a token to manipulate, which
  means the synthetic-account credential, and the useful version of the check
  reasons about the token's structure. It belongs with the credential
  handling work rather than bolted onto the unauthenticated-access probe.
- **Spec/production drift and stale API versions (API9) are not
  implemented** — the parser records the declared surface and the probes
  exercise it, but nothing yet compares what the spec declares against what
  the server actually exposes. That needs live discovery (also deferred, see
  Phase 3/4 entries) to be worth anything.
- **No trials, ASR or confidence intervals yet.** §7's machinery applies to
  probabilistic AI probes; every API probe here is deterministic, so a single
  observation is the whole result and an ASR would be theatre. The machinery
  lands with the AI engine in Phase 6.
- **Results are not yet findings.** `ScanResultRecord` stores the §11.1 wire
  shape. Fingerprinting, risk scoring, severity rationale, mapping versions
  and lifecycle are the findings service in Phase 7, and the API deliberately
  returns no risk score rather than inventing one at the boundary.
- **No frontend UI for results yet** — same reasoning as the scope, surface
  and runs UIs: they land together against a settled API.

## Phase 6 — AI security engine (this build)

Delivered: the trials/baseline/ASR machinery (Wilson score intervals, an
explicit decision rule, stability classification) with a determinism harness;
eleven AI probes covering LLM01 direct injection (six techniques), LLM02
disclosure, LLM08 hidden context, LLM10 output handling, LLM06 consumption and
LLM03 excessive agency with a Mermaid permission graph; a standalone
redaction module; a judge that ships **disabled**; adapter configuration on
the target; and the AI engine wired into runs. Backend: 276/276 tests
passing, ruff clean, `mypy app` clean, 95% statement coverage.

Decisions worth stating:

- **The judge ships disabled, and that is the outcome, not a gap.** §7.3 says
  "an uncalibrated judge does not ship". Publishing precision and recall we
  have not measured would be worse than having none, so `JudgeConfig` cannot
  be enabled without a `Calibration`, enforced by the type and by a test.
  Every detection in this engine is marker-based or structural.
- **Every payload is a canary request.** A probe succeeds when this run's
  random marker comes back — never by eliciting harmful output (§2.2).
  Nothing in `direct_injection.py` is a jailbreak; the techniques tested are
  structural (override, role framing, delimiter confusion, hierarchy,
  encoding, language switching), which is what prompt-handling is supposed to
  withstand and which an instruction as innocuous as "say this word" tests.
- **Output handling deliberately does not use the ASR decision rule**, and
  says so in the finding. The adversarial component there *is* the structure,
  so a control with the structure removed is a plain-text echo — which an
  application that escapes correctly would also return. Applying the rule
  anyway would report a reliably vulnerable target as clean, so the probe
  reports deterministic reachability and carries the echo rate as context.
- **A tool surface is never guessed.** An empty declaration means "not
  declared", so the agency probe reports "not tested" rather than a clean
  permission graph. Architectural findings are valid at `DESIGN_REVIEW`
  confidence: an agent holding an irreversible external tool behind no
  confirmation is a real finding, and establishing it by triggering the tool
  would cause the irreversible effect being warned about.

Three bugs found while building, each now covered by a test:

- The trial driver **pooled trials across different techniques**, so one
  framing that worked every time and two that never did averaged into
  "inconclusive" — reporting a reliably exploitable target as clean. It now
  measures each technique separately and reports the strongest, naming it.
- `measurement_evidence` printed **raw response text**, so a credential the
  target disclosed reached the finding. Redaction now happens once, in the
  driver, when a trial is recorded — for every AI probe, not just the one
  looking for secrets.
- `.capitalize()` on a prompt containing the canary **lowercased the marker**,
  which silently made the affected controls unable to ever succeed.

Deferred out of Phase 6, with reasons:

- **The acceptance criterion is met against fixture apps, not the demo lab**
  (same as Phase 5). `tests/lab/ai_handlers.py` holds a seeded-vulnerable chat
  app and a hardened control, served through the real adapter, transport and
  scope engine with only the socket replaced. The engine finds all 11 seeded
  flaws and reports nothing against the control; removing one hardening
  measure from the control was verified to fail that test. They are
  deterministic stand-ins for model behaviour, which is what lets the test
  measure the engine rather than a model's variance — the statistics are
  covered separately by the determinism harness.
- **Indirect/cross-domain injection (LLM01) is not implemented.** §9 requires
  its carriers to be "served from the local content-server lab component
  only", and that component is Phase 12. Serving hostile HTML/PDF/DOCX from
  anywhere else to prove the path would mean planting attacker-controlled
  content somewhere we do not control.
- **LLM09 vector/embedding weaknesses are not implemented** — §9 restricts
  active poisoning to an authorized lab ingestion path, which does not exist
  yet.
- **LLM04/LLM05 supply chain and poisoning are not implemented** — inventory
  and ML-BOM work belongs with the SBOM tooling in Phase 12.
- **Multi-turn escalation is not implemented** — §9 gates it behind
  `allow_multi_turn`, and the adapters do not yet carry conversation state.
- **`kervy-ai replay <finding-id>` (§7.2) is not implemented** — trial records
  carry the exact prompt and a redacted response, which is what replay needs,
  but the command itself is Phase 10 with the rest of the CLI.

## Phase 14 — AppSec engines: SAST, SCA, Secrets, IaC (this build)

The first phase of the reconciled plan (`docs/IMPLEMENTATION_PLAN.md`).
Delivered: the `code_scope` domain model and a fail-closed workspace
resolver; a subprocess tool layer; identifier verification; static
fingerprinting; four engines (Semgrep and Bandit for SAST, pip-audit for
SCA, a repository secret scanner, Checkov for IaC); a `CodeScanCheck` for
the orchestrator; and the code-scope API. A vulnerable repository fixture
and a hardened control repository sit alongside the existing app fixtures.

**Acceptance met.** Nine seeded flaws across four pillars are found in the
vulnerable fixture, and the hardened control produces **zero** findings.
Both directions were verified to have teeth: reverting one hardening measure
in the control (`yaml.safe_load` back to `yaml.load`) fails the control test.

Decisions worth stating:

- **An empty `allowed_paths` is refused, not read as "everything".** A
  checkout with no stated boundary may contain a second project or a
  developer's credentials. This is §6.2's fail-closed rule applied to a
  repository, and it is enforced in the `CodeScope` constructor so no code
  path can bypass it.
- **A repository over the size cap is refused rather than truncated.** A
  partial scan reported as a complete one is the dishonest outcome.
- **Semgrep runs offline against a bundled local ruleset.** `--config
  p/default` downloads rules, and a subprocess that reaches the network is an
  outbound path §6.3 governs just as it governs an `httpx` client. A registry
  ruleset remains available as an explicit operator choice. The bundled rules
  are deliberately few, per the addendum's limit on native rules, and include
  `kervy.ungated-http-client` — this platform dogfooding its own central rule.
- **Dependency advisory lookup is off by default.** Matching a dependency
  graph means sending the client's dependency list to whoever runs the
  advisory database. That is a disclosure an operator opts into per
  assessment, so the default reports the inventory and states plainly that no
  matching was performed — an empty result would read as "no vulnerable
  dependencies", which is a very different claim.
- **Bandit's B404/B603/B607 are downgraded to informational, not
  suppressed.** They flag the presence of an API rather than a misuse of it
  and fire on correctly-written code; a scanner whose clean state is
  unreachable teaches its users to ignore it. They stay in the result set,
  attributed and explained, and simply do not count as findings. The reason
  is written into each finding's own description.
- **Fingerprints use a code-span signature, never a line number.** Line
  numbers drift on unrelated edits, so fingerprinting on them would split one
  long-lived issue into a new finding on every commit that touched the file
  above it.
- **Secret detection reuses the Phase 6 detector stack.** Two
  implementations would mean two redaction policies, which is how the §13
  "never persist a secret" invariant gets broken.
- **Checkov findings outside the code scope are dropped.** Checkov is pointed
  at the workspace root and does not honour our scope natively, so the
  adapter re-filters its output. The scope boundary stays authoritative even
  when a tool does not enforce it.

### Phase 14b — repository checkout and run-pipeline wiring

The deferred half of Phase 14. A run against a target with a `repo_ref` now
clones the repository, scans it, persists the findings and deletes the
checkout.

`git` does not route through `GatedTransport`, so every control the transport
would have applied is applied before `git` starts:

- **The repository host must be explicitly allowlisted.** A `repo_ref` is
  operator-supplied and therefore untrusted input; without an allowlist it is
  a request-forgery primitive aimed at whatever the worker can reach. An
  empty `allowed_repo_hosts` permits nothing.
- **The resolved address is checked against the scope engine's own blocked
  ranges** via `is_blocked_ip`, not a second list. An allowlisted name that
  points at loopback, RFC1918 or `169.254.169.254` is still refused.
- **Only `https` and `file` are accepted.** `ext::` makes a clone arbitrary
  command execution; `git://` is unauthenticated plaintext.
- **Hooks are disabled, submodules are never fetched, and the terminal
  prompt is off**, so a repository cannot execute its own code, pull content
  from a host that bypassed the checks above, or hang waiting for credentials.
- **The checkout is deleted in a `finally`,** including when the clone fails
  part-way. A working copy of a client's repository is precisely what must
  not be left on a worker: it is the material the secret scan just found
  credentials in.

A host that fails these checks skips code scanning and records why in the run
event log; the rest of the assessment is unaffected.

Two bugs the end-to-end test exposed, both fixed:

- **The scope engine reported an ordinary DNS failure as
  `internal_error` and halted the whole run.** A hostname that does not
  resolve is a normal outcome, not an engine fault. It now has its own rule
  (`dns_resolution_failed`), still fails closed — without an address there is
  no way to prove the host is not internal — but no longer aborts an
  assessment because one host is dead.
- **A file-reading check was skipped once the request budget halted.** A
  budget bounds outbound requests; it is not a general stop signal. Checks
  now declare `requires_network`, and the code engines — which spend no
  requests — keep running after a budget halt. An operator cancellation still
  stops everything.

Still deferred:
- **Container image and CI-artifact scanning are not implemented.** The
  addendum lists both as secret-scanning surfaces. They need an image-pull
  path, which is the same missing piece as the checkout above.
- **CodeQL is not integrated** — §15 requires verifying its licence before
  integrating, and that verification has not been done.
- **No cross-engine deduplication.** A SAST finding and a DAST finding
  describing the same underlying defect are two findings. The addendum
  explicitly puts this out of scope for v1; faking a correlation heuristic
  would be worse than the honest gap. Correlation belongs with the findings
  service in Phase 7 and the AI layer in Phase 16.
- **`nist_ssdf` mappings are not yet emitted.** The key exists in the finding
  schema, but §3.4's discipline requires verifying each practice against a
  pinned source first, and that ingestion has not been done. Emitting
  unverified practice ids would be exactly the invented-mapping failure the
  spec forbids.
- **The run pipeline does not yet execute `CodeScanCheck`.** The check, the
  workspace builder and the API all exist and are tested; wiring it into
  `execute_assessment_run` needs the checkout step above to be meaningful,
  so it lands with it rather than shipping a code scan that can only ever
  scan an empty directory.

## Phase 16 — AI intelligence layer (this build)

Delivered: an `AIService` with a two-method provider abstraction
(`generate`, `structured_output`), an OpenAI-compatible provider covering
hosted and self-hosted endpoints, a deterministic fake provider used
throughout the tests, the autonomy ladder, versioned prompt templates, an
`AiDraft` table with an explicit accept step, and the assistant API.

The shape the whole layer enforces (Implementation Specification §10):

    Tool / Engine -> Observation -> Detection -> Finding -> AI interpretation

Decisions worth stating:

- **The provider call goes through the same gated transport as everything
  else.** The provider endpoint is infrastructure the operator configured,
  not a target — but that is not a licence to open a second way out of the
  process, and an AI subsystem is the likeliest place for one to be added by
  accident. `platform_egress_context` builds a scope allowing the provider's
  host and nothing else, derived from configuration with no parameter a
  caller could widen. A provider endpoint resolving to the metadata service
  is refused exactly as a target would be.
- **`EXECUTE` is a mode, not a power.** The two source documents appeared to
  disagree about whether the assistant may execute anything; §4.5 row 7
  resolves it by asking *execute what*. Producing an artifact is something a
  mode permits; consuming budget, reaching a target, granting authorization
  or writing a finding's real fields is in `TARGET_TOUCHING`, checked
  independently of the mode so that raising the mode cannot grant one. There
  is no `execute()` on the service at all.
- **Evidence is fenced as data, and cannot close its own fence.** The
  material this layer summarises is adversarial by construction — it is
  harvested from injection probes, and the successful ones contain text
  written to redirect a reader. It is quoted inside a delimited block whose
  markers are stripped from the content, under a system prompt stating that
  nothing inside is an instruction. Passing it unfenced would repeat the
  mistake the platform tests its clients for.
- **Counts come from the platform, never from the model.** The executive
  summary is handed the severity counts and the untested list; a model asked
  to count would sometimes get it wrong, and a wrong number in an executive
  summary discredits the whole report.
- **An unreadable autonomy mode is treated as OFF, not as the default.** A
  typo in configuration must not silently grant more autonomy than the
  operator intended.
- **Accepting a draft is a higher privilege than requesting one.** Reading a
  suggestion is cheap; putting it into the record is not, so acceptance is an
  explicit act by a named person, recorded in the audit trail alongside the
  model and prompt template that produced the text.

One bug the boundary tests caught: `propose_scan` called the
target-touching guard unconditionally, so composing a command always failed.
The guard belongs where something tries to *act*, not where text is
produced.

Deferred out of Phase 16, with reasons:

- **Correlation and prioritisation are declared capabilities but not
  implemented.** Both need a `Finding` model with fingerprints and lifecycle,
  which is Phase 7. Correlating raw scan results would produce suggestions
  that cannot be acted on, and a "duplicate" suggestion across engines is
  exactly the cross-engine dedup already deferred in Phase 14.
- **Cost limits are configurable but not enforced.** `ProviderConfig`
  carries `max_cost_usd`, and the egress context carries a cost budget, but
  the OpenAI-compatible provider reports no cost because the wire format does
  not return one. Enforcing a limit against an estimated cost would be
  presenting a guess as a measurement, so the field is carried and the
  enforcement waits for per-model pricing data.
- **No CLI surface yet** (`kervy assist`, `kervy findings accept-draft`) —
  the CLI is Phase 10 and the API is the tested surface.
- **No structured-output use yet.** The provider implements
  `structured_output` and it is tested, but every current capability drafts
  prose. It exists for the correlation and prioritisation work above.
- **No import-linter configuration.** The "nothing in `core` outside
  `assistant/` imports it" contract is enforced by a test in
  `tests/security/test_assistant_boundary.py` rather than by the linter; the
  linter config lands with the rest of the Phase 11 tooling.

## Phase 7 — findings & risk (this build)

Delivered: the Kervy risk model with published ordinal tables, fingerprinting
that survives across runs, normalization from `ScanResult` into a stored
`Finding`, promotion wired into the run pipeline, and the findings API with
lifecycle transitions.

**Acceptance met.** §26 names two criteria and both are tested directly:
the fingerprint-stability test passes, and every finding carries a
`severity_rationale` that states the score it belongs to.

Decisions worth stating:

- **The score and its rationale are generated in the same call.** There is
  no path that produces one without the other, so a finding cannot carry a
  number nobody can account for. A rationale written beside a computed score
  drifts the first time either changes, and a reader who notices stops
  trusting both.
- **`docs/risk-model.md` is generated from the scorer's own constants.** A
  table maintained by hand is wrong the first time a weight changes, and §12
  requires the numbers to be published. A test asserts the document contains
  the values the scorer actually applies.
- **Likelihood uses the measured interval's lower bound, not the rate.** A
  3/5 success rate has a lower bound near 0.23; scoring it as 0.6 would treat
  sampling noise as an established fact. A probabilistic finding therefore
  scores below the identical deterministic one — which is the entire point of
  the Phase 6 measurement machinery reaching the risk number.
- **The fingerprint excludes response text**, per §11, and normalizes object
  ids, timestamps, canaries and short hex ids out of the surface and
  signature. Without that the same unfixed weakness becomes a new finding
  every run, the history is destroyed, and remediation has nothing stable to
  attach to. Both directions are tested: volatile detail collapses, and two
  genuinely different weaknesses stay distinct.
- **CVSS and AIVSS are left empty rather than manufactured.** §12 forbids a
  CVSS vector for "the model followed an injected instruction", which CVSS
  cannot express. An empty field is honest; a fabricated vector a reader will
  paste into a calculator is not.
- **A triage decision survives a re-run, with one exception.** Re-running a
  scan must not revert a human's judgement — except that something marked
  remediated which a later run still finds is reopened as confirmed, because
  a stale "remediated" on a live weakness is the most dangerous record in the
  system.
- **Transitions are restricted.** A finding cannot jump from `new` to
  `closed`; it has to pass through a state that records why, which is what
  makes a closed finding auditable months later. `remediated` leads only to
  `retest_required`, because a remediation is a claim until something checks
  it.
- **Exposure is read conservatively.** When the target's reachability is
  unclear the higher exposure is assumed: under-stating reach produces a
  comfortable number and an unpleasant surprise.

One bug the fingerprint-stability test caught: the hex-normalizing rule
required sixteen characters, so eight-character request and correlation ids
survived into the signature and would have produced a new finding every run.

Deferred out of Phase 7, with reasons:

- **`mapping_versions` is empty.** §3.4 requires each mapping to cite a
  pinned framework version with a retrieval date, and that ingestion has not
  been done. An unverified version string implies a check nobody performed,
  so the field stays empty and a test asserts it.
- **No evidence_ref yet.** The column exists; sealing evidence into a
  content-addressed bundle is Phase 8.
- **No cross-engine correlation.** Still the honest gap from Phase 14 and
  Phase 16: a SAST finding and a DAST finding describing the same defect
  remain two findings. The fingerprint now gives correlation something stable
  to work from, which is the prerequisite it was missing.
- **Exposure and impact are derived, not declared.** An operator cannot yet
  override the exposure reading for a target that is, say, behind a VPN the
  platform cannot see. The inputs are recorded on every finding so the
  derivation is visible and arguable; making it editable belongs with the
  remediation workflow in Phase 9.

## Phase 8 — evidence & reporting (done)

Evidence bundles are content-addressed, hash-chained and redacted before they
are written; reports render from one `ReportData` into Markdown, HTML, PDF,
canonical JSON, SARIF 2.1.0 and CSV across four audience templates; both are
downloadable only by a member of the owning organization, and every download
is audited.

Decisions worth stating:

- **Redaction happens before serialization, and the store refuses anything
  that got through.** `build_bundle` is the only sanctioned constructor, and
  `EvidenceStore.write` re-scans the serialized bytes and refuses the write,
  naming what tripped it. A bundle assembled by hand cannot be stored, so the
  guarantee does not depend on every future caller remembering.
- **A run's own canary is exempt from redaction.** This one was a bug the
  end-to-end test found, and it mattered twice over. The canary is a random
  16-hex-digit marker, so whether it happened to clear the entropy threshold
  decided whether a run could store evidence at all — the same target
  produced storable evidence on one run and none on the next. And redacting
  it destroys the evidence's whole point: a marker-based finding whose record
  reads `[REDACTED]` where the canary came back proves nothing. `find_secrets`
  now takes an `ignore` list, claims those spans first, and the driver, the
  bundle builder and the store all pass the run's markers through it.
- **Word boundaries came out of the secret patterns.** The property test
  defeated the old `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b` in one line:
  `AKIAIOSFODNN7EXAMPLE0` contains a complete AWS key id, but the trailing <!-- pragma: allowlist secret -->
  `\b` fails against the extra character and the value passed through
  unredacted. Adjacency must not be a way to smuggle a credential past the
  detector, so the issuer prefixes anchor each match and the quantifiers are
  open-ended. The cost is occasional over-redaction of a token that merely
  starts like a key, which is the right way round.
- **The detector's own verdict is redacted too.** Nothing guarantees a
  detector kept only a digest; one that quoted what it saw would have put a
  disclosed credential into the bundle by a route redaction never covered.
- **Content addressing makes a re-write idempotent, not observations
  interchangeable.** `created_at` is part of a bundle's content, so two
  separate observations of an identical exchange stay two bundles. They were
  two trials, and collapsing them would understate the measurement. Writing
  the *same* bundle twice is one file and one chain entry.
- **Verification checks the chain and re-hashes the files.** The chain alone
  catches a removed or reordered entry; re-hashing catches one whose bytes
  were edited in place. Both failures are tested by doing the tampering.
- **The SARIF schema is the real OASIS one, vendored.** `tests/schemas/`
  holds the 2.1.0 schema fetched from the spec repository, with a README
  explaining why: an approximation would pass output the spec rejects, and
  fetching it at test time makes CI depend on the network. A companion test
  breaks the document deliberately and asserts the validator complains, so
  "it validates" means something.
- **Golden snapshots for every format and template.** A report is the
  artefact that leaves the platform, so a silent change to its wording,
  ordering or structure is a change to what an organization believes it was
  told. `UPDATE_GOLDEN=1` re-records them and the diff has to be read.
- **`level` is not severity, and the fingerprint travels.** SARIF has four
  levels and this platform has five severities; critical and high both map to
  `error`, with the Kervy score kept at full resolution in `properties`. The
  Phase 7 fingerprint becomes `partialFingerprints`, without which a code
  host shows every run's findings as new.
- **Two honesty gaps the templates closed.** The developer template had no
  coverage section, so a developer would have read a findings list with no
  statement of what the run did not look at; framework coverage is now in
  every template for its "not tested" half. And a finding with no measurement
  printed no rate at all, which a reader seeing rates on the finding above it
  could fairly read as a measured zero — it now says "not measured" and why.
- **Reporting does not import the assistant.** The boundary test caught an
  import of the assistant's evidence delimiters in `reporting/build.py`.
  Stripping a prompt artefact is the assistant's job where it stores a draft,
  not reporting's where it renders one; which sections a draft contributed is
  read from the `ai_drafts` rows.
- **A report is refused before the run has executed.** A document full of
  zeroes from a queued run reads like a clean result. A report from a
  *running* one is allowed and says so in its limitations.
- **Evidence download needs analyst, reports need viewer.** A bundle is
  redacted but still the closest thing kept to the raw exchange, and a
  read-only reporting account has no need for it. Both are 404 rather than
  403 for a non-member, and both are audited.

Deferred out of Phase 8, with reasons:

- **No encryption at rest, at the time.** §13 makes it optional, and a
  half-built implementation with an undocumented key model would have been
  worse than none — an operator would believe the evidence was protected
  while the key sat beside it. Closed later (see "Evidence encryption at
  rest" further down this file) with exactly the key model this deferral
  was waiting to have decided: one static key from an environment variable,
  the same trade this project already made for every other secret it holds.
- **Evidence is only produced by the AI engine.** The AI driver has the whole
  exchange, so its findings carry bundles. The API and AppSec engines record
  their evidence as text on the result; giving them structured bundles needs
  the request/response to survive into `ScanResult`, which is a change to
  those engines rather than to the store. Findings without a bundle carry a
  null `evidence_ref` rather than a reference to nothing.
- **PDF needs an optional extra.** WeasyPrint is in a `pdf` extra because it
  needs system Pango and Cairo; CI installs it so the path is exercised, and
  the endpoint returns 501 with the install hint rather than a 500 when it is
  absent.
- **Retest results are a placeholder section.** The template has the section
  and the renderer states that no retest has been recorded; the retest
  workflow itself is Phase 9.
- **No scheduled retention job.** `EvidenceStore.purge` performs a genuine
  delete and is tested, but nothing calls it on a schedule yet — retention is
  a policy the operator has no way to configure.

## Engine completion pass (done)

Prompted by a review of what the engine actually produced end to end, not by
a phase boundary. Three real defects came out of it.

- **The `Observation` → evidence bundle pipeline finally exists.** The gated
  transport's own docstring had promised it since Phase 2 and it was never
  built, so only the AI engine's findings carried downloadable evidence. API
  probe findings now carry the exchange behind them, and the AppSec engines
  carry the tool, rule and code span. 14 of the 17 findings the vulnerable lab
  produces now have verifiable evidence; the other three are read out of the
  specification and carry none *on purpose* — a bundle asserts "this was
  observed", and a finding nobody observed must not claim one. A test names
  those three, so a new probe cannot quietly join them.
- **Evidence withholds the other party's data where that is the finding.**
  A BOLA probe establishes that account B reached account A's object; storing
  that object would turn the evidence bundle into a copy of the records the
  probe was only supposed to prove were reachable. Bundles therefore default
  to *not* retaining the response body, and a caller opts in where the body
  *is* the finding — a stack trace, an echoed marker, a GraphQL schema. Both
  directions are tested.
- **`uri.lstrip("./")` leaked the checkout directory into every semgrep
  finding.** `lstrip` strips characters, not a prefix: `./src/app.py` became
  `src/app.py` as intended, and
  `/home/runner/checkout-a1b2/src/app.py` became
  `home/runner/checkout-a1b2/src/app.py`. The path is part of the §11
  fingerprint and a checkout directory is unique per run, so every static
  finding got a new identity on every scan — no dedup, no history, no "is this
  still there?" — and the worker's filesystem layout went into
  customer-facing reports. Now one shared `relative_to_workspace` resolves
  against the workspace and drops anything outside it, with a regression test
  that scans the same file from two checkout directories and asserts one
  fingerprint.

The audit also confirmed what was already right: the vulnerable lab yields 17
API findings and 23 static ones, the hardened control yields zero and zero
reportable, and all 17 API findings have distinct fingerprints.

## Phase 9 — remediation & retest (done)

A finding can be assigned with a due date, moved through the §11 lifecycle,
retested, and shown as reproduced or not reproduced with the evidence digests
either side.

Decisions worth stating:

- **A retest is a run.** It reuses `assessment_runs` with `kind=retest`, so it
  inherits the authorization gate, the scope engine, the budgets, the audit
  event and the evidence path rather than re-earning each of them — and cannot
  drift from them later. It also takes its own explicit
  `authorization_confirmed`: having scanned something once is not standing
  permission to scan it again.
- **There is no status column on a remediation task.** The finding's lifecycle
  is the single source of truth for security state; the task carries the work
  (assignee, due date, notes). Two state machines over one fact drift, and
  when they disagree nobody can say which one a report should believe.
- **`not_tested` is a first-class verdict, and it is why this phase needed a
  new table at all.** An ordinary scan cannot express an absence: a run that
  no longer reports a weakness looks exactly like a run whose probe never got
  to try. So a retest writes down what it set out to check and gives each
  finding a verdict — and a probe that was skipped, refused by scope, held
  back by safe mode, or cut short by a halt is reported as not tested, never
  as a fix. Two tests drive that path specifically.
- **"Did the probe run?" needed its own record.** The first implementation
  inferred it from whether the probe wrote any result, which is wrong in the
  dangerous direction: a probe that ran and found nothing writes nothing, so a
  genuine fix was being reported as `not_tested`. Runs now record
  `probes_executed` from the orchestrator's own check results. A run from
  before that column existed has an empty list and every verdict fails closed
  to `not_tested`.
- **The baseline is a snapshot, not a live read.** Both halves of the
  comparison move otherwise: the run overwrites a reproduced finding's
  `evidence_ref`, and someone triaging in the meantime changes its state. The
  run stores each finding's id, fingerprint, probe id, severity and evidence
  digest before it starts.
- **Only a finding that was awaiting a retest is closed by one.** Requesting a
  retest moves `remediated` → `retest_required`, which is the transition §11
  reserves for exactly this moment. A not-reproduced verdict then closes it and
  closes its task. A finding still `in_remediation` has not been declared
  fixed by anybody, and the platform will not declare it for them.
- **A report says which kind of claim it is making.** A retest renders the
  three verdicts with before/after digests. An assessment renders recurrence
  instead and labels it as the weaker claim it is, rather than implying it
  compared anything.
- **A retest naming an unknown finding is refused, not narrowed.** Quietly
  dropping a finding would report a clean result for work that was never
  checked.

Deferred out of Phase 9, with reasons:

- **No partial retest.** A retest re-runs the target's whole configured check
  set and then compares; it does not run only the one probe behind a finding.
  Narrowing the run would be faster but would change what the control
  comparison means, and the ASR machinery's controls are per-probe for a
  reason. Recorded as a performance gap, not a correctness one.
- **No notifications.** §17's `retest.completed` webhook and in-app events are
  not built; the verdicts are visible through the API and the report.
- **No SLA or ageing on the board.** Due dates are stored and returned, but
  nothing computes breach, and no effort or priority band is invented — the
  report is explicit that this tool does not estimate effort.
- **Before/after evidence is two digests, not a diff.** A reader can download
  both bundles and compare them; the platform does not render a structured
  difference between them.

## Phase 10 — CLI, API keys & CI/CD gate (done)

`kervy-ai` exists as a console script, organizations can mint scoped API keys
for CI, and `kervy-ai gate` / `kervy-ai ci` fail a build on a seeded critical
finding with the documented exit code.

Decisions worth stating:

- **The CLI is its own package, and a test enforces it.** §26 Phase 10
  requires the CLI to exercise the same API and scope engine as the UI rather
  than a weaker path of its own, and the strongest way to guarantee that is
  structural: `kervy_cli/` may import `app.core.gate` (pure logic over
  findings the API returned) and the shared enums, and nothing else from
  `app.core`. It holds no scope engine, no probe, no adapter and no database
  session, so the only way it can reach a target is to ask the API to — which
  means every request it causes passes the same authorization gate a browser
  session does. `tests/test_cli.py` asserts that rather than trusting it.
- **`--safe` is passed to the API, not honoured by the CLI.** A flag the
  client enforced by itself would be a second, weaker gate, and the one that
  matters would be the one nobody was looking at.
- **An API key cannot grant authorization.** Its scopes top out at security
  engineer, so it cannot create a target, amend an authorization, add a
  member, or mint another key. A credential living in a CI runner is the most
  exposed thing this platform issues, and the authorization grant is the
  human act that makes a scan lawful. A test mints an owner's key and proves
  all four are refused — without the role cap, every key an owner created
  would have been an owner key.
- **A key's authority is its scopes; the role is derived.** One source of
  truth. Carrying both a scope list and a role invites the two to disagree,
  and then nobody can say which the platform enforces.
- **The secret is SHA-256, not Argon2.** It is 256 bits of CSPRNG output, so
  there is nothing to brute-force; a deliberately slow KDF on every CI request
  would buy latency and no security. A password is the opposite case, which is
  why `app/auth/security.py` still uses Argon2id for those.
- **The gate refuses to fail a build on a single-shot finding.** §23 names the
  failure mode plainly — gating on unstable, low-confidence AI findings makes
  pipelines flaky and gets the tool switched off by the first adopting team —
  so `require_stability` defaults to deterministic and probabilistic only.
  Low-confidence, design-review and already-triaged findings are excluded for
  the same reason. Gating on single-shot results is possible, but has to be
  asked for.
- **Every exclusion is printed with its reason.** A gate that says "failed: 3
  findings" teaches people to add `|| true`; one that shows what it skipped
  and why is one they can argue with, and arguing with it is how it stays
  switched on.
- **An unknown setting in `security-gate.yaml` is an error.** A typo'd
  `max_hihg: 0` that silently did nothing would leave a team believing they
  had a gate they did not have.
- **`fail_on` is a threshold, not a set.** `[high]` also fails on critical: a
  gate that let a critical through because the list said "high" would be
  indefensible.
- **A refusal never exits 0.** Authentication problems exit 3, a scope refusal
  or a halted run exits 4, a bad configuration exits 2 — and only a real
  finding exits 1. Reporting "no findings" because the tool could not
  authenticate would be worse than having no gate.
- **`ci` gates on the run it started**, not on the organization's backlog,
  which would fail one team's build for another team's open finding.

Two bugs the tests caught, both about the gate saying something it did not
mean:

- `max_high: null` was being read as "use the default of 0", because the
  parser could not tell an explicit null from an absent key. The documented
  example uses null to mean "no limit", so the parser now distinguishes them.
- The gate initially matched `fail_on` exactly, so a config listing `high`
  would have passed a critical.

Deferred out of Phase 10, with reasons:

- **Four of the nine §23 workflows are absent, not stubbed.** `container.yml`
  needs images this repository does not yet build in CI, `lab-e2e.yml` needs
  the Phase 12 demo lab, `release.yml` needs the Phase 13 release process, and
  `framework-drift.yml` needs the pinned framework corpus from §3.4 that
  `mapping_versions` is still empty for. A workflow that exists and does
  nothing is worse than one that is honestly missing.
- **detect-secrets runs against a committed baseline.** A bare scan of this
  repository is red on day one — 31 files of migration revision hashes,
  environment-variable *names*, and the credentials the vulnerable lab fixture
  contains deliberately — and a job that is red from the start gets disabled
  rather than fixed. The baseline stores hashes, not values, and the step
  fails on anything new (verified by planting an AWS key and watching it
  fail). Running the CI steps locally before committing the workflow is what
  surfaced this; it also surfaced that the platform's own Semgrep rule fires
  on the gated transport and on the CLI's API client, both now suppressed at
  the line with a stated reason rather than by excluding the files.
- **Actions are pinned to tags, not SHAs.** §23 asks for SHAs; the existing
  `ci.yml` pins tags and changing that convention is a repository-wide edit
  that belongs with the Phase 12 supply-chain work.
- **Some §20 commands are absent rather than stubbed**: `init`, `test --probe`,
  `replay`, `frameworks`, `probes list` and `evidence purge`. Each needs an
  endpoint the platform does not have yet, and a command printing "not
  implemented" is still a command people script against — `kervy-ai probes
  list` returning nothing would read as "this build has no probes".
- **No OIDC.** §21 lists API-key *or* OIDC authentication; only the first is
  built.
- **No rate limiting on authentication endpoints**, which §21 also asks for
  and which remains the oldest open item on this list.

## Phase 11 — plugins & third-party adapters (done)

Entry-point discovery across the four §16 groups, an allowlist that is off
until an operator turns it on, a third tool adapter, and
`docs/plugin-development.md` whose example is the code the test suite actually
runs.

Decisions worth stating:

- **No sandbox is claimed, anywhere.** §16 says so and every file that touches
  plugins repeats it: a plugin is Python running in the worker process and can
  do anything a dependency can. Pretending otherwise would be the single most
  dangerous thing this subsystem could say, because an operator who believes a
  plugin is contained will install one they have not read.
- **What *is* guaranteed is narrower and checkable.** Nothing loads unless a
  package is named in `plugins.allowlist`; the contract hands a plugin a
  `RunContext` and a `GatedTransport` and no attribute on either yields a raw
  client; and bad metadata is refused at load. The scope claim is tested three
  ways — structurally (nothing reachable from the contract is an httpx
  client), behaviourally (a plugin pointed at an out-of-scope host gets
  nothing, and the mocked route is never called), and on budget (a plugin's
  requests are counted, so a one-request budget stops the second).
- **Discovery is off by default.** `pip install` must not be what decides which
  code runs inside the scope engine's process, so the policy loads nothing
  until `PLUGINS_CONFIG` points at a file that names packages.
  `KERVY_NO_PLUGINS=1` wins over everything: when something has gone wrong
  there should be exactly one thing to set.
- **A hash pin means "this build".** It is a digest over the installed
  distribution's `RECORD`, so a package silently replaced after it was pinned
  is refused. A name-only entry is weaker and allowed, because forcing
  operators to produce hashes they do not have would get them fabricated.
- **Attribution is not the plugin's to set.** `probe_id` and `probe_version`
  are overwritten with the plugin's own id and installed version, and any
  `evidence_bundle` it supplies is discarded. A plugin filing findings under
  `ai.injection.direct.instruction_override` would have an operator drawing
  conclusions about code that never ran; a bundle from a plugin came from
  somewhere the platform cannot vouch for. Both have tests that try it.
- **Every run that loads a plugin says so** — a banner in the run's own event
  log and an informational `KERVY-PLUGIN-900` result naming what loaded. §14's
  coverage honesty cuts both ways: silence about a plugin is as misleading as
  silence about an untested area.
- **One bad plugin does not lose the run.** An import that raises, a
  constructor that throws, a `run` that explodes — each becomes a recorded gap
  and the rest still run, the same principle the orchestrator already applies
  to probes.
- **Policy notes are kept apart from plugin refusals.** The first version put
  "discovery is off, no config set" into the refusal list, which meant every
  run on every deployment filed an event announcing that it ran no plugins.
  Refusals are per-plugin and belong in a run's history; the policy's own state
  belongs in the log.
- **Gitleaks is the third adapter, and it is not a duplicate of the secrets
  engine.** The built-in one reads the working tree, which is what an operator
  can fix today; gitleaks reads the git history, where a credential removed in
  a later commit still sits. A secret that was ever pushed is compromised, so
  the finding only gitleaks can see is the one that matters most. It passes
  `--redact`, and then hashes whatever arrives anyway rather than trusting a
  flag to stay set in a future release, and it deletes its own report file in a
  `finally` — that file lists where every credential is.

Deferred out of Phase 11, with reasons:

- **Only `kervy.probes` is consumed.** All four groups are discovered,
  validated and listed in the banner, but nothing yet runs a third-party
  detector, adapter or reporter: each needs a contract of its own (a detector
  needs the observation shape, a reporter needs the template API), and
  inventing three more contracts to leave unused would be worse than saying
  this.
- **No signature verification.** §16 says "signed/allowlist mode"; the
  allowlist half is built, with an optional hash pin. Sigstore verification
  belongs with the Phase 12 supply-chain work that also signs this project's
  own releases.
- **Gitleaks is untested against the real binary here.** It is a Go binary that
  is not installed in this environment, so the adapter's normalizer is tested
  against a recorded report and the absent-tool path is tested for real. That
  is the same position the other tool adapters were in before CI installed
  them.
- **The secrets baseline was wrong when Phase 10 shipped, and is fixed here.**
  It was generated from `git ls-files` before the Phase 10 files were tracked,
  so `kervy_cli/config.py` (an environment-variable *name*) and the api-keys
  migration's revision hashes were never recorded — `security.yml` would have
  been red on the commit that introduced it. Running the job locally after each
  change is what caught it, and is now the habit: a CI job is not done when it
  is written, it is done when it has been seen to pass on the tree it will run
  against.
- **`--no-plugins` is a deployment switch, not a per-run flag.** Disabling
  plugins for one run would mean carrying the choice on the run row and through
  the worker; it is not clear anyone wants that, and guessing would add a
  column that has to be maintained forever.

## Phase 12 — demo lab & hardening (done)

`demo-target/` runs three services on a network with no route off the host, an
authorization pass walks the real route table, and `docs/security-review.md`
states what is covered and what is not.

Decisions worth stating:

- **Isolation is enforced in code, not described in a README.** The lab refuses
  to start if any of thirteen provider-credential variables is set, binds
  loopback unless `LAB_HOST` says otherwise, uses a stub with no HTTP library,
  and prints a banner. Each is a test. The credential check matters most: this
  app follows injected instructions and renders model output as HTML, so
  pointed at a real model with a real key, a prompt-injection demo becomes a
  bill or an exfiltration path into somebody's actual account. `env_file` is
  deliberately absent from the compose services so the project's own `.env`
  cannot supply one.
- **`internal: true`, and no published ports.** Docker attaches no gateway to
  `lab_net`, so the lab reaches nothing and nothing reaches it; the worker joins
  that network as well as the default one, which is how the scanner reaches the
  lab while the lab reaches nothing. A vulnerable app on a host port is a
  vulnerable app on somebody's network.
- **The authorization pass enumerates routes rather than reading a list.** For
  every organization-scoped route it asserts a declared minimum role, 401
  unauthenticated, 404 (not 403) to a non-member, and 403 below the declared
  role. A new endpoint cannot join the API without RBAC, because nothing has to
  remember to add it.
- **The route→role table is pinned.** Found by breaking it: downgrading a route
  from analyst to viewer passed every other assertion, because a weakened route
  enforces its weaker declaration perfectly well. A privilege change now has to
  be deliberate, where a reviewer sees it.
- **Cloud metadata endpoints can no longer be allowlisted.** This came out of
  thinking through how the worker reaches a lab on a private network. Private
  ranges are overridable on purpose — an internal staging host and the lab both
  live there — but `169.254.169.254` is not a target, it is what hands out the
  credentials of the machine this platform runs on. Until this change a wide
  `allowed_ip_ranges` would have permitted it. Tested with allowlists as broad
  as `0.0.0.0/0`.
- **`lab-e2e.yml` runs the lab under uvicorn, not Docker.** The test then
  exercises real sockets, real DNS and the real scope engine without CI needing
  a container runtime — and it has to list `127.0.0.0/8` in the target's Rules
  of Engagement, which is the same opt-in an operator makes for the Docker
  network. The counterpart test empties that list and asserts the run observes
  nothing.
- **The demo target is scanned on different terms from the products.** A HIGH
  finding fails the build for the backend and worker images; the lab is scanned
  for base-image and dependency problems only, because failing on its own
  findings would be failing on the thing it was built to be.

Two test-expectation bugs of my own, worth recording because both were wrong in
the direction of a false pass:

- the lab e2e asserted `KERVY-API-001` (unauthenticated access). The lab *does*
  require authentication on `/api/orders/{id}`; its flaw is skipping the
  ownership check afterwards. The assertion now names `KERVY-API-050` (BOLA),
  which required configuring the lab's synthetic accounts — so the test now
  exercises credentials-from-environment too.
- the "no opt-in" test asserted zero reportable results, and two appeared. Both
  were the analysis-only probes that read configuration and specification
  without sending anything, so their presence is not evidence of a bypass. The
  assertion now excludes them by name and adds the stronger check: no result
  carries an evidence reference, because nothing was observed.

Deferred out of Phase 12, with reasons:

- **No Sigstore signing and no `release.yml`.** Signing is only meaningful with
  a release process to attach it to, and that is Phase 13.
- **`framework-drift.yml` absent.** It needs the pinned framework corpus from
  §3.4 that `mapping_versions` is still empty for; a weekly job checking
  versions nothing records would report drift against nothing.
- **`container.yml` is unverified here.** No container runtime in this
  environment, so the workflow is written from the Trivy action's documented
  interface and has not been seen to pass. Same honest position as the other
  Docker-dependent paths.
- **No ML-BOM.** §23 asks for one alongside the SBOM for lab models. The lab
  uses a string-handling stub rather than a model, so there is nothing to
  inventory — an ML-BOM listing no models would be a claim, not a document.

## Later phases

See `docs/BUILD_SPEC.md` §26 for the full phase plan. Remaining: Phase 13
(documentation & release), plus Phase 15 (DAST), 17 (workflows, dashboard) and
18 (RASP extension points) — and the integrations and Aikido-parity engines
described in the next section.

## Phase 15: DAST (done)

`docs/dast.md` is the reference. A scope-gated crawler for `kind: web_app`, plus
Nuclei and ZAP adapters whose template and scan-mode policy is derived from the
rules of engagement.

**The design decision this phase turns on.** The acceptance criterion is that a
crawl never *fetches* an out-of-scope URL discovered mid-crawl. The obvious
implementation satisfies that by accident — queue everything, let
`GatedTransport` refuse the bad ones later. This does not do that. A discovered
URL is checked **before it enters the queue**, because:

- a queue of out-of-scope URLs is itself a defect: anything that later iterates
  the crawl's state (a retry, a progress view, a future adapter handed "the
  discovered URLs") reaches them;
- "it would have been refused later" is not testable — an assertion about
  requests passes whether the check is early or late, while an assertion about
  the *queue* only passes when it is early;
- budget is finite, and a site linking to a thousand external URLs should not
  spend the run discovering they are all out of scope.

Both are proved by deliberately weakening the control: replacing the pre-queue
check with "queue everything" fails
`test_an_out_of_scope_url_discovered_mid_crawl_is_never_queued`, and including
the mutating tags unconditionally fails
`test_the_default_policy_excludes_every_mutating_tag`.

**A distinction that was wrong at first and is now explicit.** Refused,
deferred, and unvisited are three different things. Budget says "not now"; scope
says "not ever". The first implementation filed a budget refusal under
`refused`, which tells a reader the engagement did not cover an in-scope URL —
a different and wrong claim. In-scope URLs are now queued regardless of budget
and surface in `unvisited`, reported as `KERVY-DAST-009`. A related off-by-one:
the page popped from the queue when budget ran out was lost from `unvisited`,
understating coverage by exactly one page; it is put back before the break.

**`allow_state_mutation`** is new on the rules of engagement (migration
`e4b1c6d83a29`), defaults to false, and is deliberately separate from
`safe_mode`: safe mode bounds how a probe behaves, this decides whether
state-changing tooling may run at all. The crawler never submits a form under
either setting — a test greps the module to confirm no code path sends anything
but `GET`. What the flag opens is the tool policy: Nuclei's intrusive tags and
ZAP's active script.

Out-of-band callback templates (`oast`, `interactsh`, `blind`) are excluded
**even with state mutation allowed**. They make the target contact a third-party
server the engagement never authorized, which is a separate decision from "may
state change" and one this platform has not built the infrastructure for.

**The honest limit of this phase.** Neither Nuclei nor ZAP is routed through
`GatedTransport` — they open their own sockets. Nuclei is mitigated by being
handed explicit `-target` URLs that each passed the scope engine at crawl time.
ZAP spiders on its own and cannot be bounded that way, so it runs only when the
rules of engagement name exactly one concrete host and declines with a visible
`not tested` marker otherwise. Recorded in `docs/security-review.md` too.

**One thing the existing tests caught.** Adding `web-app` to the lab's entry
point without adding it to `docker-compose.yml` failed
`test_every_service_the_entry_point_offers_is_in_the_compose_file` — a Phase 12
test written for exactly this drift. The compose service was added with the same
isolation properties as the rest (internal network, no published ports,
read-only, `cap_drop: ALL`), and because those assertions iterate `LAB_SERVICES`
they now cover it too.

**Deferrals, stated rather than hidden:**

- **No JavaScript execution.** No headless browser, so a single-page
  application's routes are invisible to the crawler. This is the largest gap in
  the phase.
- **No authenticated crawling** — no login sequence, no session handling.
- **No form submission at all**, even with `allow_state_mutation`.
- **Nuclei and ZAP are not installed in CI**, so their output parsing is
  exercised against fixtures and their absence against the `not tested` path.
  Nothing in CI runs a real scanner against a real site.
- **No ZAP daemon mode**, so no context configuration or session reuse.
- **Link extraction is a bounded regex, not an HTML parser** — deliberately, as
  the input is an adversarial response body, but it misses links a browser
  would find.

---

## Phase 13: documentation and release (done)

The §25 documentation set, and a v0.1.0 release prepared. The acceptance
criterion was behavioural rather than editorial — *"a fresh clone, following the
quickstart verbatim, reaches a scanned demo lab and a downloaded report"* — so
the quickstart was executed rather than written from memory.

**What the verification produced**, against a fresh database, the real Celery
worker, the real scope engine and the lab on a real socket:

```
run WITHOUT authorization        409  <- refused, as designed
run status                       completed
scan results                     10 results, 10 distinct codes
   KERVY-AI-000, KERVY-AI-020, KERVY-AI-900, KERVY-API-002, KERVY-API-010,
   KERVY-API-011, KERVY-API-013, KERVY-API-020, KERVY-API-021, KERVY-API-050
findings                         7
download report markdown/sarif/json  200
evidence chain verify            ok=True
```

The script that did it is committed as `docs/examples/quickstart.py`, so the
documentation and the thing that proved it cannot drift apart. It was then run
again from its committed form to confirm the shipped artifact works.

**Two things the verification found, both now documented:**

- *A scan without an uploaded OpenAPI document finds very little.* The first
  run produced 5 results; uploading the lab's own `/openapi.json` took it to 10.
  Not a bug — the API probes derive their surface from the document — but a
  reader following a quickstart that omitted the step would have concluded the
  target was nearly clean. It is now a step in the quickstart and the first
  entry in `docs/troubleshooting.md`.
- *Credential variables must be in the **worker's** environment, not the API's.*
  Synthetic accounts are stored by variable name, and the process that resolves
  a name is the one that makes the request. With them exported only in the API
  shell, BOLA (`KERVY-API-050`) silently did not appear: 6 findings instead of
  7. The run still completed and the coverage section still said what was not
  tested, so nothing lied — but it cost a re-run to notice, and it is now called
  out in three places.

**A definition-of-done item closed rather than documented as a gap.** §27
requires every framework mapping to be traceable to a pinned upstream version
with a retrieval date. `mapping_versions` was plumbed all the way to the report
but never populated — and a test, `test_mapping_versions_are_empty_until_verified`,
asserted the emptiness *deliberately*, on the grounds that an unverified version
string implies a check nobody performed. That was the right call at the time.
`app/core/findings/frameworks.py` now supplies the pinned editions with
retrieval dates, normalization derives each finding's versions from the mappings
actually present, and the placeholder test is replaced by three stronger ones:
every non-CWE mapping cites a version and a date, a framework with no references
is never claimed, and no entry carries an invented version or an unparseable
date. Verified in a live report, not only in a unit test.

CWE remains deliberately unversioned, and a test pins that too — CWE identifiers
are stable across MITRE's releases in a way the others are not, and a "CWE
version" would imply a precision that does not exist.

**Deferrals, stated rather than hidden:**

- **No v0.1.0 tag is pushed.** The release notes, CHANGELOG and documentation
  are ready, but tagging is an outward-facing, hard-to-undo act and this work
  lives on a feature branch. A `v0.1.0` tag belongs on the merge commit on the
  default branch, and that is the repository owner's call.
- **`docker compose up --build` is still unverified.** Docker Hub blob
  downloads are blocked at this environment's proxy (HTTP 403 from the registry
  CDN); that is a policy denial, not a transient error, so it was reported
  rather than retried. Stated in the README, `docs/installation.md` and the
  CHANGELOG rather than left for a reader to discover.
- **No Sigstore signing and no `release.yml`.** Both need a release process on
  a default branch to attach to.
- **No ML-BOM.** The CycloneDX SBOM covers software components only.
- **`docs/cicd.md` keeps its name** rather than the spec's `docs/ci-cd.md`;
  renaming would break existing links for no benefit.

---

## Requested after Phase 12: integrations and Aikido-parity scanning

Asked for directly: outbound integrations (mail, Slack, Teams) and repository
scanning comparable to Aikido Security. Planned as vertical slices:

1. **Integrations foundation** — *done, see below.*
2. **Slack, Teams, email and generic signed webhook** adapters, API, CLI —
   *done, see below.*
3. **Container image scanning**, **license risk** and **EOL runtime** detection
   — *done, see below.*
4. **Malware and typosquat signals** on dependencies — *done, see below.*
5. **Repository and pull-request integration** — *done, see below.*

### Slices 1 and 2: outbound integrations (done)

`docs/integrations.md` is the reference; this records what was decided and what
is deliberately missing.

**Four controls stand between an organization admin and an outbound request**,
because a channel is operator-configured data that produces an HTTP request —
the shape of an SSRF primitive:

1. Delivery goes through `GatedTransport` under a context whose
   `allowed_domains` is the one resolved destination host and whose
   `allowed_ip_ranges` is empty, so loopback, RFC1918 and the cloud metadata
   service stay refused — including the DNS-rebind case, since the engine
   re-resolves at send time.
2. The allowlist is derived from the resolved destination, never passed as a
   parameter. Same property as `app/core/assistant/egress.py`, for the same
   reason.
3. Vendor kinds are pinned to vendor hosts (`hooks.slack.com`,
   `*.webhook.office.com`, `*.logic.azure.com`).
4. A generic webhook host or SMTP relay must appear in an operator allowlist
   that lives in the **environment**, not the database. An admin picks among
   destinations an operator sanctioned; the database alone can never widen
   egress.

**Credentials are held by reference, as §5 requires.** A Slack incoming webhook
URL *is* a credential — the token is its path — so the channel row stores the
name of an environment variable plus a redacted display form
(`https://hooks.slack.com/…/…/…`). The migration has no column that could hold
a URL, a token or a password. Verified by a test that reads every column of a
stored channel row and asserts the token appears in none of them.

**Two things found while building this, both fixed:**

- *An error string was going to leak the webhook URL.* A transport exception
  quotes the URL it failed on, and that URL is a credential. Relying on the
  secret detector here would have been a mistake: a Slack webhook token is
  opaque random text matching no issuer pattern. So `scrub` strips URL paths
  outright before the detector runs, and every outcome passes through one
  wrapper rather than each `return` remembering to scrub. The test establishes
  the premise first — it asserts the plain redactor *does not* catch the token —
  so it cannot pass for the wrong reason.
- *A lazy relationship load in the notification worker.* `run.target.name`
  raises `MissingGreenlet` under asyncpg rather than quietly querying. Replaced
  with an explicit select. Caught by the fan-out test, not by review.

**Deliberate choices worth stating:**

- A payload that trips the secret detector is **refused**, not truncated. A
  delivery marked `refused` with a reason beats an alert missing the one line
  somebody needed.
- A refusal is never retried; only a transport failure is, four attempts across
  ~12 minutes, then `dead_letter`. A retry loop against a bad configuration is
  how rate limits get hit.
- A retry rebuilds the event from the delivery row's snapshot rather than
  re-reading the finding, so a "critical finding" alert cannot arrive about
  something a human already closed.
- An event whose severity cannot be ranked is **not** dropped. A missed security
  notification is the costliest failure mode here.
- Every attempt is audited, including the ones that never reached the network.

**Deferrals, stated rather than hidden:**

- `retest.completed` and `gate.failed` are defined event types that **nothing
  emits yet** — the retest worker and the CI gate are not wired to `enqueue`. A
  channel subscribed only to those receives nothing. Said plainly in
  `docs/integrations.md` too.
- **SMTP is not gated by `GatedTransport`**, because SMTP is not HTTP. The same
  `ScopeEngine` adjudicates the relay host first and STARTTLS is required, but
  the engine does not see that socket. A smaller guarantee than the webhook
  path has. `tests/security/test_scope_controls.py` now pins `smtplib` and
  `socket.socket(` to that one module, and the pin was proved to have teeth by
  planting a second import.
- **No SMTP integration test against a real relay.** The email path is covered
  at the unit level (policy, rendering, STARTTLS-required branch) and by the
  scope refusal, but nothing in CI speaks SMTP to a server.
- No per-channel rate limiting or digesting. A run that promotes fifty new
  criticals sends fifty messages.
- No Slack/Teams app with interactive actions — incoming webhooks only. Buttons
  that change a finding's state would need the assistant-layer restrictions
  thought through first, and §26 forbids an AI layer modifying a real finding.
- No delivery replay endpoint. A dead-lettered row is visible and carries its
  event snapshot, but re-sending it means a database change today.

### Slices 3 and 4: supply-chain scanning (done)

`docs/supply-chain.md` is the reference. Five engines, registered in
`app/core/appsec/registry.py`, all reporting the same `ScanResult` shape as every
other engine: end-of-life runtimes, dependency licence risk, name confusion, a
container dependency scan, and — added later, see below — known-malicious
package identification.

**The reason all four exist is that none of them has a CVE behind it**, which is
why an advisory-only scanner reports an affected repository as clean. An
end-of-life Python 3.8 base image gets no advisory. A licence obligation is not a
vulnerability. "Is this the package you meant" has no identifier at all.

**Restraint is the design, and it is what the tests check:**

- A runtime or series not in the vendored EOL table is reported as **not
  assessed** (`KERVY-SUPPLY-019`), never as supported. Every EOL finding carries
  the table's compile date, so "supported as of six months ago" is
  distinguishable from "supported today".
- EOL severity is **capped below CRITICAL**. A standing exposure is not a
  demonstrated exploit, and calling every old base image critical would devalue
  the findings that are.
- The licence engine reports **obligations, not violations**: whether AGPL
  matters depends on whether the product is distributed or hosted, which the
  scanner does not know. A missing licence classifies as unknown, never as
  permissive. Permissive dependencies get no finding at all, because one per MIT
  dependency buries the two that matter.
- Name-confusion findings are **signals at LOW/INFORMATIONAL with
  `DESIGN_REVIEW` confidence**, and a test asserts none of them contains the
  words "malware" or "malicious package". A test also pins that `dateutil` is
  *not* flagged against `python-dateutil` — that false positive is what would
  make the check unusable.
- The container engine scans the **filesystem, not a pulled image**, and emits
  `KERVY-CONTAINER-009` saying base layers were not examined. Pulling would mean
  reaching an unsanctioned registry as an outbound request the transport never
  sees, and materialising an untrusted image on the worker.

**Three things found while building this, all fixed:**

- *The licence engine classified almost everything as "unknown".* It read Trove
  classifier text (`License :: OSI Approved :: Apache Software License`) and
  trimmed the trailing word, producing `"Apache Software"` — not an SPDX
  identifier, so every such package fell into the unknown bucket, which is a
  useless output dressed up as a finding. Fixed with an explicit
  `CLASSIFIER_TO_SPDX` map and a lookup order of expression → short `License`
  field → mapped classifier. Caught by running the engine against the venv's own
  installed packages rather than by reading the code.
- *Transpositions were not detected.* `reqeusts` for `requests` is the commonest
  squat shape, and Levenshtein scores an adjacent swap as two edits — so the
  one-edit cap missed it, and raising the cap to two would have admitted
  genuinely different names. Added as its own check. The test asserts the
  premise (`edit_distance("reqeusts", "requests", cap=1) > 1`) so it cannot pass
  for the wrong reason.

- *An unrecognised base image was silently invisible.* `runtime_declarations`
  only emitted a declaration for images whose name mapped to a known runtime, so
  `FROM crystal:1.9-alpine` produced nothing at all — and nothing at all reads
  as "supported", which is the exact failure the not-assessed marker exists to
  prevent. Now any versioned base image yields a declaration under its own name
  and comes through as `KERVY-SUPPLY-019`. Caught by the test that asserts the
  not-assessed path, which failed on the first run.

**Deferrals, stated rather than hidden:**

- **No registry lookup**, so no true dependency-confusion detection ("does this
  private name also exist publicly?") and no new-maintainer or freshly-published
  signal. Both need an authorized outbound path and an operator's disclosure
  decision, the same shape as `pip-audit`'s opt-in.
- **No image-layer scan.** Recorded as a gap in the findings themselves, not
  just here.
- **No malware analysis in this engine.** It reports *where* install-time code
  runs; it does not analyse what that code does, and does not claim to. A
  separate engine now exists for the narrower, demonstrated case — see below.
- **No reachability analysis** on container findings, same as the existing SCA
  engine.
- **No licence policy configuration.** There is no way to declare "AGPL is
  forbidden here" and have the CI gate fail on it; findings are reported and a
  human decides. The gate already thresholds on severity, so wiring this means
  deciding whether a policy breach is a severity or a separate gate dimension.
- **A floating base image tag (`FROM python:latest`) or a digest-only pin is not
  reported**: neither declares a version, so there is nothing to compare against
  a support schedule. An unpinned base image is a real finding, just not this
  engine's.
- **Trivy is not installed in CI**, so `KERVY-CONTAINER-001` parsing is
  exercised only against the "tool absent" path there. The test asserts the
  honest-gap behaviour when Trivy is missing and the real parse when it is
  present, so the coverage is visible either way.

### Requested after Phase 15/17: malware scanning of dependencies (done)

`docs/security-review.md` carried "malware scanning of dependencies absent"
as an open gap. `appsec.supplychain.malware` closes it at a stated scope: a
new module, `app/core/appsec/supplychain/malware.py`, vendors 50 real GHSA
"type: malware" advisories (25 PyPI, 25 npm), each pulled live from
`github.com/advisories?query=type:malware` rather than invented, and dated
`AS_OF = 2026-09-25`. The engine (`malware_engine.py`) matches declared
dependency names against that table, normalized the same way
`typosquat.py` normalizes one, and reports a match at CRITICAL/HIGH — the one
supply-chain engine allowed to say "malware" outright, because a hit here is
a name match against a report GHSA already confirmed, not a resemblance
`typosquat_engine.py` is deliberately careful never to call malicious.

**Why vendored rather than queried**, same reasoning as `pip_audit_engine.py`'s
opt-in advisory lookup and `eol.py`'s local table: sending a client's
dependency list to a third party at scan time is a disclosure decision an
operator makes, not one a scanner makes quietly. The static
no-network-per-supply-chain-engine test now covers this engine too.

**The coverage-honesty pattern, made explicit rather than implied:** every run
with at least one declared dependency emits a single aggregate
`KERVY-SUPPLY-041` finding stating how many dependencies were checked against
how many table entries and as of what date — one note rather than one per
dependency, because the vendored sample here is minuscule next to a real
dependency list and a per-item repeat would say nothing the aggregate does
not. A dependency absent from the table is **not assessed**, never reported
as clean; `lookup()`'s own docstring says so, and a test pins that a `None`
result is not treated as a verdict.

**Deferrals, stated rather than hidden:**

- **Not a live feed.** 50 entries is a demonstration of the mechanism, not
  current coverage. Extending `TABLE` from OSV's `MAL-` advisories, a
  continuously-updated GHSA query, or an opt-in network lookup are the paths
  named in the module docstring for whoever wants that.
- **Name match only, no version awareness.** Matching entries are almost all
  purpose-built decoy packages with no legitimate release, so there is no
  "version 2.1 is fine, 2.2 is compromised" case to preserve here the way a
  hijacked legitimate package would need — unlike the EOL table, which does
  carry versions.
- **CHANGELOG's "no malicious-payload scanning of dependencies" limitation
  bullet is now false** and belongs removed from `docs/limitations.md` and the
  next changelog entry — left alone in the 0.1.0 entry itself, since that tag
  point predates this engine.

### Slice 5: pull-request integration (done)

`docs/pull-requests.md` is the reference. A run's findings are posted to a
GitHub pull request as a check run with inline annotations, and the conclusion
comes from the **same `evaluate()` the CI gate uses**, so a pull request and a
pipeline cannot disagree about whether the same findings are a blocker.

**The boundary is the design.** This layer reads a pull request and posts a
check run. It cannot push a commit, merge, update a ref, write a file, approve
or request changes — enforced three independent ways rather than asserted:
`GitHubClient` has no such method; a static test greps `app/core/vcs` for the
write verbs and the `/merges`, `/git/refs`, `/git/commits` and `/contents`
endpoints (verified against a planted violation); and the egress context allows
`GET` and `POST` only, so a call added later is refused by the scope engine
before it leaves the process. That is how "no autofix that pushes to a
customer's repository" stays true under future edits.

**Egress and credentials** follow the same pattern as notifications: a `github`
connection reaches `api.github.com` and nothing else, pinned in code so a
database row cannot redirect it; an Enterprise host needs
`KERVY_VCS_ALLOWED_HOSTS` in the environment; `allowed_ip_ranges` stays empty,
so sanctioning a host does not sanction an internal address behind it. The token
is held by env-var reference and appears in no URL, log, audit record, response
or error string.

**Annotations only where GitHub will render them.** GitHub accepts an
annotation only on a line the diff touches and silently discards the rest, so
each file's patch hunks are parsed for added lines and findings are filtered
against them. Anything unanchorable — untouched code, no line number, an HTTP
surface that is not a file, or overflow past the 50-annotation cap — moves into
the check run body rather than vanishing, and both counts are recorded.

**Two bugs found and fixed:**

- *A misconfigured connection returned a 500.* `resolve_destination` documented
  its refusals as `VcsError` but let `IntegrationError` escape from the shared
  secret resolver, so an unset token variable bypassed every caller's handler
  and surfaced as an unhandled exception instead of a message naming the
  variable. Caught by the test asserting the error names the variable.
- *An unknown `run_id` reached the foreign key as a 500 — and was a tenancy
  hole.* The publish endpoint did not check that the run existed and belonged to
  the caller's organization, so another organization's run id was
  distinguishable from a nonexistent one by the error it produced. Now both are
  404.

**Deferrals, stated rather than hidden:**

- **No webhook receiver.** Kervy does not listen for `pull_request` events and
  scan automatically; publishing is invoked by CI or by hand. Ingesting webhooks
  needs an inbound authenticated endpoint, replay protection, and a decision
  about what a push from a fork may trigger — worth doing deliberately.
- **GitHub only.** The contract is provider-shaped so another host is an
  adapter, but GitLab, Bitbucket and Azure DevOps do not exist today.
- **No re-posting or de-duplication.** Publishing twice for the same head SHA
  creates two check runs; the history records both and nothing updates the first.
- **`post_review` is implemented and tested but unused by `publish`**, which
  posts the check run alone: two writes mean two chances to half-succeed, and a
  review comment on a line the check run already annotated is the same message
  twice.
- **No test against a real GitHub API.** The client is covered against a fake
  transport that replays canned responses, and the diff parser against real
  patch text; nothing in CI speaks to github.com.

Deliberately out of scope, and recorded rather than half-built: cloud posture
management, runtime protection, and any "autofix" that pushes a commit to a
customer's repository.

## Phase 17 — workflows, dashboard & CI gate (done)

Two acceptance criteria, both structural rather than behavioural: *a
repository-change workflow runs the AppSec engines, normalises, correlates and
gates deterministically*, and **an AI recommendation cannot alter a gate
decision**. Plus §27's dashboard rules: no hardcoded values, and every visible
action works or is disabled with a reason.

`docs/workflows.md` and `docs/dashboard.md` are the reference; this records what
was decided and what was left out.

### The workflow is five stages, and no more

`trigger → plan → actions → evidence → result`. No branching, no user-defined
steps, no expression language. That limitation is the feature: a plan is a list
of actions the platform already knows how to run, derived from the trigger and
the target's configuration and nothing else, which is what makes `Plan.digest`
mean something. Two runs whose digests match would have done the same things, so
"did the plan change between these commits?" is a comparison rather than an
investigation.

Every action a plan *skips* is stored with its reason. A plan that silently
omitted the AI scan because no adapter was configured would leave a reader
unable to tell "nothing was found" from "nothing was looked for" — the same
coverage-honesty rule the reports follow.

### An AI recommendation cannot change a gate decision — three ways

Not a policy the code asks nicely about:

- `decide()` **has no parameter** for drafts, recommendations or suggestions,
  so there is no argument a caller could pass. Adding
  `drafts: Sequence[object] = ()` makes
  `test_the_decision_function_takes_no_recommendation_parameter` fail — which
  is how the property was verified, by adding it.
- It builds `GateFinding`s from each finding's real columns, and
  `app/core/workflow/result.py` never imports the assistant. Asserted by
  parsing the module's imports with `ast`, not by grepping its text — the first
  version grepped for `"assistant"` and matched the module's own docstring,
  which is a test that passes for the wrong reason.
- A draft proposing a different severity and a different status is stored,
  the gate is re-run, and the decision is byte-identical.

### A misconfigured gate never passes, at either end

Validated on write (422 at the endpoint, through the same `load_config` the CLI
gate uses, so `max_hihg: 0` is rejected where somebody typed it) and on
evaluation (a stored configuration that cannot be parsed makes the run
`refused`, never a pass, and never silently replaced by the default). Verified
by removing the validator and watching two tests fail.

### The dashboard is read-only, and that is the security decision

Every route under `/app` is a `GET`, asserted by a test that walks the route
table. The reason is the CSRF gap `docs/security-review.md` already listed: a
cookie-authenticated route that changed state would be forgeable. So the
dashboard renders the action, disables it, and states both the reason and the
API call that performs it. §27's *"every visible action works or is disabled
with a reason"*, met without pretending.

### A test that passed when it should not have

The first version of *"every number is a real query"* asserted against the
query object and the presence of a finding's title. Replacing a card's value
with a literal `0` **did not break it** — it was testing that the query worked,
not that the page used it. It was rewritten to read the card values and the
severity table back out of the rendered HTML and compare the whole set to the
query's output, and now fails on exactly that edit. Recorded because the
original would have shipped a green suite around a broken guarantee.

Five other controls were verified the same way, each by breaking it: adding a
`POST` route, hardcoding the severity breakdown, blanking the disabled-action
reason, making `blockers` always empty, adding a CDN `<script>` tag, and
removing `require_membership` from a page.

### HTMX is not vendored, and the reason is stated

The templates carry `hx-get` / `hx-target` and the handlers honour
`HX-Request`, returning the fragment instead of the page — one handler, one
query, two renderings. But `htmx.min.js` is **not committed**, and the base
template renders no `<script>` tag without it.

Two reasons. Fetching it here was refused by this environment's egress proxy
(403 — an organization policy denial, reported rather than worked around), and
independent of that, vendoring a minified third-party bundle into a security
product is a supply-chain decision that belongs to whoever checked its hash.
There is deliberately no CDN tag: unpinned third-party script on the page where
findings are read is exactly what this platform tests its clients for. A test
asserts every script a template loads is served by this application.

**Nothing breaks without it.** Every page is a complete server-rendered
document reachable by an ordinary link.

### Deferrals, stated rather than hidden

- **No inbound webhook endpoint.** `repository_change` and `pull_request` are
  valid trigger kinds and nothing accepts an event *from* a code host. That
  needs an authenticated endpoint with replay protection and a decision about
  what a fork's push may trigger. Drive workflows from CI, which already
  authenticates with an API key. (Same reasoning as the Phase-13 VCS deferral.)
- **No scheduler.** `SCHEDULE` is a valid trigger kind; nothing fires it.
- **Triggering a workflow does not queue an assessment.** It records the
  trigger, the plan and the gate decision over findings that already exist. The
  scan actions in the plan are executed by the assessment path — one code path
  for "run an assessment", not two. Wiring the trigger to queue one is a small
  change and is not made here, because it would mean a workflow could start a
  scan through a route the run endpoint's own checks do not cover.
- **The Next.js scaffold in `frontend/` remains and is not the dashboard.** It
  is the Phase-1 auth scaffold. It was not deleted, because deleting a working
  thing to make a claim tidier is not an improvement; it is recorded here as
  superseded for the dashboard's purpose.
- **The dashboard has no pagination.** Findings are capped at 200 and runs at
  50. An organization past that sees the newest, and the API is the complete
  answer.
- **No CSRF token, so no actions.** If one is added, these routes are where the
  actions go back, and the read-only test is what makes that deliberate.

## Phase 18 — RASP extension points & hardening (done)

The last phase, and the smallest deliberately. §26 asks for the
`runtime_protection` interface **only, no engine**, plus the §12 hardening pass.
Acceptance: *a RASP-effectiveness engine can be added without touching the
orchestrator or the scope engine; no RASP agent ships, and a static check proves
no unsafe-mode path exists for that interface.*

`docs/runtime-protection.md` and `docs/releasing.md` are the reference; this
records what was decided.

### The hard line, and how it is held

A RASP agent is code that loads into a running application and instruments it.
Shipping one means asking an operator to run this project's code inside their
production process, which §2 forbids outright. So there is no agent, no
bootstrap, no `sitecustomize`, no import hook, no monkey-patch.

The check scans **every** Python file under `app/`, not just `app/core/rasp/`:
an agent would not announce itself by living in the directory named after the
thing it must not be. It also fails on a file *named* `sitecustomize.py`, which
is how one loads without any code referencing it.

**It reads parsed source with docstrings removed**, and that detail is the
phase's main lesson repeating itself. The first version was a substring scan,
and it fired on the contract's own docstring explaining the rule — the same
grep-versus-prose mistake that made an earlier boundary test in this project
pass for the wrong reason, this time in the other direction. A control that
fails on its own documentation is a control somebody deletes. There is now a
test *of the scanner*: it must not fire on prose describing instrumentation, and
must fire on code performing it.

### A claim is never storable as a measurement

The interesting design decision. `ClaimedControl` carries a required
`evidenced` field with three values, and `__post_init__` **raises** on anything
but `claimed` — because nothing on this platform measures runtime protection,
and a record saying otherwise would carry that lie for the life of the row. The
API has no `evidenced` input field at all.

A future engine relaxes that constructor deliberately, together with the test
asserting it. Making it fail loudly now is cheaper than discovering later that
an unmeasured claim quietly acquired the word "observed".

A target that declares controls gets an explicit **"not tested"** line in every
run, with impact stated as *Unknown*. A test asserts the marker contains no
claim-shaped phrase and does positively say "did not measure" — and its first
version forbade the bare word "effective" and fired on the marker's own honest
sentence *"did not measure whether any of it is effective"*. A test that
punishes precise writing gets the precise writing removed, so it now matches
phrases, and the marker was reworded to remove even the ambiguity.

### No unsafe-mode path

`RuntimeProtectionContext` has no field that could relax a control, and the
protocol's methods take the context and nothing else — so an engine cannot be
handed its own transport. Measuring whether a WAF blocks something sounds like
it needs an escape hatch; it needs the engagement to authorize the request,
which the rules of engagement already decide.

Seven controls in this phase were verified by breaking them: adding `safe_mode`
to the context, planting a real `sys.meta_path` hook, shipping an engine class,
deleting the `evidenced` guard, removing the env-var-name validator, making the
marker always return `None`, and making the contract import the scope engine.

### The §12 hardening pass: the last two workflows

`framework-drift.yml` and `release.yml`, which had been listed as absent in
`docs/security-review.md` since Phase 12.

**The drift checker does not fetch.** Every outbound request in the application
goes through the scope engine's transport. A maintenance script that opened its
own connection would be a second HTTP path placed just outside the directory the
static check scans — worse than an obvious one, because it looks compliant. So
the workflow reads upstream with `gh api`, visible in the job log, and
`scripts/framework_drift.py` does the comparison, which is the part worth unit
testing. A test asserts the checker imports no HTTP library.

**A failed lookup is never "current".** The checker has four buckets, and
`unknown` exists so a GitHub outage or a renamed repository cannot make the
weekly job report that every pin is fine. Frameworks published as a web page
have no tag to compare, so they are reported by retrieval age instead —
reporting them as current would be reporting that the script did not look.

**Signing is keyless.** No long-lived key in a repository secret: a stolen one
works forever and rotating it means every consumer relearns it. Sigstore binds
the certificate to this repository, this workflow and this run.
`docs/releasing.md` shows the verification command **with `--cert-identity`**,
because verifying that *a* valid signature exists proves nothing.

A new `tests/test_ci_workflows.py` enumerates the nine §23 workflows rather than
trusting a prose list somebody has to remember to update — which is exactly how
those two stayed missing for five phases. It also asserts every workflow
declares its permissions and that none uses `pull_request_target`.

### Deferrals, stated rather than hidden

- **No release has been cut.** `release.yml` is written and its structure is
  asserted, but nothing has run it end to end, because that means publishing a
  real tag. `docs/releasing.md` says so in its own "what a release does not
  promise" section rather than leaving it to be assumed.
- **No container image signing or publishing.** Images are scanned; none is
  published, so there is nothing to sign.
- **No reproducible builds.** GitHub's attestation says what built an artifact,
  not that the build was hermetic. The docs do not claim otherwise.
- **The drift check cannot read a web-published framework.** OWASP API
  Security's edition pages and the NIST AI RMF have no machine-readable
  version. Those are surfaced by retrieval age, and a maintainer reads them.
- **No runtime-protection engine, and none planned here.** Phase 18 authorizes
  the extension point. Adding an engine is one line in
  `RUNTIME_PROTECTION_ENGINES` and a deliberate change to three tests, which is
  the whole point of the shape.

## Post-Phase-18: closing the definition of done

All eighteen phases were built, so this pass worked §27's checklist rather than
a phase. Four items were genuinely open; one of them was a gap this project
created for itself.

### The coverage section did not name DAST or RASP

§27's addendum is explicit: *the report's framework-coverage section names
SAST/DAST/SCA/Secrets/IaC/RASP explicitly whenever any of them were not run.*

It did not. The section was derived entirely from the engines' own "not tested"
markers, which **cannot** satisfy that requirement, because a pillar that never
ran emits no marker. DAST went unmentioned in every report for three phases and
RASP for one — added in Phase 15 and Phase 18 respectively, by me, without
either appearing in the one section whose job is to say what was not covered.
No test noticed, because nothing enumerated.

The fix is `PILLARS` plus `PillarCoverage`: a fixed list, one verdict per
pillar, every time. A pillar counts as tested only when a real, non-marker
result carries one of its probe-id prefixes — an engine that degraded to a "not
tested" marker tested nothing, and counting it would move the same lie to a
different part of the report. The untested pillars are now also named in the
executive summary, because "some areas were not tested" is how a gap goes
unnoticed by the person who reads one page.

Rendered in Markdown, HTML, PDF and the canonical JSON, so a consumer can tell
"DAST found nothing" from "DAST never ran" without parsing prose. Four controls
verified by breaking them; the golden snapshots were re-recorded and the diff is
additive.

**The lesson is the one this project keeps relearning.** Coverage honesty
derived from what produced output degrades to silence exactly when coverage is
worst. It has to be enumerated.

### A test-isolation race that only appeared under coverage

Five tests failed in a full run with `--cov` — which is how CI runs — while
every one passed alone, passed with coverage alone, and passed in a full run
without it. The symptom was a test watching its own freshly-registered user
vanish, failing several calls later with a confusing 401.

Cause: the autouse `TRUNCATE` ran as **teardown**. `TRUNCATE` takes an ACCESS
EXCLUSIVE lock and waits for any session an earlier test left open, and that
wait could outlast the teardown and land in the middle of the *next* test.
Coverage slows execution by about a quarter, which was enough to widen the
window.

It now cleans at **setup**. Same guarantee — no test sees another's rows — but a
blocked truncate delays the test waiting for it instead of sabotaging the one
already running. The only difference is that the last test's rows outlive the
session, which costs nothing in a disposable database.

This was pre-existing and unrelated to the phases' own work. It is recorded
because a flake that only bites under CI's flags is worse than one that bites
everywhere.

### The coverage gate is enforced, not reported

§24 sets three floors — ≥80% overall, ≥85% on `core/`, ≥95% on `core/scope/` —
and CI reported a number without failing on any of them. Only the overall floor
is expressible as `--cov-fail-under`, and on its own it is the weakest of the
three: a large, well-tested API surface keeps the headline healthy while the
scope engine, which is the entire safety boundary, rots underneath it.

`scripts/coverage_floors.py` enforces the per-package floors, with the scope
package counted against its own stricter floor rather than diluted into
`core/`. Measured before the gate was set, and met with real headroom:

| Package | Measured | Floor |
|---|---|---|
| `app/core/scope/` | 97.8% | 95% |
| `app/core/` | 91.6% | 85% |
| overall | 91.8% | 80% |

The floors are the spec's numbers, not today's. A floor set to wherever the
suite happens to sit can only ever be met.

### The ML-BOM, and why it is nearly empty

§27's addendum: *software SBOM and ML-BOM ship as separate labelled components
of one release artifact, never merged into one undifferentiated bill of
materials.* Only the software half existed.

`scripts/mlbom.py` writes the other half as its own labelled document. Its model
inventory is **empty**, and that is the answer rather than an omission: this
repository ships no weights, no checkpoints, no training data and no fine-tune.
Two things that could be mistaken for models are recorded as what they are — the
demo lab's assistant is a deterministic string function, and the AI layer calls
an endpoint an operator supplies at run time by environment-variable *name*. A
generator that padded the list to look complete would make the document
worthless for the one question it exists to answer.

It emits CycloneDX **1.6**, not the 1.7 §23 names, because `cyclonedx-python-lib`
tops out at 1.6 and the software SBOM is generated at 1.6 too. Writing "1.7"
into a document no 1.7 validator had checked would be a version claim nobody
verified. A test pins the emitted version to what the library can actually
produce, so the two halves cannot drift apart.

### Still open, and honestly so

- **The 10-minute `docker compose up --build` walkthrough is unverified.**
  Docker Hub blob pulls are refused by this environment's egress proxy (403, an
  organization policy denial), and no Docker daemon runs here. The compose file
  and its services are asserted by tests; the end-to-end timing claim is not.
- **No release cut**, so `release.yml` and `sbom.yml` have never run end to end.
- **CycloneDX 1.7** once the tooling supports it.
- **No auth rate limiting, no CSRF token, no server-side JWT revocation, no
  evidence encryption at rest.** All four were open when this line was
  first written; all four are now addressed in the "Post-Phase-18" sections
  below, in the order they were tackled. Evidence encryption stays opt-in
  by design, not a default — see its own section for why.

## Post-Phase-18: authentication rate limiting

The oldest open gap in `docs/security-review.md`, listed since Phase 12 and
named there as the one most likely to matter first in a real deployment.
Required by §18 ("login rate limiting") and §22 ("per-route rate limiting").
`docs/rate-limiting.md` is the reference.

### The decisions, and what each is defending against

**Two dimensions.** Per-IP alone falls to a botnet; per-identity alone falls to
spraying one password across many accounts. An attempt consumes from both.

**Throttle, never lockout.** A lockout triggered by failed attempts is a
denial-of-service primitive aimed at whoever the attacker names — knowing a
colleague's email would be enough to keep them out. A 429 with `Retry-After`
costs an attacker the same time and costs the victim a wait that ends by
itself. Only failures accumulate; a success clears the counters, because a
limiter that throttles legitimate users is a limiter somebody switches off.

**It must not become an enumeration oracle.** Budget is consumed *before* the
user lookup and identically for every address, so a throttled response cannot
distinguish a real account from one that was never registered. The login
handler was already careful about this, and a limiter bolted on afterwards is
the usual way that care gets undone.

**A client cannot choose its own bucket.** `X-Forwarded-For` is ignored unless
an operator declares how many proxies sit in front. Reading it by default gives
an attacker one fresh bucket per forged value — unlimited attempts, with the
configuration still reporting the control as on. That is worse than no limiter,
and it is the single most common way this control ships broken.

**The counter store holds no email addresses.** Identity keys are an HMAC under
a server-side pepper: an unkeyed hash of an enumerable identifier is reversible
with a wordlist by anyone who can read the store. Normalizing first matters as
much — without it the limit is one capitalization away from being doubled.

### The one boundary here that fails open

Everything else on this platform fails closed. This does not, and the asymmetry
is reasoned rather than convenient: a rate limiter sits *on top of*
authentication rather than being it, Argon2id still stands behind it, and
failing closed would turn a Redis blip into a total lockout of the product —
trading a bounded, already-mitigated risk for a total outage.

What it must never do is fail open *silently*. An unavailable store logs
`rate_limit_store_unavailable` at error level, and `docs/security-review.md`
says plainly that the control is only as reliable as the alert on that event.

### A pre-existing bug found on the way

The application's `HTTPException` handler rebuilt every error response and
**silently dropped `exc.headers`**. The 429 therefore arrived with no
`Retry-After` — telling a client it was throttled but not for how long. It
would have applied equally to `WWW-Authenticate` or `Allow`; nothing had
needed a header on an error until now. Fixed, and the rate-limit test is what
caught it.

Nine controls verified by breaking them: trusting `X-Forwarded-For` by default,
hashing the identity without a pepper, skipping normalization, dropping the
identity dimension, never clearing on success, failing open silently, shipping
the limiter off, enforcing after the user lookup, and dropping the exception
headers again.

### Deferrals

- **Only `login` and `register` are limited.** §22 asks for per-route limiting
  across the API; authenticated routes already require a credential and are
  bounded by RBAC. Extending is a table entry — the machinery is general.
- **Fixed window, not sliding.** An attacker can land up to `2 × limit`
  attempts across a window boundary. A sliding log closes that at the cost of a
  sorted set per key and a read of every entry, which under exactly the
  spraying attack this defends against is the memory profile that takes the
  store down. Bounded slack beats an unbounded blow-up.
- **No CAPTCHA, progressive delay, or device fingerprinting.**
- **`MemoryStore` is single-process only** and is not the default; two API
  workers would each enforce the full limit.

## Post-Phase-18: CSRF protection

Required by §18 ("CSRF protection where cookie-based sessions are used") and
§22, and the reason the Phase-17 dashboard shipped read-only.
`docs/csrf.md` is the reference.

### The scope decision is the control

A token is required for unsafe methods authenticated **by cookie**, and for
nothing else. Both halves matter and they fail in opposite directions:

- too narrow, and the attack is wide open — the browser attaches the session
  for whoever asks;
- too wide, and every CLI invocation and CI gate breaks, for callers who were
  never at risk, because a cross-site page cannot attach an `Authorization`
  header to a request the browser sends on its own.

Enforced as **middleware, not a per-route dependency**. A dependency protects
the routes somebody remembered to decorate, and the one they forget is the one
that matters. The check narrows by the request rather than by a maintained
list, so a route added later is covered by default.

### Not plain double-submit, and the difference is the whole point

The textbook scheme sets a random value in a cookie and requires the same value
in a header. It rests on an attacker being unable to **read** the cookie — which
same-origin policy provides — but **not** on being unable to **write** one.
A sibling subdomain setting a cookie for the parent domain, or a MITM on a
plain-HTTP subdomain, supplies both halves and they trivially match.

So the token carries an HMAC over the session cookie's own value. A planted
pair does not verify against the victim's session, and a token minted for a
different session fails the same way — asserted end to end by taking a valid
token from one account and using it against another.

It is deliberately not the session token reused: that would put a credential
somewhere a page's JavaScript must read it, turning any injection bug into
session theft.

### A stale reason is a false statement

The dashboard's disabled controls said *"this platform has no CSRF token"*.
That became false the moment this shipped. Leaving it would have been a lie in
the product's own UI, of exactly the kind this project spends its effort
avoiding — so the reason was replaced: the dashboard is read-only because no
write handlers are built, which is a scope decision, not a security constraint.

`tests/test_web.py::test_every_dashboard_route_is_a_get` stays, but for a
different reason, now written down: `GET` being exempt from the CSRF check is
only sound while every dashboard route is one.

### A control I could not prove

Replacing `hmac.compare_digest` with `==` leaves the entire CSRF suite green.
A timing property is not observable from a functional assertion. The code is
correct, the test suite is not evidence of it, and both the module and
`docs/csrf.md` say so rather than letting a passing suite imply coverage.

Six of the seven controls here were verified by breaking them; that one is the
seventh, and it is recorded as unproven rather than quietly counted.

### Deferrals

- **Login CSRF is open.** `/auth/login` and `/auth/register` are exempt
  because no session exists to bind a token to, so an attacker can forge a
  request signing a victim into the *attacker's* account. Closing it needs a
  pre-session token issued to anonymous visitors. It is now the residual in the
  security review's gap table rather than an unnoticed hole.
- **No dashboard write actions.** The machinery a form needs is in place
  (`csrf_token` form field accepted), but no handler uses it yet. That is the
  natural next piece of work.

## Post-Phase-18: server-side JWT revocation

The next item in the security review's residual list. §18 asks for real
session/token management; a JWT with no server-side kill mechanism does not
have that — "logout" only cleared a cookie, and a leaked token stayed valid
for its full 12-hour default lifetime regardless of anything a user or
operator did about it. `docs/revocation.md` is the reference.

### Two mechanisms, chosen for what each is actually for

Per-token revocation (`/auth/logout`, a Redis deny-list keyed by `jti`,
self-expiring with the token's own remaining lifetime) scopes correctly to
one session — proven by logging in twice and killing only the first token.
Per-user revocation (`/auth/logout-all`, a Postgres cutoff timestamp) is the
compromise-response case: it kills every token ever issued to a user,
including ones it never tracked and never learned the `jti` of, by comparing
issuance time to a cutoff rather than enumerating anything.

The split between Redis and Postgres is deliberate and asymmetric. Losing a
single logout to a Redis restart is a bounded, tolerable regression — the
token becomes valid again for at most its own remaining life. Losing a "log
out everywhere" cutover the same way would silently undo a compromise
response, which is the one case that mechanism exists for, so it lives in
Postgres instead.

### The one control here that fails closed, and why that is a deliberate
### contrast with everything else Redis-backed on this platform

The rate limiter and the run kill switch both fail *open* on an unreachable
store — each sits on top of a decision something else still makes correctly
(Argon2id, the scope engine's budget checks), so a Redis blip must not widen
into a bigger outage than the risk being mitigated. Revocation is not that
shape: it **is** the authorization decision for a token that was deliberately
killed, and "could not check, so let it through" is exactly the failure a
revoked-but-still-working token represents. An unreachable revocation store
therefore refuses every JWT-authenticated request — the wider blast radius is
accepted on purpose. A single test file asserts both halves side by side
(`test_the_two_controls_disagree_on_purpose`), so a future refactor cannot
quietly make them agree.

### A timestamp bug caught by writing the test that should have been easy

The per-user cutoff needs to compare a token's issuance time against a
Postgres timestamp. The obvious approach — the JWT's own `iat` claim — is
ambiguous whenever both events land in the same wall-clock second, because
RFC 7519 mandates `iat` as an integer-second `NumericDate` and PyJWT truncates
a `datetime` claim to that on encode. The natural first fix (floor the
Postgres cutoff to match) just moves the race to the opposite failure: a token
issued a moment before the cutoff, in the same second, can then survive it.

This was not found by inspection — it was found by writing
`test_a_token_issued_after_logout_all_still_works` (log out everywhere, then
immediately log back in, then use the new token) and watching it fail
intermittently depending on exactly when in the second the test happened to
run. The fix is a second, dedicated claim (`iat_us`, whole microseconds since
the epoch) carried alongside the standard `iat` purely for this comparison,
required on every token the same way `jti` is: a token forged without it is
refused outright, not silently exempted from the check it cannot satisfy.

Three controls verified by breaking them: fail-open instead of fail-closed on
a degraded store, accepting a token forged without a `jti`, and revoking by
user id instead of by `jti` (which broke logout entirely rather than merely
widening its scope, since the lookup path only ever checks by `jti` — a
useful confirmation that the per-token key is truly load-bearing).

### Deferrals

- **No visibility into active sessions**, and no way to revoke one specific
  *other* session by name — only "this one" or "all of them" is expressible,
  because this platform does not enumerate issued tokens.
- **No password-change flow exists yet** to hang an automatic "revoke
  everything on password change" rule from. `/auth/logout-all` is the
  deliberate stand-in.

## Post-Phase-18: a frontend regression from the CSRF middleware, found and fixed

### The client half of the CSRF contract was never written

`app/core/csrf/enforce.py` shipped requiring `X-CSRF-Token` on every unsafe,
cookie-authenticated request, but `frontend/lib/api-client.ts`'s
`clientApiFetch` — the fetch helper every Client Component uses — was never
updated to read the `kervy_csrf` cookie and attach that header. Every
cookie-authenticated browser write has been returning 403 since CSRF
enforcement landed; `POST /organizations` (the "Create Organization" form)
is the first one anyone would hit. This was a real, previously-undetected
regression, not a documented residual: nothing in `docs/csrf.md` claimed
this path worked, and nothing claimed it didn't either — it was simply
untested at the level that would have caught it, because
`components/auth/__tests__/login-form.test.tsx`-style tests mock
`clientApiFetch` itself rather than exercising its header logic.

Fixed in `clientApiFetch` and, pre-emptively, in `serverApiFetch`
(`frontend/lib/api-server.ts`) even though its only two current callers are
both GETs — otherwise the first server-side mutation added later hits the
identical gap with nothing here to catch it in advance. Both read the
`SAFE_METHODS` boundary from the same set of methods the backend exempts,
kept in a comment next to each rather than imported, since the two live in
different language runtimes.

While writing the fix, an earlier draft of `serverApiFetch` also forwarded
the CSRF cookie as a second, separate `Cookie:` header entry, with a comment
claiming the backend compares two cookies (a plain double-submit check).
Re-reading `enforce.py::check` disproved that: it only ever reads the
*session* cookie to recompute the expected signature, and compares that
against whatever arrives in the header — it never looks up `kervy_csrf` by
name during verification. The extra forwarding was dead code justified by a
false claim about the server it was talking to; removed, and the comment
rewritten to describe the real mechanism.

### Proven with a test that exercises the real function, not a mock

`frontend/lib/__tests__/api-client.test.ts` calls the actual
`clientApiFetch` against a stubbed global `fetch` and a seeded
`document.cookie`, and asserts: the header is attached on an unsafe method
when the cookie is present; omitted on a safe method even with the cookie
present; omitted on an unsafe method with no cookie yet (the pre-session
case); and never overridden when a caller already supplies the header.
Confirmed the first case fails with the fix reverted (header absent) and
passes with it restored — the same "break it, watch the test catch it, put
it back" discipline used for every other control in this project.

## Post-Phase-18: login CSRF closed for real

`docs/csrf.md` carried "login CSRF is open" as an accepted, deliberate gap
since the CSRF middleware first shipped: `/auth/login` and `/auth/register`
were flatly exempt because there is no session yet for an ordinary,
session-bound token to bind to. This closes it with a pre-session token —
`app/core/csrf/anon.py`, a new `GET /api/v1/auth/csrf` endpoint, and both
paths moved from `EXEMPT_PATHS` into a new `ANONYMOUS_CSRF_PATHS` in
`app/core/csrf/enforce.py` that requires it.

### Why a merely self-signed token would not actually fix anything

The first design considered was an HMAC over a random nonce with no
per-visitor binding — simpler than the session-bound scheme, since there is
no session value to sign against. It does not work: the server would hand
out a genuinely valid, correctly-signed token to *anyone* who asked,
attacker included, and an attacker who can plant a cookie for the site (the
sibling-subdomain case the session-bound scheme already defends against)
could plant that self-obtained token as both the cookie and the
header/field in a forged request. Signing alone proves a token came from
this server at some point; it says nothing about whose browser holds it.
`app/core/csrf/anon.py`'s docstring works through this in full, because it
is exactly the kind of mistake that looks like a fix while changing
nothing.

The actual fix needs the value the victim's browser echoes back to be the
exact value sitting in the victim's own cookie jar, with the attacker unable
to control that cookie. That is what the `__Host-` cookie prefix is for:
browsers refuse a `Set-Cookie` for a `__Host-`-prefixed name unless it has
no `Domain` attribute, `Path=/`, and `Secure`, which host-locks it to the
exact origin that set it — a sibling subdomain cannot set it at all, because
setting without `Domain` scopes a cookie to the setting host only. `__Host-`
requires HTTPS, so a deployment serving plain HTTP (local dev, by default)
falls back to an unprefixed cookie of the same shape: still immune to the
naive double-submit break (an attacker picking an arbitrary matching pair
still cannot forge the signature), just not to the sibling-subdomain one.
Named in `docs/csrf.md` rather than left for a reader to assume is covered.

### A break I found before it shipped: this would have taken down the CLI

The obvious first implementation made `ANONYMOUS_CSRF_PATHS` require the
token unconditionally, on the reasoning that login/register have no
`Authorization: Bearer` header to signal "not a browser" the way every other
route does. That reasoning missed something: **login is the request that
*produces* the Bearer token**, so nothing can ever carry one yet, which means
that signal cannot distinguish a browser from `kervy-ai login` or any other
non-browser caller for these two routes specifically — unlike every other
route, where Bearer presence already does this job. Requiring the token
unconditionally would have 403'd the CLI's own login on the very next run.

Caught before committing, by tracing through what the CLI's login path
actually sends (`kervy_cli/client.py` builds a fresh `httpx.Client` per
call — no persistent cookie jar, no browser). Fixed by giving the CLI the
same front door a browser gets: a new `ApiClient.fetch_anon_csrf_token()`
does the `GET /auth/csrf` round trip and hands `cmd_login` both the cookie
name and value to send back explicitly (since there is no jar to carry them
forward automatically the way a browser's does). `tests/test_cli.py`'s
login test was updated to mock that endpoint too.

### The blast radius, and why it went to a subagent

Flipping enforcement on immediately turned every other test that registers
or logs in — 66 call sites across 24 files that had never needed a token
because the paths were exempt — into a 403. Rather than sweep all of it by
hand under time pressure and risk missing one, the mechanical part (fetch
the token, pass the header, following the exact pattern already proven in
`tests/security/test_csrf.py::_register`) went to a background agent with a
precise brief naming every file, the special cases to watch (the rate
limiter's exact-count assertions, `test_cli.py`'s respx mock, one grep false
positive in `test_rasp.py`), and an instruction to run the full suite to
completion rather than report back early. It came back with all 27 files
fixed, `ruff`/`ruff format`/`mypy` clean, and **1379 passed, 2 skipped, 0
failed** — the +13 over the previous 1368 baseline is exactly the new
`anon.py`-specific tests this change itself added to `test_csrf.py`, not
anything left over from the migration. Verified independently afterward
rather than taken on the agent's word alone.

### Deferrals

- **The dashboard's login page's instructional `curl` example**
  (`app/web/templates/login.html`) and the quickstart script/doc
  (`docs/examples/quickstart.py`, `docs/installation.md`) were updated to
  fetch the token first — these are the platform's own worked examples, so
  leaving them stale would have meant the platform's documentation no longer
  matched its own enforcement.
- The `GET /auth/csrf` endpoint is intentionally not rate-limited: it does
  no database or Redis work, only an HMAC over a fresh random nonce, so the
  cost of calling it repeatedly is negligible — unlike `/auth/register` and
  `/auth/login`, which do real work per attempt and are exactly why that
  budget exists.

## Post-Phase-18: evidence encryption at rest, made opt-in

The last of the four gaps this roadmap tracked since Phase 12. §13 makes
encryption at rest for evidence bundles optional, and the earlier deferral
for it was explicit about why nothing existed yet: "a half-built
implementation with an undocumented key model would be worse than none — an
operator would believe the evidence was protected when the key sat beside
it." Closing it meant deciding that key model, not just writing the crypto.

### The key model is the same trade this project already made, not a new one

`KERVY_EVIDENCE_ENCRYPTION_KEY`, read the same way `JWT_SECRET` and
`KERVY_CSRF_SECRET` already are: one static value from an environment
variable, `app/core/config.py`. No rotation, no per-tenant key, no KMS
integration, no tool to re-encrypt bundles already on disk from before the
key was set. This is stated as plainly in `app/core/evidence/crypto.py`'s
own docstring as the absence it replaces was stated in
`app/core/evidence/store.py`'s — the goal was never "encryption", it was "an
honestly-scoped answer to what protects a bundle", and a single env-var key
is exactly as honest a scope as this platform's every other secret already
gets.

**This is a deliberate departure from `docs/BUILD_SPEC.md` §13's own
illustrative text**, which describes "optional encryption-at-rest using a
*run key* (age/libsodium)" — a distinct key per run rather than one static
key for the whole deployment. A per-run key needs somewhere to keep each
one; unless that is itself wrapped by a master key (envelope encryption),
storing it anywhere reachable is exactly the "operator believes it is
protected while the key sits beside it" failure the original deferral
existed to avoid, and envelope encryption trades that for a second problem
— a wrapping key with its own rotation and compromise story — that this
platform has never needed for any other secret. §13 itself says "document
the key-management model honestly" rather than mandating the specific
run-key shape it illustrates with, so a single static key, documented as
exactly that, is read here as satisfying the instruction rather than
missing it.

Unset — every existing deployment, unchanged — a bundle is written exactly
as it always was. Set, `app/core/evidence/crypto.py` (AES-256-GCM, a fresh
nonce per bundle, `nonce || ciphertext_with_tag` on disk) encrypts before
`EvidenceStore.write` touches the filesystem and decrypts transparently in
`read`; `verify` decrypts before re-hashing, since the manifest's digest was
always computed over plaintext content and has to stay that way regardless
of what protects the bytes on disk — content addressing and the hash chain
are about the observation, not the storage format.

### A misconfigured key fails at startup, not mid-run

`Settings.model_post_init` reads `evidence_encryption_key_bytes` for its
side effect: a key that is not valid base64, or does not decode to exactly
32 bytes, raises `ValueError` at process startup. The alternative —
validating lazily, on the first write — would mean a run collects probe
observations for however long it takes to reach one with a bundle, then
loses that observation to a typo made hours earlier. `tests/test_config.py`
covers both failure modes directly against `Settings`, not through
`get_settings()`'s cache, since these tests are specifically about
construction succeeding or failing.

### Proven with the same "break it and watch the test fail" discipline

`tests/test_evidence.py` adds: an unconfigured store still writes plaintext
(the unchanged default); a configured one never writes the plaintext bytes
to disk (checked by asserting the plaintext content string is *absent* from
the file, not merely that some encryption ran); reading a configured store
back returns exactly the original plaintext; verification still passes
through encryption; the wrong key cannot read a bundle written under the
right one, at the level a caller actually hits (`read`, not the primitive);
`verify` reports a wrong-key bundle as a listed problem rather than raising
out of the whole method; a single flipped byte in an encrypted bundle fails
to decrypt entirely rather than producing corrupted plaintext (GCM's
authentication tag is what makes "decrypts cleanly" an integrity claim, not
only a confidentiality one); and two writes of identical plaintext never
produce identical ciphertext, which is what a fresh nonce per write buys.
Verified the write-path test fails when encryption is skipped, by
temporarily reverting the `write()` change and confirming three tests catch
it, before restoring the fix.

## Post-Phase-18: dashboard pagination

`docs/security-review.md` listed "dashboard has no pagination" with the
consequence spelled out plainly: findings capped at 200, runs at 50, with
the API named as the actual complete answer for anyone who needed more.
That consequence is what changed — `/app/.../findings` and `/app/.../runs`
now take a `page` query parameter (`PAGE_SIZE = 50` in `app/web/router.py`)
instead of a single capped page, so the dashboard itself, not just the API,
can reach everything.

Scoped to the two routes the gap actually named. `workflows_page` still
renders a fixed list — it was not part of the stated gap, and stretching
this change to cover it would have been scope creep against what was
actually being fixed rather than a continuation of it.

**A cheap existence query answers "is there a next page" rather than
over-fetching.** `queries.has_more_findings` / `has_more_runs` run the same
filtered query the page itself ran, offset one page further, `LIMIT 1` —
asking the one further question a "Next" link needs, rather than fetching
`limit + 1` rows on every page load and trimming one off just to answer it
on the last page, where the answer is always no.

**Digests, ordering and filters compose with a page number rather than
being replaced by one.** `open_findings`'s `offset` keyword changes which
slice of the already risk-score-ordered result set a page selects; it does
not change the ordering itself, and a severity filter combined with a page
number still filters first and pages the filtered set, not the whole one —
`findings_table.html`'s pager links carry the active `severity` query
parameter forward for exactly this reason, checked directly in
`tests/test_web.py::test_findings_pagination_preserves_the_severity_filter`
by seeding one page's worth of matching rows plus one unrelated one and
asserting the unrelated row stays out of both pages.

Proven the same way as everything else in this file: seed one page's worth
of rows plus one, assert the extra row is absent from page 1 and present on
page 2 (and the reverse for the "Previous"/"Next" and "Newer"/"Older" link
visibility), and confirm the test actually fails — page 2 rendering the
same rows as page 1 — with `.offset()` reverted, before restoring it.

## Post-Phase-18: session visibility and revocation by name

The Phase 18 revocation section's own deferral list named this directly:
"no visibility into active sessions... because this platform does not
enumerate issued tokens." Closing it meant reversing that specific
decision — deliberately, not by accident — since "list what is active" has
no answer without a durable record of what was ever issued, and the
revocation deny-list only ever records what is *dead*.

### A new table, kept strictly separate from the authorization decision

`app/models/user_session.py` adds `user_sessions`: one row per issued
token, written alongside the cookie in `register`/`login` via a small
`_record_session` helper, carrying `jti`, `expires_at`, best-effort
`ip_address`/`user_agent`, and a nullable `revoked_at`. The design choice
that matters is what this table is *not*: it is a record for
`GET /auth/sessions` to read, not a second place a request's validity is
decided. That stays exactly where it already was — the deny-list in
`app/core/revocation/` and `users.tokens_valid_after` — and the model's own
docstring says so explicitly: losing this table makes past sessions
invisible, but revokes nothing that was already revoked and un-revokes
nothing that was not.

`create_access_token`'s signature was deliberately left alone rather than
made to also return the `jti` it generated — `_record_session` decodes the
token it was just handed instead. One redundant decode per login, in
exchange for not touching the two other places that construct a token
today (`decode_access_token(create_access_token(...))` in
`tests/security/test_revocation.py`) for a change only this one caller
needed.

### `/auth/logout-all` stayed a cutover, not a loop

The obvious-looking alternative — now that sessions are tracked, revoke
every tracked row for this user — was rejected. A bulk cutover by
*timestamp* keeps two properties a loop over rows cannot: it invalidates a
token whose row was somehow lost (a botched restore, a race with
`_record_session`'s own write), and it invalidates one issued in the
instant between the loop's `SELECT` and this request's `COMMIT`, which a
snapshot taken slightly earlier could not have known about. `logout_all`
does still bulk-update `user_sessions.revoked_at` for every row that is not
already revoked — but that is bookkeeping for `GET /auth/sessions` to stay
honest about what happened, not the mechanism that makes those tokens stop
working.

### Scope: the caller's own account, and only that

`GET /auth/sessions` and `DELETE /auth/sessions/{id}` are scoped to the
current user, the same boundary `/auth/logout-all` already drew — there is
no admin capability here to see or revoke another user's sessions, which
would have been a materially larger authorization surface than the gap
actually asked to close. Revoking a session that belongs to someone else
returns 404, not 403 — the same non-disclosure `require_membership` already
uses for another organization's resource, so a caller with no legitimate
reason to know cannot tell "not yours" from "does not exist" here either.

### Proven at the level that would have caught a fake fix

`tests/security/test_sessions.py`'s central test does not stop at the
session disappearing from `GET /auth/sessions` — it asserts the token
itself is refused afterward. Verified to fail exactly the way a
row-only "fix" would: with `revoke_session` updated to set `revoked_at`
without calling `revocation.revoke`, the row vanishes from the list but the
token keeps authenticating, which is precisely the gap between "looks
revoked" and "is revoked" this test exists to close. Also covers: each
login adding a distinct row rather than overwriting one; revoking your own
current session working exactly like `/auth/logout`, with no special case
that makes the general endpoint weaker for the one session most likely to
be revoked by mistake; a nonexistent session id returning 404 rather than
500; and `/auth/logout-all` clearing the listing, not only the underlying
authorization already covered end to end in `tests/security/test_revocation.py`.

### Deferrals

- **No admin visibility into another user's sessions** — deliberately out of
  scope, per the boundary above.
- **No client (CLI or dashboard) surfaces this yet.** The API is the
  complete answer today, the same stated position `docs/security-review.md`
  took for dashboard pagination before that gap had its own UI built.

## Repositories: a lightweight path onto code scanning

`docs/repositories.md` has the full design. In short: code scanning
(SAST/SCA/secrets/IaC) previously required the same `Target` →
`Authorization` → `Rules-of-Engagement` sequence built for a live network
assessment, even for source code with no network surface at all. This adds
`kervy-ai repo add|list|show|scan|remove` and the matching
`/organizations/{id}/repositories` API, which composes the same three rows
that workflow would eventually produce, from a URL, a branch, and an
explicit self-affirmed consent — no YAML RoE document, no operator-role
authorization grant from someone else.

`TargetKind.CODE_REPO` is the mechanism that keeps this safe: it is a
distinct kind from `WEB_APP` specifically so `app/workers/tasks.py` never
builds a `DastCheck` for one, and it has no adapter configured so no
`AiSecurityCheck` either — a connected repository's scan runs only the
AppSec engines, against its own checkout, with no code path back to the
network. Verified live: adding, listing, reading, scanning and removing a
repository through the running API and dashboard, and a dedicated test file
(`tests/test_repositories_api.py`) covering RBAC, tenant isolation, and
rejection of an unauthorized-consent or disallowed-scheme/duplicate
repository, alongside the full existing suite passing unchanged.

Found and fixed along the way: `TargetKind.WEB_APP` had never actually been
added to the Postgres `target_kind_enum` by any migration — only to the
Python enum — so a `web_app` target could never be created against a
database built by running the migrations in order (only against one built
by `Base.metadata.create_all()`, which regenerates the type fresh each
time and so never exposed the gap). `CODE_REPO`'s own migration adds both.

### Deferrals

- **No auto-discovery from a connected GitHub org.** Adding a repository is
  manual — paste a URL — by deliberate choice (the user chose this over
  extending `VcsConnection` to call GitHub's repo-listing API); the
  scope decision and the alternative considered are recorded here rather
  than in the migration.
- **No per-organization repository quota or cost cap** beyond what already
  bounds any assessment run.
- **Findings from a repository scan use the same exposure model every
  other code-scanned target already uses** (`app/core/findings/service.py`'s
  `exposure_for`, keyed on `base_url`/`environment`), which was
  designed for a live target and is an approximation for source code — the
  same approximation the pre-existing single-repo-per-target code scan
  already made; this feature does not add a new gap, just more targets
  that inherit the existing one.

## Pentest module, Phase 1 — foundation (schema, migrations, RLS)

The first phase of the AI-powered security-assessment-and-penetration-
testing module: a much broader platform (containers, cloud accounts, VMs,
domains; a controlled pentest-tool adapter layer, sequenced up to and
including authorized exploit execution; multi-vendor AI used throughout;
scheduling and webhooks; an external API/MCP surface for AI agents; a
security-operations dashboard) layered on top of the existing AppSec/API/
AI-red-teaming platform rather than replacing any of it. The full 12-phase
plan is recorded as this session's own implementation plan, not repeated
here; this entry and the next cover the two phases actually built so far.

Delivered: a generalized `asset_scope` JSON column on
`rules_of_engagement` (one column, not one per asset kind — each kind
validates its own sub-shape via a `resolve_*_scope` function in
`app/core/scope/asset_scope.py`, the same pattern `code_scope` already
uses); four new `TargetKind` values (`container`, `cloud_account`,
`virtual_machine`, `domain`); a `discovered_assets` table for things a scan
finds but does not itself authorize (`app/models/discovered_asset.py`); a
`run_tool_invocations` table recording exactly which tool ran, with which
network posture, per assessment run; and five new reporting pillars
(Container, Cloud, VM, Domain, Pentest) so coverage stays honest — "not
tested" — until each engine lands.

Decisions worth stating:

- **`asset_scope` is one column, not five.** A fifth asset kind is a new
  resolver function and `TargetKind` value, never a migration to this
  module's structure — the same reasoning `code_scope`'s single-column
  design already established.
- **A `DiscoveredAsset` is not a `Target`.** It is something a scan found —
  a subdomain, eventually a cloud resource or an open port — with no
  `Authorization`/`RulesOfEngagement` of its own. Promotion to a real,
  scannable `Target` is a separate, explicit human action
  (`promoted_to_target_id`), never automatic. This is the concrete
  mechanism behind "never automatically expand testing to targets outside
  the approved scope."
- **Pentest scope reads its own absence as "discovery only," not
  "refused."** Unlike the four asset-kind scopes, `PentestScope` is an
  *additive* capability layered on whatever asset kind is already being
  scanned; a target makes no statement about pentest tooling by default,
  and that silence means the least invasive tier rather than an abort.
- **Both new tables joined the existing Row-Level Security policy in the
  same migration that created them** — a new tenant-scoped table with no
  RLS policy would be exactly the gap `b2e6f4a91c7d`'s own docstring warns
  against.

Verified: `ruff check`/`mypy app` clean, 14 new resolver unit tests
(`tests/security/test_asset_scope.py`), the reporting golden snapshots
regenerated for the five new pillars, and the full backend suite green —
including catching and fixing a real gap this phase exposed: the test
database needs its own independent `alembic upgrade head`, separate from
the development database, which nothing had previously required.

### Deferrals

- **Container, cloud, VM, and pentest-tool engines do not exist yet.**
  Only the schema/scope-resolver foundation is built. The domain engine
  (next section) is the first to actually run.
- **Real exploit execution is deliberately last in the plan**, behind its
  own `ExploitationAuthorization` tier, a simulate-then-fire two-step, and
  named operational-readiness items (incident-response runbook,
  authorization-artifact format, insurance/liability review) that are the
  operator's responsibility, not implementation tasks.
- **No frontend UI for any of the new asset kinds yet.** Configuration is
  API-only, the same phased approach every earlier module took.

## Pentest module, Phase 2 — domain/DNS engine

Delivered: `app/core/domain/` — subdomain discovery via certificate-
transparency logs (`crt.sh`, through `GatedTransport` like any other
outbound request) and a small built-in DNS brute-force wordlist (through
the same `DnsResolver` every scope check already uses); TLS certificate
inspection (expiry, protocol version) and missing-security-header checks
against the root domain and any discovered host matching
`asset_scope.allowed_subdomain_patterns`; a `DomainCheck` orchestrator
wrapper mirroring `DastCheck`'s "one engine failure must not lose the run"
contract; wiring into `execute_assessment_run` for `TargetKind.DOMAIN`; and
a `PUT /organizations/{id}/targets/{id}/domain-scope` endpoint (mirroring
`configure_code_scope`'s shape) so an operator can actually declare a
domain target's scope through the API rather than only through a direct
database write.

Decisions worth stating:

- **Discovery never expands what gets tested.** Every discovered hostname
  becomes a `DiscoveredAsset` row; only the root domain and hosts matching
  `allowed_subdomain_patterns` receive the HTTP/TLS checks. An empty
  pattern list means "only the root domain itself," never "everything
  found" — the same fail-closed reading `resolve_domain_scope` already
  documents.
- **The TLS probe resolves and blocked-IP-checks a host itself before
  connecting**, because `httpx`/`GatedTransport` do not expose peer-
  certificate details and a raw socket connection is therefore its own,
  separate egress path — one that reuses `is_blocked_ip`/`parse_ip_ranges`
  directly rather than reimplementing the check, per this module's own
  rule for any new engine that talks to something that isn't raw `httpx`.
- **A pure-HTTP/DNS engine does not synthesize a `RunToolInvocation`.**
  That machinery exists to bound and report on *subprocess* scanners; an
  HTTP call already gated by `GatedTransport`/`ScopeEngine` does not need a
  second record of having run.
- **A malformed `asset_scope` skips the check, not the run.** The same
  pattern a bad `code_scope` already gets: the event log records why, and
  every other check still executes.

A real bug found and fixed while writing this phase's tests: crt.sh
returns wildcard SANs (`*.example.test`) alongside concrete hostnames, and
the original filter used `str.lstrip("*.")` to strip the wildcard marker —
which strips *characters*, not a literal prefix, so `"*.example.test"`
became `"example.test"` and silently passed the root-domain-equality check
instead of being skipped, folding a wildcard SAN into the root domain
itself. Fixed by checking for the wildcard prefix before any stripping,
with a regression test.

Verified: `ruff check`/`mypy app` clean, 12 new engine/resolver tests
(`tests/test_domain_engine.py`, in-memory fakes for the resolver and
transport, no real network — mirrors `tests/test_dast.py`'s style) plus 5
new API tests (`tests/test_domain_scope_api.py`), and the full backend
suite green.

### Deferrals

- **No live registry/wordlist configuration from the operator.** The DNS
  brute-force list is a small, static, built-in set of common prefixes —
  enough to prove the discovery → `DiscoveredAsset` pipeline end to end,
  not an exhaustive enumeration. An RoE-declared wordlist is a later
  increment.
- **No dashboard page for domain assets yet.** The API and the engine are
  complete and tested; the security-operations dashboard is a later phase
  in the plan, built once against a more complete asset surface
  (container/cloud/VM too) rather than piecemeal.
- **Container, cloud, VM, and pentest-tool engines do not exist yet** — see
  the foundation section above.

## Pentest module, Phase 3 — container engine (live registry pulls)

Closes the gap the Aikido-parity container engine (`appsec.container.trivy`,
this build's earlier work) states plainly rather than fakes: it scans a code
checkout's filesystem and says outright it "did not pull or examine the base
image layers", because pulling one means reaching a registry that engine has
no scope to authorize. `app/core/container/` is that authorization, made
explicit through `asset_scope.allowed_registries` and
`asset_scope.allow_live_pull` on a `TargetKind.CONTAINER` target (both
already defined in the Phase 1 foundation's `ContainerScope`) — never
assumed, and never on by default.

Delivered: `parse_image_ref`/`check_registry_allowed` (`app/core/container
/pull.py`) — registry-host extraction and the same allowlist-then-resolve-
then-block-check pipeline `app/core/appsec/checkout.py` already established
for `git clone`, since `docker pull` is a subprocess and does not route
through `GatedTransport` either; `ContainerEngine` (`engine.py`) — pull,
scan, remove, always, via injectable `pull`/`scan`/`remove` callables the
same way `DomainEngine` injects its transport and DNS resolver; scanning is
`trivy image --image-src docker --skip-db-update --offline-scan`, reading
the image the pull already placed on the local Docker daemon rather than
letting trivy make its own registry call — a second, unaudited path to the
same host; `ContainerCheck` (`app/core/orchestrator/container_check.py`),
mirroring `DomainCheck`'s "one engine failure must not lose the run"
contract; wiring into `execute_assessment_run` for `TargetKind.CONTAINER`;
and a `PUT /organizations/{id}/targets/{id}/container-scope` endpoint
mirroring `configure_domain_scope`'s shape.

The first engine to actually populate `run_tool_invocations`
(`app/core/container/service.py::record_tool_invocations`) — the table
Phase 1's foundation added schema-only, "recording exactly which tool ran,
with which network posture, per assessment run." `docker pull`, `trivy
image`, and the cleanup `docker rmi` each write their own row; the domain
engine before this needed none of this machinery because it is pure
HTTP/DNS, not a subprocess.

Decisions worth stating:

- **A pulled image is removed whatever happened**, in a `finally` around
  the scan — the same "the checkout is removed whatever happened"
  discipline `discard_checkout` already follows for a repository clone. A
  pulled image left on the worker is exactly the kind of artifact that
  discipline exists to avoid.
- **An unauthorized live pull is a visible "not tested" gap, never a
  silent skip.** `allow_live_pull` defaults to `False` even though
  `resolve_container_scope` permits either value — declaring a registry
  allowlist is not, by itself, authorization to reach the network; an
  operator opts in to the live pull as a separate, explicit decision, the
  same way `PentestScope`'s own `max_depth` requires `approved_modules`
  before exploitation.
- **The registry match checks both the qualified host and the port-
  stripped resolve host.** A wildcard allowlist entry (`*.internal`) has
  no notion of a port to ignore, so an operator pointing at
  `registry.internal:5000` would otherwise find a correctly-written
  wildcard silently fail to match. A bug caught during this phase's own
  tests, before it shipped.
- **Docker Hub's own registry host is resolved and checked, not the name
  "docker.io" a reference actually contains.** `docker.io` in an image
  reference and the host actually dialed for a pull
  (`registry-1.docker.io`) are different strings; checking the wrong one
  would validate nothing.

Verified: `ruff check`/`mypy app` clean; new tests across
`test_container_pull.py` (reference parsing, registry allowlist, blocked-
address refusal, the wildcard/port fix above), `test_container_engine.py`
(gating, cleanup-always including on a raised exception, verified-advisory
filtering), `test_container_check.py` (check-level failure isolation, the
DB-backed `RunToolInvocation` write), and `test_container_scope_api.py`
(mirroring `test_domain_scope_api.py`); the RBAC route→role matrix test
extended for the new route; a regression pass over the domain/runs/targets/
workers/security clusters this phase touches (502 passed, 2 skipped,
unaffected); and the full backend suite green.

### Deferrals

- **No image signature or provenance verification.** Only vulnerability
  scanning is implemented; Sigstore/cosign verification is a later
  increment, tracked alongside the pentest-tool architecture phase.
- **Multi-architecture manifest lists pull whatever the local Docker
  daemon's own platform default resolves to.** No per-run platform
  override exists yet.
- **No dashboard page for container assets yet** — same reasoning as the
  domain phase's own deferral: it lands once against a more complete asset
  surface (cloud/VM too) rather than piecemeal.
- **Cloud and VM engines, and the pentest-tool architecture, still do not
  exist** — see the Phase 1 foundation section above.

## Pentest module, Phase 4 — cloud engine (AWS, read-only)

Closes the "Cloud and VM engines... still do not exist" gap the Phase 3
container-engine section named above. `app/core/cloud/` inventories
object-storage exposure for a `TargetKind.CLOUD_ACCOUNT` target's declared
account, gated on `asset_scope.provider`/`account_ref`/`credential_env_var`/
`allowed_regions` (`CloudScope`, already defined in the Phase 1 foundation)
and on `resolve_cloud_scope`'s own hard refusal of anything but a
read-only assessment — a mutating cloud call is a higher authorization tier
this engine does not grant, and unlike `ContainerScope.allow_live_pull` this
is not even a caller-settable flag: `read_only` defaults `True` and a `False`
value is rejected at resolve time, before the engine ever runs.

Delivered: `app/core/cloud/providers/aws.py` — real, correct `boto3` usage
against exactly four read-only S3 calls (`list_buckets`,
`get_bucket_location`, `get_bucket_policy_status`, `get_bucket_acl`), never a
`put_*`/`delete_*`/`create_*` verb, enforced by this phase's own static test
the same way `docs/security-model.md` guarantee #20 already enforces "no
write verbs" for `app/core/vcs`'s pull-request layer; `CloudEngine`
(`engine.py`) dispatching by `provider` through an injectable `providers` map
— the same reason `ContainerEngine` injects `pull`/`scan`/`remove` rather than
reaching for a real Docker daemon at call time; `CloudCheck`
(`app/core/orchestrator/cloud_check.py`), mirroring `ContainerCheck`'s "one
engine failure must not lose the run" contract; wiring into
`execute_assessment_run` for `TargetKind.CLOUD_ACCOUNT`, including promoting
inventoried buckets to `DiscoveredAsset` rows
(`app/core/cloud/service.py::promote_discovered_buckets`, upsert-on-rerun,
mirroring `promote_discovered_subdomains`); and a `PUT
/organizations/{id}/targets/{id}/cloud-scope` endpoint mirroring
`configure_container_scope`'s shape.

Decisions worth stating:

- **AWS ships fully implemented this phase; Azure and GCP do not.**
  `resolve_cloud_scope` already validates `provider` against exactly
  `{"aws", "azure", "gcp"}`, and `CloudEngine`'s dispatch handles all three —
  but calling either unimplemented provider today produces an explicit
  `KERVY-CLOUD-109` "not implemented yet" gap finding rather than a
  fabricated result. Each needs its own multi-package SDK integration
  (`azure-identity` + `azure-mgmt-storage` + `azure-storage-blob`;
  `google-cloud-storage` + service-account credential handling), and shipping
  either untested against a real account would be exactly the kind of
  unverified claim this codebase's own discipline refuses to make — the same
  reasoning Phase 5's SSRF probe and Phase 6's indirect-injection probe were
  deferred under in the AI engine, rather than stubbed.
- **The credential a `credential_env_var` resolves to is a JSON object, not
  a bare token.** S3 access needs an access-key/secret-key pair (plus an
  optional session token), not the single string `SyntheticAccount`'s bearer
  header needed — `{"access_key_id": ..., "secret_access_key": ...,
  "session_token": ...}`. Malformed or incomplete JSON is a
  `CloudProviderError`, surfaced as a coverage marker, never a crash.
- **A bucket is judged public from two independent signals** — the bucket
  policy's own `GetBucketPolicyStatus.IsPublic` flag, and an ACL grant to the
  `AllUsers`/`AuthenticatedUsers` well-known groups — because an account can
  restrict read access to one API and not the other; checking only one would
  under-report. Either surface being unreadable (access denied) is treated
  as a conservative "not public" rather than fabricating a verdict from a
  denial.
- **An out-of-scope region is skipped entirely, not merely reported
  untested** — the same "discovery never expands what gets tested" rule
  `DomainEngine` applies to a subdomain outside
  `allowed_subdomain_patterns`. An empty `allowed_regions` means no
  restriction, matching the schema's own permissive default.
- **`boto3` is an optional `cloud` extra** (`pip install -e ".[dev,cloud]"`),
  the same reasoning `appsec` already established for its scanners: an
  engine whose SDK is absent reports `KERVY-CLOUD-109` rather than crashing
  or, worse, silently reporting nothing. The base test suite never imports
  it for real — every test exercises the provider through dependency
  injection.

Verified: `ruff check`/`mypy app` clean (a new `[[tool.mypy.overrides]]`
entry for `boto3.*`/`botocore.*`, mirroring the existing `celery`/
`weasyprint` overrides, since neither ships a `py.typed` marker); new tests
across `test_cloud_aws.py` (credential parsing, public-grant detection via
both the policy and ACL paths, region filtering, rejected/failed-credential
handling, missing-SDK handling, and the static read-only-verb check),
`test_cloud_engine.py` (credential gating, unimplemented-provider gating,
provider-error gating, the unconditional inventory finding, public-bucket
findings), `test_cloud_check.py` (check-level failure isolation, the
DB-backed `promote_discovered_buckets` upsert-on-rerun and
exposure-change test), and `test_cloud_scope_api.py` (mirroring
`test_container_scope_api.py`); the RBAC route→role matrix test extended for
the new route; a regression pass over the container/domain/runs/targets
clusters this phase touches (81 passed, unaffected); and the full backend
suite (1736 passed, 2 skipped). Four failures on this run are pre-existing
and unrelated to this phase — two `checkov` rule-ID mismatches and their
downstream `test_code_scan_e2e.py` effect (the pinned `checkov` version's
own IaC rule set drifted, unrelated to any file this phase touches), and
one CycloneDX SBOM spec-version assertion whose own docstring already
states its deferral is recorded here rather than papered over — the
installed `cyclonedx-python-lib` now tops out at 1.7 where §23 pins 1.6.
Neither failure touches `app/core/cloud/`, `app/core/container/`,
`app/workers/tasks.py`, the targets router, or the RBAC matrix.

### Deferrals

- **Azure and GCP object-storage inventory** — see above; the engine and API
  surface already route to either provider correctly, only the SDK
  integration itself is deferred.
- **No compute/database/network exposure inventory** — this phase is
  object-storage only (S3-equivalent). Broader cloud posture (open security
  groups, public RDS instances, IAM policy analysis) is a later increment.
- **No dashboard page for cloud assets yet** — same reasoning as the
  container phase's own deferral: it lands once against a more complete
  asset surface (VM too) rather than piecemeal.
- **VM engine and the pentest-tool architecture still do not exist** — see
  the Phase 1 foundation section above.

## Pentest module, Phase 5 — VM engine (authorized port/service discovery)

Closes the last of the three engine gaps the Phase 1 foundation named
(domain, container, cloud already shipped in Phases 2–4). `app/core/vm/`
port-scans a `TargetKind.VIRTUAL_MACHINE` target's declared host with
`nmap -sV`, gated on `asset_scope.host`/`allowed_ports` (`VmScope`, already
defined in the Phase 1 foundation) and on the same blocked-address check
(`is_blocked_ip`) `check_registry_allowed` already applies to a container
registry's resolved host.

Delivered: `app/core/vm/nmap.py` — `check_host_allowed` (resolve-then-
block-check, mirroring `check_registry_allowed`) and `scan_ports`/
`parse_open_ports` (`nmap -Pn -sV --open -p <declared ports> -oX -`, parsed
with the stdlib's `xml.etree.ElementTree` rather than a new dependency);
`VmEngine` (`engine.py`) dispatching through an injectable `scan` callable —
the same reason `ContainerEngine` injects `pull`/`scan`/`remove` rather than
reaching for a real `nmap` binary at call time — emitting an unconditional
port-inventory finding plus a `KERVY-VM-101` finding for a small, fixed set
of ports whose mere reachability is already noteworthy (Telnet, SMB, Redis,
MongoDB, and similar unencrypted or commonly-unauthenticated services);
`VmCheck` (`app/core/orchestrator/vm_check.py`), mirroring `ContainerCheck`'s
"one engine failure must not lose the run" contract — the first check to
carry both `tool_invocations` (like `ContainerCheck`) and `discovered`
(like `CloudCheck`) at once; wiring into `execute_assessment_run` for
`TargetKind.VIRTUAL_MACHINE`, including recording `nmap`'s invocation into
`run_tool_invocations` (the second engine to populate that table, after the
container engine) and promoting discovered open ports into `DiscoveredAsset`
rows via `AssetKind.OPEN_SERVICE` — reserved for exactly this in the Phase 1
foundation's own model docstring ("an open service on a VM") but unused
until now; and a `PUT /organizations/{id}/targets/{id}/vm-scope` endpoint
mirroring `configure_container_scope`'s shape.

Decisions worth stating:

- **Declaring a port in `allowed_ports` is itself the authorization to
  probe it — there is no separate `allow_live_pull`-style opt-in flag.**
  `VmScope` was defined without one back in the Phase 1 foundation, and this
  phase respects that: `resolve_vm_scope` already refuses an empty
  `allowed_ports` list, the same "an unstated allowlist is not a permissive
  one" rule `resolve_container_scope` enforces for `allowed_registries`.
  Unlike a container pull (which downloads arbitrary third-party content
  onto the worker), a port probe's cost and footprint is small and bounded
  by the declared port list itself, so the extra flag `ContainerScope
  .allow_live_pull` needs has no equivalent here — the same reasoning
  `DomainTarget.root_domain`'s mere presence already gives the domain
  engine's own baseline discovery and TLS/header checks.
- **This engine does not itself judge a service vulnerable.** `nmap -sV`
  fingerprints what is listening; deeper, tool-driven vulnerability
  scanning and validation against a discovered service is the pentest-tool
  architecture's own job (Phase 6, `PentestScope.max_depth`), layered on top
  of this baseline the same way a later, deeper probe would build on the
  domain engine's own TLS/header checks. What this engine flags on its own
  — a small, fixed, noteworthy-port list — says a surface is reachable,
  never that it is misconfigured.
- **No elevated privilege is required.** The scan omits `-sS`; without
  root, `nmap` already falls back to a TCP connect scan, so this runs the
  same way any other subprocess-based engine on this platform does.
- **`nmap`'s XML output (`-oX -`) is parsed with the standard library**
  (`xml.etree.ElementTree`), not a new dependency — the same reasoning that
  kept the SBOM/reporting pipeline's XML handling dependency-free
  elsewhere. `nmap` itself, like `trivy`/`docker`, is expected to already be
  present on the worker; a missing binary reports `KERVY-VM-109` rather
  than crashing, the same graceful-degradation contract every other
  subprocess-based engine on this platform follows.
- **`ToolInvocationRecord` and `record_tool_invocations` are duplicated
  into `app/core/vm/`, not imported from `app.core.container`.** The two
  engines are conceptually independent; sharing a ~10-line dataclass and
  persistence function across unrelated engine packages would be a stranger
  coupling than the small duplication avoids — the same "mirror, don't
  share" convention every other per-phase `contract.py`/`service.py` in
  this module already follows.

Verified: `ruff check`/`mypy app` clean; new tests across `test_vm_nmap.py`
(blocked-address refusal including the cloud-metadata address even when
allowlisted, an explicitly-allowed private range, unresolvable-host
handling, missing-`nmap`-binary handling, XML parsing including a closed
port correctly excluded and malformed XML refused), `test_vm_engine.py`
(empty-allowlist gating, blocked-address gating, scan-failure gating,
malformed-output gating, the unconditional inventory finding, noteworthy-
port findings), `test_vm_check.py` (check-level failure isolation, the
DB-backed `record_tool_invocations`/`promote_discovered_open_services`
upsert-on-rerun tests), and `test_vm_scope_api.py` (mirroring
`test_container_scope_api.py`, plus an out-of-range-port rejection case);
the RBAC route→role matrix test extended for the new route; a regression
pass over the container/cloud/domain/runs/targets clusters this phase
touches (334 passed, 2 skipped, unaffected); and the full backend suite
(1769 passed, 2 skipped). The same four pre-existing, unrelated failures
from the Phase 4 run recur here unchanged — two `checkov` rule-ID
mismatches and their downstream `test_code_scan_e2e.py` effect, and the
already-documented CycloneDX spec-version deferral — none touching
`app/core/vm/`, `app/core/orchestrator/vm_check.py`,
`app/workers/tasks.py`, the targets router, or the RBAC matrix.

### Deferrals

- **No SSH-based authenticated/credentialed scanning.** `VmScope
  .ssh_credential_env_var` exists in the Phase 1 foundation's schema but is
  not read by this engine — this phase is unauthenticated network discovery
  only, the same tier the domain engine's own baseline occupies.
- **No exploitation or validation against a discovered service** — see the
  "does not itself judge a service vulnerable" decision above; that is
  Phase 6's job.
- **No dashboard page for VM assets yet** — same reasoning as the
  container/cloud phases' own deferral: it lands once against the complete
  three-engine asset surface rather than piecemeal, now that all three
  (domain, container/cloud, VM) exist.
- **The pentest-tool architecture itself still does not exist** — see the
  Phase 1 foundation section above; this was its last prerequisite engine.

## Pentest module, Phase 6 — pentest-tool architecture (discovery/vuln-scan/validation)

Closes the last gap the Phase 1 foundation named: `app/core/pentest/`, a
closed, tier-gated module registry layered on an already-discovered,
already-authorized service — never a fresh scan of its own. This phase
wires it only to `app.core.vm`'s discovered open services (see the
engine's own docstring for why extending it to a domain-discovered HTTP
endpoint or a cloud resource later is a caller-side wiring change, not a
change to the engine itself).

Delivered: `app/core/pentest/nmap_scripts.py` — three NSE-script modules,
each exactly one `nmap --script <category>` invocation against one
already-open `host:port`, mapping onto `TestDepth`'s tiers by what the
category actually does rather than by name (nmap has no category literally
called "validation"): `discovery` (safe information-gathering beyond the
VM engine's own `-sV`), `vuln` (known-vulnerability checks, read via the
`vulns` NSE library's own `State: VULNERABLE` convention), and `auth`
(confirms a service is reachable with no/default/anonymous credentials —
this platform's validation tier: confirming exploitability-by-lack-of-auth
without attempting to exploit anything further); `registry.py`, a closed
tuple of `PentestModule`s mirroring `appsec_engines()`'s closed-set idiom,
with **no `TestDepth.EXPLOITATION` module registered at all** — real
exploit execution stays exactly where the Phase 1 foundation put it,
behind its own tier, last in the plan (Phase 12); `PentestEngine`
(`engine.py`) gating on `scope.max_depth.at_least(module.tier)` and, when
non-empty, `scope.approved_modules`, via an injectable `modules` tuple —
the same reason `VmEngine` injects `scan`; `PentestCheck`
(`app/core/orchestrator/pentest_check.py`) — the first check on this
platform to depend on another check's result (`vm_check.discovered`)
rather than only on the target/scope, safe only because `execute_run`
(`app/core/orchestrator/runner.py`) runs every check sequentially in the
exact order `workers/tasks.py` appends them; wiring into
`execute_assessment_run`, appended only when, and always after,
`vm_check`; and `PentestScopeIn` nested inside `VmScopeIn` — no separate
endpoint, since `resolve_pentest_scope` reads its fields from the exact
same `asset_scope` document `resolve_vm_scope` also reads from.

Decisions worth stating:

- **No separate opt-in flag beyond `max_depth`/`approved_modules`
  themselves.** Silence resolves to `TestDepth.DISCOVERY` and runs the
  `discovery`-tier module — never a refusal — the exact "silence means the
  least invasive tier, not an abort" rule the Phase 1 foundation's own
  `PentestScope` already documents; declaring a deeper tier is itself the
  authorization, the same reading `VmScope.allowed_ports` already gets.
- **A deeper `max_depth` still runs every shallower tier's modules too.**
  `TestDepth.at_least` is an ordinal comparison, not an exact-tier match —
  a run authorized for `vulnerability_scan` gets the `discovery`-tier
  module's output as well, the same way a deeper RoE authorization has
  always implied the shallower ones on this platform.
- **`vuln`-tier confidence is `MEDIUM`, not `HIGH`.** `is_vulnerable_state`
  is a text-match against the `vulns` NSE library's own convention, stated
  plainly as a heuristic in its own docstring — not a database-verified
  advisory ID the way `app.core.appsec.identifiers.verified_advisories`
  confirms a container-engine CVE. `auth`-tier (validation) findings are
  `HIGH` confidence instead: the script's output exists only because the
  anonymous/default-credential check itself live-succeeded, a directly
  observed condition rather than a text heuristic.
- **`nmap`'s XML output is parsed with `defusedxml`, not the stdlib's
  `xml.etree.ElementTree`** — caught by this platform's own dogfooded
  Bandit rule (B314) against `app.core.vm.nmap`'s Phase 5 parser too, fixed
  in both places together. The XML comes from a subprocess this platform
  itself invoked, not an external upload, but the same reasoning applies
  either way: a parser with external-entity resolution enabled is a risk
  for any XML whose full provenance is not the platform's own code, and a
  correct drop-in replacement was one import away.
- **`ToolInvocationRecord`/`record_tool_invocations` are duplicated into
  `app/core/pentest/`, not imported from `app.core.vm` or
  `app.core.container`.** Three independent engine packages now carry the
  same ~10-line shapes — the same "mirror, don't share" convention every
  per-phase `contract.py`/`service.py` in this module already follows,
  chosen over a shared cross-engine coupling with no semantic meaning.

Verified: `ruff check`/`mypy app` clean (`defusedxml`/`types-defusedxml`
added as direct dependencies — the library was already present
transitively but neither module had imported it directly before); `bandit
-r app kervy_cli -ll` clean (confirmed the B314 finding this phase's own
work exposed, and fixed it in both `app/core/vm/nmap.py` and
`app/core/pentest/nmap_scripts.py`); new tests across
`test_pentest_nmap_scripts.py` (script parsing across both port- and
host-scoped results, the `is_vulnerable_state` heuristic, missing-binary
handling), `test_pentest_engine.py` (tier/approval gating including the
"deeper implies shallower" ordering, per-tier finding shape, module-failure
and malformed-output gaps), `test_pentest_check.py` (check-level failure
isolation, the DB-backed `record_tool_invocations` test, and a dedicated
test proving the sequential-check-ordering dependency on
`vm_check.discovered` actually works), and `test_pentest_scope_api.py`
(declaring `pentest.max_depth`/`approved_modules` through the existing
`vm-scope` endpoint, the one case `resolve_pentest_scope` itself validates
— `exploitation` without `approved_modules` — refused with 422); a
regression pass over the container/cloud/vm/domain/runs/targets clusters
this phase touches (396 passed, 2 skipped, unaffected); and the full
backend suite (1801 passed, 2 skipped). The same four pre-existing,
unrelated failures from the Phase 4/5 runs recur here unchanged — two
`checkov` rule-ID mismatches and their downstream `test_code_scan_e2e.py`
effect, and the already-documented CycloneDX spec-version deferral — none
touching `app/core/pentest/`, `app/core/vm/nmap.py`,
`app/core/orchestrator/pentest_check.py`, `app/workers/tasks.py`, the
targets router, or the RBAC matrix.

### Deferrals

- **Only VM-discovered open services are wired in.** The engine itself is
  asset-kind-agnostic (see its own docstring); extending it to a
  domain-discovered HTTP endpoint or a cloud resource is a later
  increment's caller-side wiring change.
- **No dashboard page for pentest-tool findings specifically** — they
  report through the existing `Pentest` reporting pillar and findings
  pipeline like any other engine's output; a dedicated view is a later
  phase, the same reasoning every earlier engine's own dashboard deferral
  gives.
- **`TestDepth.EXPLOITATION` has no registered module, on purpose** — see
  the "no exploitation module registered" decision above; that tier is
  Phase 12's own job, behind its own `ExploitationAuthorization` tier.

## Pentest module, Phase 7 — AI expansion (correlate/prioritise, evidence Q&A)

Closes the gap `app/core/assistant/autonomy.py` had named since Phase 16:
`Capability.CORRELATE_FINDINGS`/`PRIORITISE_FINDINGS` were declared at
`AutonomyMode.RECOMMEND` with no `AIService` method behind either, and the
module's own docstring already promised a co-pilot that "explains,
correlates, prioritises and drafts" — only the first and last of those
existed. This phase adds the missing two, plus a third, previously
undeclared capability the same brief asked for: answering a free-text
question about a finding's own captured evidence.

The "multi-provider" half of this phase's brief is already satisfied by
the native Agent framework (Phases 1–7 above): a tool call resolves an
org's configured Anthropic/Gemini/OpenAI/`openai_compatible` provider
(`app/core/agent/provider/factory.py`) before ever constructing an
`AIService`, so no second provider-resolution path was needed — the same
"resolve overlap before building" reasoning this module's plan applied to
the Phase 6/Phase 9 MCP-surface overlap.

Delivered: `Capability.ANSWER_EVIDENCE_QUESTION` (`AutonomyMode.ASSIST`,
matching `EXPLAIN_FINDING`'s own tier — it explains, it does not
recommend); three new versioned `PromptTemplate`s
(`assistant.correlate_findings`, `assistant.prioritise_findings`,
`assistant.answer_evidence_question`), all carrying the same
`SYSTEM_PREAMBLE` and observed/inferred/recommended/unknown labelling
discipline as every earlier template; `AIService.correlate_findings()`,
`.prioritise_findings()` (each over a capped, evidence-fenced list of
`FindingView`s via a new `_render_findings_list()` helper — the same
`MAX_FINDINGS`-style cap `summarise_run`'s own title list already uses,
because a co-pilot reasoning over too many findings at once produces noise
rather than a correlation), and `.answer_evidence_question()` (a finding
plus a free-text question, both evidence-fenced independently — the
question is fenced too, not just the evidence, since it is equally
untrusted free text reaching the prompt); and three new READ_ONLY
native-agent tools (`app/core/agent/tools/analysis.py`'s
`answer_evidence_question`, and a new `app/core/agent/tools/correlation.py`
holding `correlate_findings`/`prioritise_findings`), each reusing the
existing `Tool`/`AgentContext` shape `analyze_finding` already established
— load `Finding` rows scoped to `ctx.organization_id`, project to
`FindingView`, call the `AIService` method, return its draft. The two
multi-finding tools load up to 25 findings by ID and raise
`ToolNotFoundError` naming every ID not found in the caller's own
organization, rather than silently dropping them.

Decisions worth stating:

- **All three new tools are `READ_ONLY`, not `STANDARD`.** Each drafts text
  a human is expected to weigh, exactly like `analyze_finding`; none writes
  a finding's stored severity, status, or relationships — the same
  reasoning that keeps `analyze_finding` at `READ_ONLY` applies unchanged.
- **The tool hardcodes its own minimum autonomy mode when constructing
  `AIService`**, the same pattern `analyze_finding` already established:
  the tool's own `risk_level`/`minimum_role` is the real authorization
  gate for the call, not a second autonomy configuration that would need
  to be kept in sync with it.
- **No new provider-resolution code.** `ctx.provider` already arrives
  pre-resolved by the Agent framework's own multi-provider factory; every
  new tool simply reuses it, the same way `analyze_finding` already did.

Verified: `ruff check`/`mypy app` clean; targeted run of
`tests/security/test_assistant_boundary.py`, `tests/test_agent_tools.py`,
and `tests/security/test_agent_boundary.py` (69 passed) covering the
updated closed-capability-set pin test, the updated closed-tool-registry
pin test, evidence-fencing of both a hostile finding inside a correlated
set and a hostile question, and tenant-isolation for all three new tools
(including the multi-finding tools' cross-organization `ToolNotFoundError`
behaviour).

### Deferrals

- **No new prompt-injection surface introduced, but also none newly
  defended against beyond what `quote_evidence()` already provides** — a
  free-text question is user-supplied, not scanner-derived, so it is a
  different threat model than scan evidence; fencing it the same way is a
  reasonable default, not a claim that every injection vector through a
  question has been separately analysed.

## Pentest module, Phase 8 — automation (Celery Beat, webhooks, approval gates)

Closes the three gaps `docs/workflows.md`'s "What is not built" section and
the Phase 17/Agent-framework deferrals both named explicitly: no scheduler,
no inbound webhook endpoint, and — the gap those two expose once built — no
approval gate for a trigger with no human present at all.

**The insight that ties the three together**: `queue_run()`
(`app/core/runs/service.py`) takes a *required* `user_id`; every scan this
platform has ever queued is attributed to a real human. An unattended
trigger has no human in the request, so the approval step is not a safety
feature bolted on top — it is what supplies a real `user_id` to attribute
the resulting scan to, the same way a human calling `POST /runs` supplies
their own. This is why `approve()` (not the scheduler or the webhook
directly) is the one place that calls `queue_scan_for_workflow_run`.

Delivered: `Trigger.unattended: bool` (not a new `TriggerKind` — an inbound
webhook still produces `REPOSITORY_CHANGE`/`PULL_REQUEST`, what's new is the
authenticated acceptance endpoint, not the trigger vocabulary; a human
manually re-running a `SCHEDULE`-kind workflow through the existing API
must not pause, which ruled out keying the gate off `trigger.kind` itself);
`WorkflowStatus.AWAITING_APPROVAL` and `UNATTENDED_APPROVAL_ACTIONS`
(`APPSEC_SCAN`/`API_SCAN`/`AI_SCAN`/`DAST_SCAN`/`PUBLISH_PR` — mirrors
`app.core.assistant.autonomy.TARGET_TOUCHING`'s "no mode can grant this"
idiom, no opt-out column); `Workflow.schedule_interval_minutes`/
`next_run_at` (a 60-minute floor, validated at the schema level — a stated
safety rail against unattended, high-frequency scanning of a live target,
not cron-expression support, matching `TriggerKind`'s own "not a general
workflow engine" stance) and `Workflow.webhook_enabled`/
`webhook_secret_encrypted`; three new Celery tasks
(`dispatch_scheduled_workflows` ticking every 60s, advancing `next_run_at`
*before* the run task executes so a slow run never double-dispatches;
`run_scheduled_workflow`; and `gate_workflow_run_if_linked`, hooked into
`run_assessment`'s existing `notify_run_finished.delay(...)` follow-up
call site the same decoupled way); `service.queue_scan_for_workflow_run`/
`start_and_maybe_pause`/`approve`/`reject`; a new top-level
`app/api/v1/routers/webhooks.py` (`POST /api/v1/webhooks/workflows/{id}`)
and three new endpoints on the existing workflows router
(`webhook-secret` admin, `approve`/`reject` security engineer — the same
tier `RUN_WORKFLOW`/`START_SCAN` already require, since approving *is*
authorizing a scan); `app/core/workflow/webhook_secret.py` (secret
generation/AES-256-GCM encryption, reusing `app/core/evidence/crypto.py`
directly rather than a second implementation, keyed by a new *required-
when-used* `KERVY_WEBHOOK_SECRET_ENCRYPTION_KEY` — unlike the evidence key,
not optional encryption, since a webhook secret must never sit in Postgres
in cleartext) and `app/core/workflow/replay_guard.py` (a 7th Redis-backed
store, dedup-by-signature, **fails closed** — the opposite of the rate
limiter's own deliberate fail-open, because replay protection exists
specifically to refuse something that looks legitimate); a new `beat`
Docker Compose service (no `lab_net`, no evidence volume — it only ever
enqueues tasks, it never itself reaches a target).

Decisions worth stating:

- **The inbound webhook route is deliberately outside the
  `/organizations/{organization_id}/...` prefix.**
  `test_every_organization_scoped_route_declares_a_minimum_role` correctly
  asserts every route under that prefix has a role dependency — the
  webhook's caller has no session for any organization at all, so nesting
  it there would need a special-cased exemption to an otherwise-clean
  invariant. `workflow_id` alone (unguessable) plus the HMAC signature is
  the authentication; the workflow row's own `organization_id` column
  supplies the tenant.
- **HMAC verification is reused, not reimplemented.**
  `app/core/integrations/signing.py`'s own docstring already called
  `verify()` "the reference a receiver is written against" — this phase
  is the first thing in the codebase to actually call it as one.
- **No opt-out from the approval gate.** An earlier draft of this phase
  considered a `Workflow.requires_approval` column an operator could
  disable; dropped in favour of the closed rule above, both because it
  removes an edge case (whose `user_id` would an opted-out unattended scan
  even be attributed to?) and because it matches this platform's general
  preference for a small closed rule over a configurable exception.
- **Celery Beat's own healthcheck is disabled**, not inherited from
  `Dockerfile.worker`'s image default — that default pings a worker's own
  queue, which a Beat process never runs one of, and would otherwise
  always report the container unhealthy.

Verified: `ruff check`/`mypy app` clean; new `tests/test_workflow_automation.py`
(21 tests: schedule validation/dispatch/advance-on-tick, the approval
gate's pause/approve/reject over both a plan that would and would not
queue a scan, the async gate-once-linked-scan-finishes path, and the
webhook's signature success/missing-headers/bad-signature/expired-
timestamp/replay/wrong-kind/tenant-isolation cases); `EXPECTED_ROLES`
extended for the three new authenticated endpoints
(`tests/security/test_authorization_matrix.py`); full regression pass over
`test_workflow.py`/`test_workflows_api.py` (unaffected — every existing
manual-trigger call site defaults `unattended=False`); `docker compose
config` validates the new `beat` service.

### Deferrals

- **No vendor-specific webhook translators.** The inbound endpoint accepts
  this platform's own minimal, HMAC-signed shape only; translating GitHub's
  or GitLab's own webhook payload into it is a separate, later increment.
- **No CLI for any workflow operation**, scheduling and webhooks included —
  `kervy-ai` has no `workflow` subcommand group at all yet, confirmed
  absent before this phase; adding CLI support only for the new pieces
  while base workflow CRUD has none would be inconsistent scope creep.
- **No dashboard UI** for schedule/webhook/approval configuration — matches
  every earlier pentest-module phase's "API-only, dashboard is a later
  phase" precedent (Phase 10, task #125, is the dashboard phase).
- **No rate limit on the inbound webhook** — `app.core.ratelimit`'s
  policies are each a route's own deliberate choice of window/key/fail-
  direction; adding one without that same review would be exactly the
  kind of half-built control this codebase avoids.

## Pentest module, Phase 10 — security operations dashboard

Closes the gap the previous phase's own deferral named ("No dashboard UI",
task #125): an organization-wide, at-a-glance operational view, built as a
new `GET /organizations/{id}/dashboard/summary` endpoint (`Role.VIEWER`)
and an overview page in the Next.js frontend — open findings by severity,
7-day run/gate activity, remediation and pending-retest counts, coverage by
pillar, and the five most recent runs, five most recent workflow runs, and
ten highest-risk open findings.

The data model needed nothing new — `Finding`, `AssessmentRun`,
`WorkflowRun`, `RemediationTask`, and `ScanResultRecord` already carried
everything the summary needed. The gap was entirely on the query/API/
frontend side, and the Jinja2 dashboard (Phase 17) had already solved half
of it: `app/web/queries.py`'s own rule — *no hardcoded dashboard values,
every number is a real query* — was exactly right for this endpoint too.
Rather than reimplement it, that module moved to
`app/core/dashboard/queries.py` (core domain logic two presentation layers
both call, not a web-only concern) and gained three new functions:

- `pillar_coverage_for()` — the org-wide version of
  `app/core/reporting/build.py::_pillar_coverage()`'s per-report question.
  Both now read one shared `PILLAR_PREFIXES` table (moved to
  `app/core/reporting/model.py`, next to the `PILLARS` tuple it was always
  paired with) rather than each keeping its own copy that could drift.
- `remediation_summary()` — open and overdue counts straight from
  `RemediationTask.closed_at`/`due_date`, the task's own state rather than
  a re-derivation of the finding's status (see that model's own module
  docstring on why there is exactly one status column for a finding's
  security state).
- `pending_retest_count()` — `Finding.status == RETEST_REQUIRED`, full
  stop. A remediation is a claim until a retest checks it, so the finding's
  own status machine already answers "how many are waiting", with no
  second query against `retest_results` needed.

Findings management itself was deliberately **not** rebuilt here: the ten
highest-risk findings shown have no filtering, pagination, or status
transitions from this surface. That UI already exists (the Jinja2
dashboard's `/findings` page and the `GET/POST .../findings` API); a
fuller Next.js findings view is pentest-module Phase 11 (reporting
polish), not this phase.

Caught during testing, not by any static tool: an early version of this
phase's own test suite referenced a `Finding`'s `.id` before flushing the
session, which produced a `NULL` foreign key on the very next insert and
then, because the failed transaction wasn't cleanly rolled back within one
pytest session, cascaded into 100+ unrelated failures across
`test_web.py`, `test_reporting.py`, and the authorization matrix — all from
one missing `await db_session.flush()`. Root-caused from the actual
`asyncpg.exceptions.NotNullViolationError` in the traceback rather than
chasing the symptom in each of the "downstream" files.

Verified: `ruff check`/`mypy app` clean; targeted suite (dashboard,
Jinja2-dashboard, reporting, authorization-matrix — the four modules
touched by the query-module move) green: 359 passed, 2 skipped; full
backend suite green: 1851 passed, 2 skipped, 0 failed. Frontend
`lint`/`typecheck` clean. See
`docs/dashboard.md` for the full design and what this phase deliberately
left out (no historical trend, no export, no cross-organization view).

## Rebrand — Aegis AI Security → Kervy Security

A user-directed rename, executed as a full technical rebrand rather than a
branding-only pass: every `AEGIS_*` environment variable, the
`X-Aegis-Signature`/`X-Aegis-Timestamp`/`X-Aegis-Event` webhook-signing
headers, the `aegis_session`/`aegis_csrf` cookies, every Redis key prefix,
every `AEGIS-<engine>-<rule>` finding/probe-ID code, the Celery app/task
names, the CLI (`aegis-ai`/`aegis-mcp` → `kervy-ai`/`kervy-mcp`,
`backend/aegis_cli` → `backend/kervy_cli`), the package names in
`backend/pyproject.toml`/`frontend/package.json`, and every doc/comment
mention now read `Kervy`/`KERVY`/`kervy`.

The one piece that could not be a text substitution: the Postgres
Row-Level Security session variable (`app/db/tenant_context.py`) is named
inside the `USING`/`WITH CHECK` SQL text of every `tenant_isolation`
policy, baked in by the five historical migrations that each created one
(`b2e6f4a91c7d`, `e1f4b8c72a90`, `f2a8c91e6b3d`, `a3d7e05c1f92`,
`d8b3f6a1c2e4`). Editing those files would rewrite what actually ran —
this codebase's own established discipline for migrations (append-only,
same reasoning as the audit log's own "no update/delete code path")
forbids that regardless of the reason. Instead, a new migration
(`e1d16423a6b1`) reads the live, authoritative table list from
`pg_policies` (rather than retyping it from five source files) and issues
one `ALTER POLICY ... USING (...) WITH CHECK (...)` per table, moving
`aegis.org_id` to `kervy.org_id`; `tenant_context.py` ships the matching
code change in the same commit, since a deployment running either half
without the other would see every RLS-covered query return nothing —
the same fail-closed behaviour an unset session variable already
produces, never another organization's rows.

Decisions worth stating:

- **Historical Alembic migrations are untouched, on principle** — not
  merely because it was easier. A migration is the record of what a
  database actually ran; a bulk rename that rewrote `aegis.org_id`
  inside five already-applied migration files would make that record
  say something that never happened.
- **CHANGELOG.md's `[Unreleased]` section was rewritten in place**
  (prose mentions of the old name updated to the new one, plus this
  entry's own sibling documenting the rename itself); the released
  `[0.1.0]` section's own command-name references
  (`aegis-ai repo add`, `aegis-ai target roe|...`) were updated too,
  since the CLI itself no longer answers to those names and a changelog
  entry that stopped working as a copy-pasted command would be a worse
  historical record than one accurately renamed.
- **The GitHub repository's own name was left alone.** Renaming a
  hosted repository changes its clone URL and is a separate,
  higher-stakes action than a codebase-content rename; not attempted
  without being asked.

Verified: `ruff check`/`mypy app kervy_cli mcp_server`/`bandit -r app
kervy_cli -ll` all clean; frontend `lint`/`typecheck`/`build`/`test` (16
tests) all clean; a `git grep -i aegis` across every tracked file outside
`backend/alembic/versions/` returns nothing; the live dev and test
Postgres databases were renamed (`aegis`→`kervy`, `aegis_test`→
`kervy_test`) and their RLS policies confirmed via `pg_policies` to
reference `kervy.org_id` exclusively. The full backend suite was run
twice after the rename: the first run surfaced 6 failures, all in
`tests/test_reporting.py`, and all the same root cause — the golden
fixtures under `backend/tests/golden/` had `aegis: 0.1.0` recorded
ahead of `bandit: 1.7.9` in the "Tool versions" list, and
`render.py`'s alphabetical sort now puts `kervy` after `bandit`, so the
line order genuinely changed rather than just the name. Re-recorded
those 9 golden files with `UPDATE_GOLDEN=1` and reviewed the diff line
by line before re-running; the second full run passed clean: **1845
passed, 2 skipped, 0 failed**.

## Frontend UI redesign

A visual redesign of the Next.js dashboard, requested separately from
any pentest-module phase: modernize the look (color, spacing,
elevation, motion) without touching the underlying architecture or any
API contract. Scope was deliberately the Next.js app under `frontend/`
— the primary product UI — not the Jinja2/HTMX dashboard under
`backend/app/web/` (Phase 17's lighter, API-key-authenticated ops
view), which was left alone.

Foundation first, then a sweep: `app/globals.css`/`tailwind.config.ts`
got a richer primary color, new `success`/`warning`/`accent` tokens, an
elevation shadow scale (`shadow-soft`/`shadow-elevated`/
`shadow-popover`), a softer border-radius scale driven by one `--radius`
variable, and a small set of restrained entrance animations
(`fade-in`/`fade-up`/`scale-in`) — kept deliberately subtle per the
brief's own "avoid excessive animations" instruction. Every existing UI
primitive (`Button`/`Card`/`Input`/`Select`/`Textarea`/`Checkbox`/
`Label`) got shadows, hover/active/focus transitions, and consistent
radius; `Button` gained an `isLoading` prop (spinner + disabled, so
every submit button shows real pending state instead of just disabled).
Three new primitives — `Badge`, `Alert`, `Skeleton` — replaced ad hoc
inline-styled status pills and repeated `<p role="alert">` blocks
across the app: every status pill (run/scan/workflow status, RoE/
authorization state, role, tool risk tier) now renders through `Badge`,
and every form's top-level submit error now renders through `Alert`
(destructive tone, icon, `role="alert"`), consistently across all 9
forms that had the old pattern.

Then a page-by-page sweep applied the same language everywhere: the top
nav (sticky, backdrop blur), the org section nav (icon tabs with an
animated active-underline), the dashboard, targets (list + detail),
runs (list + detail, including a live progress bar and a pulsing
"updating" indicator on the polling run-detail view), workflows,
repositories, the agent workspace (accent-tinted "ask" panel, since
this is the one surface where the platform's AI identity is
front-and-center), and the login/register/landing pages (a single
restrained radial-gradient hero background, applied via one shared
`.bg-hero-fade` utility class, never stacked with itself).

Verified with the existing tooling (`npm run lint`/`typecheck`/`test`/
`build`, all clean) plus an actual visual check, since none of those
tools verify what something looks like: `app/globals.css`/
`tailwind.config.ts` changes were screenshotted directly (headless
Chromium) in both light and dark mode, and — since automated tooling
alone would have missed it — a real Playwright-driven pass (register →
create an organization → add a target → walk every dashboard page)
caught a genuine responsive bug the static screenshots didn't: the
landing page's header row had no `shrink`/`flex-wrap` protection, so on
a narrow viewport the "Sign in"/"Get started" buttons pushed past the
right edge instead of wrapping or shrinking. Fixed (hide the redundant
"Sign in" link below the `sm` breakpoint, `min-w-0 truncate` on the
logo text, `shrink-0` on fixed-size elements) and re-verified at a true
390px viewport via Playwright's device-metrics emulation — headless
Chromium's own `--window-size` flag turned out to floor at 500px in
this sandbox, which is why the fix was confirmed through Playwright
rather than the raw screenshot flag.

## Agent framework, Phases 1–6 — native AI agent with zero persistence

A structured, permission-gated tool-calling layer on top of the existing AI
assistant (Phase 16): where the assistant only drafts and explains, the
agent can search assets, investigate findings, start an authorized scan,
run a workflow, and generate a report — through a closed registry of typed
tools, each carrying its own risk tier and minimum role — while adding
**zero** new persistent storage beyond an explicit, closed allowlist of
operational configuration and metrics. This also satisfies the pentest
module's own pending Phase 9, "External API / MCP surface" (task #124),
built once here rather than twice. Full design in `docs/agent.md`.

Delivered across six phases:

1. **Provider layer + `AgentContext`** — `app/core/agent/provider/`
   (Anthropic, Gemini, and `openai_compatible` — which also covers any
   local/self-hosted endpoint speaking the OpenAI wire format, so "support
   a local model" needed no separate provider implementation); `agents`/
   `agent_providers` tables; the one-way import-boundary test.
2. **Tool contract + registry + first `READ_ONLY` tools** — `Tool`
   (typed input/output, risk tier, minimum role, timeout), the closed
   registry, and `search_assets`/`get_asset`/`search_findings`/
   `get_finding`/`get_scan_status`/`get_scan_results`/
   `get_workflow_status`, each wrapping an existing service-layer function
   in-process.
3. **Investigation, permissions, approvals, execution tracking** —
   `Investigation`'s state machine, the two-layer `authorize_role()`/
   `authorize_sensitive()` permission model, `STANDARD`/`SENSITIVE` tools
   (`create_report`, `create_workflow`, `run_workflow`, `start_scan`), the
   `agent_configurations`/`agent_usage_metadata` tables, and the
   zero-persistence test cluster in `tests/security/test_agent_boundary.py`
   (closed-table-set pin, column-name-fragment scan, a stricter exact-set
   allowlist on `AgentUsageMetadata`, a static Redis-TTL scan, a structural
   check on `record_tool_call`'s own signature, a dynamic audit-row check,
   and the import boundary).
4. **`planner.py` + `runtime.py`** — natural-language request → evidence-
   fenced `Plan` → executed tool calls, pausing at the first unapproved
   `SENSITIVE` step rather than failing; `analyze_finding` reusing
   `AIService.explain_finding` in-process.
5. **API + frontend** — the six-endpoint router
   (`GET /tools`, `POST /tools/{name}/call`, `POST /investigate`,
   `GET /investigate/{id}/status`, `POST /investigate/{id}/approve`,
   `POST /investigate/{id}/cancel`); the Next.js AI workspace
   (`frontend/app/(dashboard)/organizations/[id]/agent/`), whose
   transcript lives in React state only — no persisted conversation,
   client- or server-side.
6. **Automation + external API/MCP** — investigation-completed/failed
   events fanned out through the existing `app.core.integrations`
   pipeline, and `backend/mcp_server/` — a hand-rolled JSON-RPC 2.0 stdio
   server (`initialize`/`tools/list`/`tools/call`), a thin client over the
   same REST endpoints via `kervy_cli`'s own `ApiClient`, with zero
   imports of `app.core.agent` — a structural proof an external MCP caller
   gets no more access than the authenticated REST API already grants.

Decisions worth stating:

- **The zero-persistence rule is enforced by tests, not just by design.**
  A closed-table-set pin test fails a future PR that adds a sixth agent
  table until someone deliberately edits it; a column-allowlist test
  forbids any `content`/`text`-shaped column on `AgentUsageMetadata`
  specifically; a static test greps `session_store.py` for every Redis
  write and asserts each one carries an explicit expiry; a dynamic test
  runs a tool with a fake secret and asserts it reaches neither the audit
  row nor the usage-metadata row.
- **The investigation session store fails closed, unlike this codebase's
  other five Redis-backed stores.** An unreadable or expired paused
  approval must never be read as "proceed" — the opposite trade-off from
  the rate limiter's fail-open default, made because the failure mode here
  is a bypassed `SENSITIVE`-tier approval gate, not a temporarily-
  unlimited request.
- **A `SENSITIVE` tool cannot be called directly, even by a caller with the
  role for it.** `POST /tools/{name}/call` (the endpoint `backend/
  mcp_server/` uses) refuses a `SENSITIVE` tool outright with `409` —
  every path to running one goes through `POST /investigate` +
  `POST .../approve`, so an external MCP client gets no shortcut a native
  caller does not also lack.
- **`Investigation.resume()` was never wired into the approve endpoint**,
  a deliberate fix made during design rather than after shipping a bug:
  `resume()`'s own increment of `plan_step_index` would double-advance
  past the just-approved step once `run_plan()`'s loop also incremented
  it, silently skipping execution of the approved action. The approve
  endpoint instead passes the paused `Investigation` straight back into
  `run_plan()`, whose loop already re-enters at the correct index.
- **No official MCP SDK dependency was added.** The server speaks exactly
  the three methods this platform's tools need
  (`initialize`/`tools/list`/`tools/call`), hand-rolled the same way CSRF,
  revocation, and rate-limiting are — a deliberate house-style choice, not
  an oversight.

Verified: `ruff check`/`mypy app` clean at every phase; the full backend
suite green (1652 passed, 2 skipped) after Phase 6; the RBAC route→role
matrix test extended for all six new routes; the zero-persistence test
cluster re-run standalone as well as inside the full suite.

### Deferrals

- **No live-execution SSE stream.** `investigate` already returns
  synchronously, so there is no in-flight state an SSE endpoint would have
  anything to report on until plan execution itself moves to a background
  worker — a stated future enhancement, not a gap in what shipped.
- **No `Agent`/`AgentProvider` CRUD endpoints.** The five persistent agent
  tables exist and are covered by the zero-persistence test cluster, but
  configuring them today is direct-database/migration-seeded only,
  faithful to the literal endpoint list in the approved plan rather than
  expanding scope to a settings UI this phase did not ask for.
- **`AgentTool.minimum_role_override` is inert.** The column and table
  exist; the permission check that would read it to raise (never lower) a
  tool's effective minimum role lands in a later phase.
- **No per-tool rate-limit policy entries yet.** `Tool.rate_limit_rule`
  exists on the contract; wiring specific policy names into
  `app.core.ratelimit.policy.POLICY` per tool is deferred alongside the
  `AgentTool` override work above.
- **Scheduled automation is still blocked on Celery Beat**, unchanged from
  the pentest-module Phase 1 note: `create_workflow` can store a
  `TriggerKind.SCHEDULE` workflow correctly, but nothing fires it on a
  schedule until Celery Beat exists (pentest-module Phase 8).

## Social OAuth login and password reset

### Context

Requested directly: add SSO login and a forgot-password/reset-password
capability. Scoped down to **social OAuth** (Google, GitHub) rather than
enterprise SAML/OIDC — the two aren't the same feature wearing different
names; SAML/OIDC federates identity from an organization's own IdP for
enterprise SSO, while social OAuth is "log in with an account you already
have" for individual signup. `docs/deployment.md`'s "What is not provided"
still correctly says no enterprise SAML/OIDC exists.

### Design

The identity rule that shapes everything else: `OAuthIdentity` links
`(provider, provider_user_id)` to a `User`, never email. A provider profile
is matched against an existing account only by that pair; a callback whose
email matches an existing password-only account refuses with `409` rather
than linking — see `app/models/oauth.py`'s module docstring for why matching
by email would be an account-takeover vector (a provider that does not
itself verify email ownership would let anyone claim any address). This is
the same disclosure `POST /auth/register`'s duplicate-email case already
makes, applied at the same "creating a new account" moment.

`User.password_hash` becomes nullable for an OAuth-only account. Every
caller that reads it now checks for `None` first (`login`'s handler; there
is no other reader).

Both new external-facing pieces — OAuth token exchange/profile fetch, and
the platform's password-reset email — go through this platform's
established "platform egress" pattern (`app/core/vcs/egress.py`,
`app/core/assistant/egress.py`, `app/core/integrations/egress.py`): a fresh
`RunContext` per call, `allowed_domains` holding exactly the one host that
call needs, through the sole `GatedTransport`. `app/core/oauth/egress.py`
is the fourth instance. The password-reset email turned out to need no new
egress module at all — `app/core/integrations/send.py::send_email` is
already generic over its relay host/port/credentials and recipient list
(the per-organization `NotificationChannel` binding lives one layer above
it, in `app/core/integrations/service.py`, never inside `send_email`
itself), so `app/core/password_reset_email.py` calls it directly with the
platform's own `KERVY_PLATFORM_SMTP_*` settings.

The OAuth authorization-code flow's CSRF protection is a single-use,
Redis-backed state nonce (`app/core/oauth/state.py`) — the same
fail-closed idiom `app/core/workflow/replay_guard.py` established for
Phase 8's webhook replay protection, the eighth Redis-backed store in this
codebase. It plays the role the anonymous CSRF token
(`app/core/csrf/anon.py`) plays for `/auth/login`/`/auth/register`: there is
no session yet to bind an ordinary token to, and a provider-issued redirect
cannot carry a custom header.

Password reset: `PasswordResetToken` follows `ApiKey`'s own secret-handling
shape exactly — 256 bits of CSPRNG output, SHA-256 digest stored, plaintext
shown/emailed once. A successful reset sets `tokens_valid_after` and revokes
every `UserSession` row, the identical "log out everywhere" cutover
`/auth/logout-all` uses — a password reset is exactly the "I think this
account was compromised" case that mechanism exists for. `forgot-password`
is always `202`, whether or not the address is registered, has no local
password, or the platform has no mail relay configured — the same
non-enumerating shape as login's generic "invalid email or password".

`forgot-password` and `reset-password` were added to CSRF's `EXEMPT_PATHS`
rather than `ANONYMOUS_CSRF_PATHS` — a real distinction, not a shortcut.
`login`/`register` need the anonymous token because they establish a
session an attacker could hijack via login-CSRF; `forgot-password` and
`reset-password` never read the caller's session at all (their entire
authority is their own request body — an email address, or a bearer token
plus a new password), so a forged request achieves nothing a direct call
would not already achieve. Caught in testing, not by design review: the
first test run failed with `403` because the shared test client already
carried a session cookie from an earlier `register()` call in the same
test — a real scenario (a logged-in person using forgot-password from an
authenticated tab), not a test artifact to work around.

### What was deliberately not built

- **No account linking UI.** An existing password account and a later OAuth
  sign-in with the same email do not merge — the callback refuses instead.
  Deliberate for this pass (see the identity-rule reasoning above); a
  "link this OAuth identity to my existing account" authenticated flow is a
  reasonable follow-up but a distinct feature with its own confirmation
  step, not assumed here.
- **No enterprise SAML/OIDC.** Scoped out at the start; see Context above.
- **No "remember this device" or session-length distinction** between a
  password login and an OAuth login — both issue the same session shape.

### Verified

`ruff check`/`mypy app` clean. Targeted suite (`test_oauth.py`,
`test_password_reset.py`, `test_auth.py`, `test_csrf.py`,
`test_rate_limit.py`, `test_authorization_matrix.py`): 324 passed, 2
skipped. OAuth's outbound calls never touch a real network in tests: a
`FakeDnsResolver` satisfies the scope engine's allowlist check and `respx`
replaces the actual socket, the same two-part substitution
`tests/test_assistant_api.py::_worker_transport` established for the AI
lab fixture. Full backend suite run as the final gate before commit.

## Membership control: close the owner-grant gap

### Context

Asked directly to confirm that an organization's owner has full
administrative and membership control, without global system privileges or
cross-tenant access. Cross-tenant isolation and "no global privileges" were
already true (guarantee #12, #26 — RLS plus `require_membership`'s 404-not-
403). Membership control was not: `app/api/v1/routers/organizations.py` had
only `invite_member` — no way to remove a member or change an existing
member's role existed at all, regardless of who was asking. And
`invite_member`'s `Role.ADMIN` minimum meant an Admin, not just an Owner,
could grant `Role.OWNER` to anyone, including an account they control —
a real privilege-escalation path, not a hypothetical one, since `Role.OWNER`
is the single most senior role in `seniority_order()` and nothing above it
exists to check the grant.

### Design

Two new endpoints, `PATCH` and `DELETE` on
`/organizations/{organization_id}/members/{member_id}`, both `Role.ADMIN`
minimum like `invite_member` — an Admin can still manage ordinary
membership day to day. The carve-out: any operation that grants, changes
away from, or removes `Role.OWNER` additionally requires the caller's own
membership to already be `Role.OWNER` (`membership.role.at_least(Role.OWNER)`,
true only for an owner, since owner is index 0 in `seniority_order`). The
same check was added retroactively to `invite_member` for the grant side of
this — the endpoint already existed but the gap was in what it permitted,
not a missing route.

An organization's last remaining owner cannot be demoted or removed at all,
even by another owner — refused with `409`, not merely discouraged. Without
that rail, the *last* owner-only check would still pass (they are an owner,
demoting/removing themselves), and the organization would be left with no
one able to perform an owner-only action ever again, including undoing the
mistake. `_owner_count()` is a single `COUNT(*) WHERE role = 'owner'` scoped
to the organization, checked before the write, never after.

### What this does not change

- Ordinary role changes (viewer ↔ analyst ↔ security_engineer ↔ admin) stay
  `Role.ADMIN` minimum, unchanged from `invite_member`'s existing bar.
- No self-service "leave organization" distinct from the new `DELETE`
  endpoint — a member removing their own membership uses the same route an
  admin would, and is subject to the same last-owner rule if they happen to
  be it.
- No organization deletion or rename endpoint — out of scope for this pass,
  unchanged from before.

### Verified

`ruff check`/`mypy app` clean. New tests in `tests/test_organizations.py`:
admin cannot grant or revoke owner, owner can change a member's role, the
last owner cannot be demoted or removed, a second owner can then be
demoted, admin can remove a non-owner member, and removing a member by id
from another organization is 404 (not 403, not silently ignored — the same
non-disclosure every other cross-tenant path in this platform uses).
`tests/security/test_authorization_matrix.py` updated with both new
routes. Full backend suite run as the final gate before commit.

## Two-factor authentication (TOTP)

### Context

Requested as a direct follow-on to the OAuth/password-reset work: the
platform's login flow was still password-only. TOTP is the standard,
free, no-recurring-cost second factor — no external service or paid API
required, matching the deployment's existing "no unnecessary paid
dependency" posture.

### Design

`pyotp` (RFC 6238), not a hand-rolled implementation. `User` gains
`totp_secret_encrypted` (AES-256, `KERVY_TOTP_ENCRYPTION_KEY`, mirroring
`webhook_secret_encryption_key`'s "not optional encryption" pattern
exactly — unset means the feature refuses with `503`, never stores a
secret in cleartext) and `totp_enabled`. A new `TotpRecoveryCode` table
mirrors `ApiKey`'s own shape: ten single-use codes minted at enable time,
shown once, stored as SHA-256 digests.

`POST /auth/login` returns a `TotpChallenge` instead of a session once
`totp_enabled` is true — a short-lived JWT deliberately missing the
`iat_us`/`jti` claims `decode_access_token` requires, so it structurally
cannot be accepted as a Bearer token by anything else in the platform,
whatever it is presented as. `POST /auth/login/2fa` redeems it exactly
once through a new Redis-backed store (`app/core/twofactor/
challenge_store.py`) — the ninth such fail-closed store in this codebase,
following the identical idiom `OAuthStateStore` and `WebhookReplayGuard`
already use: refuse the login attempt outright if Redis is unreachable or
the challenge was already claimed, never treat an unconfirmed state as
fresh.

`/auth/login/2fa` was added to `ANONYMOUS_CSRF_PATHS` (not `EXEMPT_PATHS`):
unlike `forgot-password`/`reset-password`, it *does* establish a new
session, so it is exposed to the same login-CSRF risk `/login` and
`/register` already are — found by a genuine test failure during this
work, not assumed in advance.

The frontend's enrollment lives at `/account/security` (a new page —
no account/settings surface existed before this): `POST /auth/2fa/setup`
returns a secret and a `provisioning_uri`, rendered as both a QR code
(the `qrcode` package — free, MIT-licensed, no network call, renders
client-side from a `data:` URL) and a manual-entry fallback, since not
every authenticator app can scan a QR code equally easily. `POST
.../enable` confirms with a code and shows the ten recovery codes once.
`LoginForm` gained a branch: a `TotpChallenge` response swaps the form for
a `TotpChallengeForm` step instead of redirecting, accepting either a
fresh code or a recovery code (the backend accepts either identically, so
the UI does too — no separate "use a recovery code" toggle needed).

### What this does not change

- No CLI command for 2FA management — matches the codebase's own
  precedent of leaving CLI support for a later, dedicated pass rather
  than adding one command at a time per feature.
- No backup-method beyond recovery codes (no SMS, no email fallback) —
  SMS/email 2FA are themselves weaker than TOTP and would be a downgrade,
  not an addition; recovery codes are the standard mitigation for "lost
  the authenticator app" instead.

### Verified

`ruff check`/`mypy app` clean; `npm run typecheck`/`npm run lint`/
`npm run build` clean. 18 backend tests (`tests/test_twofactor.py`) plus
3 new frontend tests (`totpCodeSchema` validation, the login form's
challenge branch). Then verified live against the actual running
application (backend + frontend + Postgres + Redis, not just build/test
output) with a scripted Chromium session covering the full flow: register
→ enable 2FA → QR code renders as a real `data:` URL → confirm code →
ten recovery codes shown → sign out → sign back in with the correct
password alone (stays on the login page, no session granted) → a fresh
TOTP code completes sign-in → sign out again → a recovery code also
completes sign-in → disable 2FA with a valid code → settings page reverts
to the disabled state. Every step passed.

## Agent provider provisioning: close the "nothing can ever configure it" gap

### Context

A live, runtime audit of the platform (starting both servers and a Celery
worker, not just reading source) found the native AI agent's own engine
(planner, tool runtime, `POST .../agent/investigate`) fully built and
correctly returning `409` when unconfigured — but there was no endpoint,
CLI command, or UI anywhere in the codebase that could ever create the
`AgentProvider` row an organization needs to clear that `409`. The only
places an `AgentProvider` was ever constructed were test fixtures. The
agent framework's own design already anticipated a local/free provider
(`AgentProviderKind.OPENAI_COMPATIBLE`, covering Ollama/vLLM/llama.cpp),
but a second, deeper gap made even that path non-functional once
provisioning existed: `platform_egress_context`
(`app/core/assistant/egress.py`) hardcoded an empty `allowed_ip_ranges`,
so `GatedTransport` refused any provider endpoint at a private or loopback
address — which is where a self-hosted model server almost always lives.

### Design

Six new endpoints on `app/api/v1/routers/agent.py`: `POST`/`GET`/`PATCH`/
`DELETE .../agent/providers` and `GET`/`PUT .../agent`, admin tier to
write and analyst tier to read — the same split `docs/workflows.md`'s
admin/security-engineer tiers use, since configuring what the agent may
reach is a configuration change, not itself a scan. `POST .../providers`
defaults `is_default: true`: creating an organization's first provider
both sets `Agent.default_provider_id` and `Agent.enabled = true` in the
same request, closing the exact trap a two-step "create provider, then
remember to separately enable the agent" flow would have reproduced. A
new `_make_default`/`_clear_default` pair in the router is the single
place that ever changes which provider is default, so `AgentProvider
.is_default` (a denormalized display flag) and `Agent.default_provider_id`
(what `_resolved_provider` actually reads) cannot drift apart, and at
most one provider per organization is ever marked default.

A new `AgentProvider.allowed_ip_ranges` column (JSON list of CIDR
strings, migration `b6f1d84a2c19`) is threaded through `ProviderConfig`
and into `platform_egress_context`'s `RulesOfEngagement.allowed_ip_ranges`
— the same mechanism a scan target's own `RulesOfEngagement` already uses
to authorize a private-network target, applied here to a provider
endpoint for the first time. The cloud-metadata address stays blocked
unconditionally regardless of this setting (`hostmatch.py`'s own
`_METADATA_IPS` check ignores the allowlist entirely), so this closes a
real functionality gap without opening the SSRF hole that check exists
to prevent.

### What this does not change

- No CLI command for provider management — `aegis-ai`/`kervy-ai` has no
  `agent` subcommand group at all today, so adding one only for
  provisioning while the rest of agent operation has none would be scope
  creep. Left for whenever agent CLI support is built generally.
- No dashboard UI for provider configuration — matches every earlier
  phase's "API-only, UI is a later phase" precedent.
- `api_key_env_var` remains a variable *name*, never a value — this
  endpoint set does not change how a provider's actual credential reaches
  the process; that is still the deployment operator's own environment
  configuration, unchanged from Agent Phase 1.

### Verified

`ruff check`/`mypy app` clean. New `tests/test_agent_provisioning.py`:
creating a provider never returns a secret, creating a default provider
enables the agent and clears `investigate`'s `409`, a second
non-default provider does not replace the first, an invalid CIDR is
rejected at write time (`422`), a local `openai_compatible` provider's
`allowed_ip_ranges` survives the round trip into the actual `RunContext`
`platform_egress_context` builds, updating `is_default` moves the agent's
default provider, deleting the default provider leaves the agent
unconfigured (not broken — `investigate` cleanly returns to `409`) rather
than pointing at a row that no longer exists, provider listing is scoped
to the caller's own organization, an unknown autonomy mode is rejected at
write time, and a default-provider id from another organization is
refused with `404`. RBAC and tenant isolation for all six routes are
covered generically by `tests/security/test_authorization_matrix.py`
(registered in `EXPECTED_ROLES`). Full backend suite run as the final
gate before commit.
