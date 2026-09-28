# Guardrails: AI/LLM controls, human-in-the-loop, and security defaults

This page pulls one question — *what stops this platform, or the AI it uses
internally, from doing something nobody authorized?* — out of the dozen docs
that each answer a slice of it. It duplicates none of their detail;
each section links to the page that carries the mechanism, the tests, and
the "what this does not cover" honesty. Read this page for the map, and the
linked page for the territory.

## 1. Guardrails on the AI/LLM layer itself

The platform contains two separate uses of AI, and they are governed
differently on purpose (`docs/ai-security-testing.md`).

### 1.1 The AI *assistant* (drafts and explains; never acts)

`app/core/assistant/` is optional — the full test suite passes with **no**
AI provider configured at all (guarantee #18, `docs/security-model.md`).
Where it is configured, four independent controls bound what it can do:

| Control | Mechanism | Source |
|---|---|---|
| **Closed capability set** | `Capability` is a `StrEnum` (`app/core/assistant/autonomy.py`); a capability not listed cannot be requested. Adding a new power is a deliberate code review, not a config change. | `autonomy.py` |
| **Autonomy ladder, per organization** | `OFF < ASSIST < RECOMMEND < APPROVAL_REQUIRED < EXECUTE`. Every capability has a minimum mode; `permits()`/`require()` enforce it before the assistant runs. Default is `ASSIST`. | `autonomy.py` |
| **Target-touching actions are refused at every mode, including `EXECUTE`** | `TARGET_TOUCHING` (`execute_scan`, `grant_authorization`, `extend_authorization`, `modify_scope`, `change_finding_status`, `change_finding_severity`, `send_request_to_target`) is checked independently of the mode — raising the mode cannot grant one of these, because they are not "high autonomy," they are actions the AI layer does not have. | `autonomy.py`, `refuse_target_touching()` |
| **Import-linter boundary** | Nothing in `core` outside `core/assistant/` imports it, so the dependency only runs one way: the assistant can read platform state, but no scan, scope, or authorization code path can be reached *through* it. Enforced statically, not by convention. | `docs/ai-security-testing.md` §"Where the AI layer stops" |
| **No AI-side memory or data retention** | Every call to `AIService.generate`/`structured_output` is a single, stateless request: nothing the assistant sees is cached, embedded, fine-tuned on, or otherwise kept by the AI layer itself for a *later* call, a different run, or a different organization to draw on. The only things persisted are the platform's own audited rows (`AiDraft`, and evidence bundles) — written for a human to read and explicitly accept, never as a store the model itself queries back. | `app/core/assistant/service.py`, `AiDraft` |

So under any configuration, the assistant can explain a finding, draft a
remediation, draft a severity rationale, summarise a run, correlate or
prioritise findings, and *propose* (never run) a scan command. It cannot
start a scan, grant or extend authorization, touch scope, change a
finding's real fields, or send a request to a target. Guarantee #17 in
`docs/security-model.md` states this as a platform guarantee, verified by
the import-linter rule rather than by trusting every caller to check.

**On "no AI-side memory," concretely:** each request to the configured AI
provider carries only what that one call needs — the specific finding,
evidence, or run being drafted about — and the response is written to a
platform-owned table or discarded, never appended to a running context the
next unrelated call could see. This holds today because every capability
is single-shot (there is no conversation state to leak *from*), and it is
a design constraint on work still to come, not just a description of what
exists: the pentest module's planned `AiConversation`/`AiMessage` tables
(multi-turn evidence Q&A) must remain the platform's own record of a
conversation, scoped and RLS-isolated the same as every other row, and
must never become a memory the AI layer itself accumulates and reuses
*across* conversations, runs, or organizations. A future capability that
wanted cross-run memory would need to say so as its own reviewed control
here, not inherit one by default.

### 1.2 The AI security *engine* (attacks the target under test; never harms it)

This is the opposite direction — testing *someone else's* LLM application —
and its guardrail is what a "success" is allowed to mean
(`docs/ai-security-testing.md`, `docs/BUILD_SPEC.md` §2.2):

- **Marker-based detection only.** Every run mints a random canary
  (`AEGIS-CANARY-<random>`); a probe succeeds when *that token* appears
  where it should not, or a response is structurally what was being tested
  for — never when the model produces something judged "harmful." There is
  no harmful-content corpus in the repository, and no scoring rubric to
  disagree with.
- **No weaponized payloads ship.** No jailbreak whose payoff is CBRN,
  weapons, CSAM, or targeted harassment content; harm-category coverage, if
  any, checks only that a refusal occurred, using benign stand-ins
  (`docs/BUILD_SPEC.md` §2.2).
- **An optional judge is off by default**, and if an operator enables one,
  its precision and recall must be published — an unmeasured judge is
  presented as an opinion, not evidence.
- **Single-shot findings are capped at MEDIUM confidence**, so one
  non-reproducing response is never reported with the same weight as a
  finding that reproduces on every trial.
- **Statistical honesty.** A finding is raised only when the attack's ASR
  lower bound exceeds the paired control's upper bound (Wilson 95% CI) — a
  benign prompt producing the same observable means the application isn't
  being subverted, and reporting it as one would be a false positive by
  construction.

### 1.3 Payload and scope policy (applies to every probe, AI or API)

`docs/BUILD_SPEC.md` §2 is precedence-level authority — it is never relaxed
by a later document. It also governs the non-AI engines: no privilege
modification, deletion, or state mutation in safe mode (the default); no
live exploitation of downstream systems (insecure-output-handling probes
stop at a proof-of-reachability marker, never RCE or destructive SQL); and
every probe declares its `payload_source` and licence.

## 2. Human-in-the-loop checkpoints

Every point below is a place the platform requires a person to decide,
rather than inferring consent or correctness from configuration.

| Checkpoint | Who | Enforced where | Why it cannot be automated around |
|---|---|---|---|
| **Authorization to test a target** | Admin or Owner only — one step above Security Engineer, and above the ceiling any API key can reach | `POST` authorization grant, checked server-side on every request via the scope engine | This is the platform's entire premise: a human takes accountable responsibility for testing a system. `docs/rbac.md`, `docs/authorization-and-scope.md` |
| **Starting, cancelling, or retesting a run** | Security Engineer or above | RBAC route→role matrix, pinned by test | A run is a live action against a target; drafting one is not the same as sending it |
| **Accepting an AI-authored draft** (remediation text, severity rationale, run summary) | Any role permitted to act on the underlying object | Draft persistence + explicit accept workflow (`app/core/assistant/service.py`); a draft is inert until accepted | The assistant produces an artifact a human reads and either accepts or discards — it never becomes "the finding" on its own |
| **Changing a finding's status or assigning remediation** | Analyst or above | RBAC route→role matrix | Only a "real," non-draft field write; never reachable by the assistant regardless of autonomy mode (§1.1) |
| **Publishing findings to a pull request** | Security Engineer, deliberately *not* Admin | `docs/rbac.md`, `docs/pull-requests.md` | Keeps a CI credential from needing admin scope, while still being a human-authorized action taken through a role, not a bot |
| **Granting an API key and its scope ceiling** | Admin or Owner | API keys cap at Security Engineer even if minted by an Owner — a CI credential can never reach the authorization-granting role | `docs/rbac.md` §"API key ceilings" |
| **Retest evidence review** | Whoever owns the remediation | Before/after evidence pair, not an automatic status flip | A retest produces evidence; closing the finding is still a decision the assignee makes |
| **Rules of engagement per target** | Admin, alongside the authorization grant | `RoE` record checked by the scope engine at run time | Scope is not just "in/out of bounds" — RoE encodes what kind of testing was actually agreed to |

The common shape: the platform will happily *compute, draft, propose, or
measure* — the AI assistant above is one instance of this, not the only
one — but every action with a real-world or record-of-truth effect requires
a named person's role to permit it, checked server-side, never inferred
from what the UI happens to show.

## 3. Security best practices already in the platform

Grouped by what each defends; each links to the doc with the full mechanism,
the test that would catch a regression, and its stated limits.

**Outbound requests never bypass authorization.**
`GatedTransport` is the *only* place an HTTP client is constructed anywhere
in `app/` — enforced by a static grep-based test, not a convention. It fails
closed on an unresolved scope, blocks cloud-metadata addresses
unconditionally, re-resolves DNS at send time (no rebinding window), and
never auto-follows a redirect out of scope. `docs/authorization-and-scope.md`,
`docs/security-model.md` guarantees #1–#6.

**Authentication.** Argon2id password hashing; httpOnly `SameSite=Lax`
session cookies signed as JWTs (the frontend never reads the token itself);
structured errors that never leak stack traces. `docs/authentication.md`.

**Rate limiting on authentication endpoints.** Login and register are
budgeted on two independent dimensions (per-identity and per-IP) so neither
alone is bypassable; identity keys are HMAC'd so the store never holds a
plaintext email; it throttles (429 + `Retry-After`) rather than locking
accounts out, because a lockout is itself a denial-of-service primitive; and
it fails **open** on a Redis outage (logged at error level) since Argon2id
still stands behind it. `docs/rate-limiting.md`.

**CSRF protection on cookie-authenticated writes.** The token is an HMAC over
the session cookie's own value, not a plain double-submit — so an attacker
who can merely *set* a cookie (a sibling-subdomain quirk, a plain-HTTP MITM)
still cannot forge one. Enforced as middleware over every route rather than a
per-route decorator, so a route nobody remembered to annotate is still
covered. Login/register CSRF is closed too, via a pre-session, `__Host__`-
prefixed token. Bearer-token callers are exempt, because a cross-site page
cannot attach that header. `docs/csrf.md`.

**Server-side JWT revocation.** Per-token revocation on logout (Redis
deny-list keyed by `jti`) and a durable per-user cutoff on "log out
everywhere" (Postgres timestamp, survives a Redis restart). Unlike every
other Redis-backed control here, this one fails **closed** — an unreachable
revocation store means every JWT request is refused, because "could not
tell if it's revoked" is exactly the failure a live revoked token
represents. `docs/revocation.md`.

**RBAC, enforced server-side only.** Owner > Admin > Security Engineer >
Analyst > Viewer, pinned by a route→role matrix test so a route silently
downgraded from Analyst to Viewer fails the suite, not just a manual review.
Cross-tenant access returns 404, never 403, so a non-member cannot even
confirm an organization exists. `docs/rbac.md`, `docs/security-model.md`
guarantee #12.

**Evidence integrity.** Redaction runs *before* anything is written — the
store refuses to persist a bundle containing an unredacted secret — and
every bundle is content-addressed and hash-chained, so tampering is
detectable by re-hashing rather than trusted by assumption. No public
report or evidence URLs exist; every read goes through the authenticated
API and an organization-membership check. `docs/reporting.md`,
`docs/security-model.md` guarantees #7–#10, #22.

**Audit logging.** Every auth and organization-membership action is written
append-only and hash-chained, both as database rows and a JSON-lines file;
no update or delete function exists in the audit service at all — not
disabled, absent. `docs/security-model.md` guarantee #11.

**Secrets never invented, never persisted raw.** Every CVE/GHSA/OSV/CWE
identifier is shape-verified against its source before it can appear in a
finding; an unverifiable one is dropped, not repaired into something
plausible-looking (`docs/BUILD_SPEC.md` §0.1 — never fabricate a mapping).
Credential schemas hold variable *names*, never values; `detect-secrets`
runs in CI against a reviewed, hash-only baseline. `docs/security-model.md`
guarantees #7, #14.

**Supply chain.** SCA (`pip-audit`), SAST (`semgrep`, `bandit`), IaC
(`checkov`), container image scanning, end-of-life runtime detection,
license-obligation and name-confusion (typosquat) engines, and known-
malicious-package matching all run with no live network dependency for the
decision itself — an offline ruleset, not a registry fetch at scan time.
`docs/supply-chain.md`.

**The demo/lab target is isolated by construction.** Loopback-only by
default, an `internal: true` Docker network with no egress, refuses to
start if a real provider API key is present in its environment, synthetic
data only. `docs/security-model.md` guarantee #21.

**A missing tool is a visible gap, never a silent pass.** Every check
(probe, AppSec engine, plugin, AI probe) wraps its execution so that one
failure is recorded as `AEGIS-*-099 — not tested` and the run continues —
because a run that loses fifteen good probes to one crashing probe is worse
for the operator than a run with a hole it can see, and a scanner that goes
quiet on failure is the most dangerous kind of false negative. See
`app/core/orchestrator/{probe_check,ai_check,code_check,plugin_check}.py`
and guarantee #16.

**Plugins cannot escalate.** Third-party probe plugins receive the same
scope-bound transport as native probes (proven by a test that a bypass
attempt fails), and any result they return is force-attributed to the
plugin's own name/version — a plugin cannot file a finding under a native
probe's identity. Plugins are explicitly *not* sandboxed; the allowlist is
the control, stated rather than implied. `docs/plugin-development.md`,
`app/core/orchestrator/plugin_check.py`.

## 4. Where these stop

Stated plainly rather than left implicit, per `docs/BUILD_SPEC.md` §0's
honesty rule:

- Plugins run unsandboxed; the allowlist is the only control.
- Evidence is unredacted-secret-free but **not encrypted at rest**.
- Revoking `UPDATE`/`DELETE` on `audit_logs` at the database level is
  recommended, not enforced by this platform.
- Rate limiting covers only `login`/`register`; authenticated routes rely on
  RBAC instead (extending the policy is a table entry, not new machinery).
- The optional AI judge, if an operator turns it on, is only as good as its
  published precision/recall — the platform does not validate that number
  for them.
- This is not a guardrail/runtime-defence *product* for someone else's AI
  application (`docs/BUILD_SPEC.md` §1.2, non-goals) — it tests whether one
  exists and holds, it does not provide one.

The full self-review, including how each control above was verified and
what deliberately-broken-then-caught test backs it, is
`docs/security-review.md`. `docs/threat-model.md` names who this is
defending against; this page names what holds.
