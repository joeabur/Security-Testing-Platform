# The native AI agent

A structured, permission-gated tool-calling layer on top of the platform's
existing AI assistant (`docs/ai-security-testing.md`, `docs/guardrails.md`
§1.1). Where the assistant only drafts and explains, the agent can *act* —
search assets, investigate findings, start an authorized scan, run a
workflow, generate a report — but only through a closed registry of typed
tools, each carrying its own risk tier, minimum role, and permission check.
It is not a chatbot with function calling bolted on: there is no
conversation to bolt it onto. Every investigation is a single request that
plans, executes, and discards its own context.

**The one property every other section here supports: the agent retains
nothing.** No prompt, no response, no tool output, and no plan survives past
the request that produced it, beyond a short-lived, fail-closed cache used
only to resume a paused approval (`Zero persistence`, below). This is a
platform guarantee (`docs/security-model.md` guarantees #29–#30), not a
convention — seven tests in `tests/security/test_agent_boundary.py` enforce
it structurally.

## Architecture

```
app/core/agent/
  provider/           # AIProvider implementations: anthropic, gemini,
                       # openai_compatible (covers hosted OpenAI *and*
                       # local/self-hosted — vLLM/Ollama/llama.cpp speak the
                       # same wire format); factory.py picks one from an
                       # AgentProvider row, never from global settings
  context.py           # AgentContext — built once per request, discarded
                        # when it returns
  tools/
    contract.py         # Tool dataclass + RiskLevel + invoke()
    registry.py          # the closed list of Tool instances
    assets.py, findings.py, analysis.py, runs.py, workflows.py, reports.py,
    scans.py             # one module per capability area, each wrapping an
                          # existing service-layer function
  permissions.py        # authorize_role() + authorize_sensitive()
  investigation.py       # Investigation state machine (in-process)
  session_store.py       # Redis-backed pause/resume cache, fails closed
  planner.py             # natural-language request -> Plan
  runtime.py              # executes a Plan's steps, pauses at an
                           # unapproved SENSITIVE step
  audit.py                # fixed-shape metadata -> AuditEvent + AgentUsageMetadata
```

A one-way import boundary, mirroring `app/core/assistant/`'s own: nothing
outside `app/core/agent/` is reachable *through* it, proven the same way —
`tests/security/test_agent_boundary.py` greps for a reverse import and
fails the build if one appears.

### Multi-provider by construction

`AgentProvider` is a per-organization, per-row configuration — `kind`
(`anthropic` / `openai` / `gemini` / `openai_compatible`), `endpoint`,
`model`, and `api_key_env_var` (a variable **name**, never a value, the
same discipline every other credential reference in this codebase follows).
`openai_compatible` is what a local or self-hosted endpoint uses too:
vLLM, Ollama, and llama.cpp all speak the OpenAI chat-completions wire
format, so "support a local model" needed no separate provider
implementation, only this row pointed at `http://localhost:.../v1`. Nothing
in `app/core/agent/` hardcodes a provider choice; `provider/factory.py`
reads it from the organization's `Agent.default_provider_id` at request
time. Every provider call — hosted or local — still goes through
`platform_egress_context` (`docs/ai-security-testing.md`), so a provider
endpoint that resolves to cloud metadata is refused exactly as a scan
target would be.

### Tools: the only thing the AI can do

A `Tool` (`app/core/agent/tools/contract.py`) is a frozen dataclass:
`name`, `description`, `input_model`/`output_model` (Pydantic — the
handler's real signature, validated on every call), `risk_level`,
`minimum_role`, `handler`, `timeout_seconds`, `rate_limit_rule`.
`Tool.invoke()` is the one call site every tool call passes through: it
validates the raw argument dict against `input_model` before the handler
ever sees it, calls the handler, and runtime-checks the result against
`output_model` before returning it. The AI never gets a database session,
a shell, or an HTTP client of its own — only what a registered tool
exposes, and every tool wraps an *existing* service-layer function
in-process (the same `queue_run`, `build_report`, `trigger_from`/`start`,
finding/asset queries the REST API itself calls), never a second HTTP hop
back into the platform's own API.

Fifteen tools exist today, in three risk tiers:

| Tier | Minimum role | Tools |
|---|---|---|
| `READ_ONLY` | Viewer | `search_assets`, `get_asset`, `search_findings`, `get_finding`, `analyze_finding`, `answer_evidence_question`, `correlate_findings`, `prioritise_findings`, `get_scan_status`, `get_scan_results`, `get_workflow_status` |
| `STANDARD` | Analyst / Admin | `create_report`, `create_workflow` |
| `SENSITIVE` | Security Engineer | `run_workflow`, `start_scan` |

`answer_evidence_question`, `correlate_findings`, and `prioritise_findings`
(Pentest module Phase 7) reuse `AIService.answer_evidence_question`/
`correlate_findings`/`prioritise_findings` in-process, the same way
`analyze_finding` reuses `explain_finding` — one prompt template per
capability, evidence-fenced, gated by `Capability.ANSWER_EVIDENCE_QUESTION`
(`AutonomyMode.ASSIST`) or `Capability.CORRELATE_FINDINGS`/
`PRIORITISE_FINDINGS` (`AutonomyMode.RECOMMEND`) in
`app/core/assistant/autonomy.py`. All three are READ_ONLY: each drafts text
for a human to weigh, and none writes a finding's stored severity, status,
or relationships.

The registry (`app/core/agent/tools/registry.py`) is a closed, explicitly
enumerated list — mirroring `appsec_engines()`'s "registered, not
auto-discovered" idiom — so a tool exists because it is listed there, never
because a module happened to define one.

### Risk tiers and the permission model

Two independent checks, mirroring the assistant's own autonomy-ladder /
`TARGET_TOUCHING` separation (`docs/guardrails.md` §1.1):

- **`authorize_role()`** — the caller's effective role (the same
  `require_membership` ceiling logic used at every other HTTP boundary,
  including the API-key-vs-membership floor) must meet the tool's minimum.
- **`authorize_sensitive()`** — a no-op for `READ_ONLY`/`STANDARD`; for
  `SENSITIVE`, raises unless this specific call has been explicitly
  approved. Never bypassed by role or configuration — a Security Engineer
  calling `start_scan` still goes through the approval round trip below,
  the same way raising the assistant's autonomy mode can never grant a
  `TARGET_TOUCHING` capability.

Both are checked, in order, by `authorize_tool()`; a caller below the role
bar learns that before learning it also needed approval.

### Investigation lifecycle

A natural-language request becomes a `Plan` (`planner.py`, via
`provider.structured_output()`, evidence-fenced the same way every prompt
in this codebase is — `quote_evidence()`, an injection-resistant system
preamble, and an explicit JSON schema the provider must fill). `runtime.py`
then executes the plan's steps in order against an `AgentContext`:

- Each step's tool is authorized (`authorize_tool()`) before it runs.
- The first `SENSITIVE` step with no matching name in `approved_tool_names`
  **pauses** the investigation — `AWAITING_APPROVAL` — rather than failing
  it. Everything already executed stays in the result; nothing before the
  pause point re-runs on resume.
- On completion, an optional final summary is produced by one more
  evidence-fenced `provider.generate()` call over the step outcomes.

`Investigation` (`investigation.py`) is the state machine behind this:
`RUNNING` → `AWAITING_APPROVAL` (with a `PendingApproval` carrying only the
tool name, risk level, and its fixed description — never the raw
arguments) → `COMPLETED` / `CANCELLED` / `FAILED`. It exists purely
in-process for a single request unless a `SENSITIVE` step actually pauses
it, at which point — and only then — its state crosses into Redis.

### Zero persistence

Nothing about a request, a plan, a tool result, or a summary is written to
a database table. What *does* exist, and no more:

1. **The platform's own tables**, if a tool triggered a real action — e.g.
   `start_scan` writing an `AssessmentRun` row via the existing
   `queue_run`. That persistence already exists independent of the agent;
   the agent is a new caller of it, not a new store.
2. **One `AuditEvent` row per tool call** (`audit.py::record_tool_call`) —
   `tool_name`, `risk_level`, `duration_ms`, `status`, `error_code`,
   `request_id`. Structurally cannot carry prompt/response content: the
   function's signature has no parameter for it.
3. **One `AgentUsageMetadata` row per tool call** (`audit.py::record_usage`)
   — the observability columns listed below. Same shape restriction, and
   the model itself is column-allowlisted by test (no `content`/`text`-typed
   column may ever exist on it — `tests/security/test_agent_boundary.py`).
4. **A short-lived Redis entry, only while a `SENSITIVE` step is paused**
   (`session_store.py`) — see below.

No `ConversationHistory`, `PromptHistory`, `AgentMemory`, `AIMessage`, or
`AIResponse` table exists anywhere in this codebase, and the five
persistent agent models (`Agent`, `AgentProvider`, `AgentTool`,
`AgentConfiguration`, `AgentUsageMetadata` — `app/models/agent.py`) are the
**entire, closed set** the agent subsystem may ever write to:

- A closed-table-set pin test asserts the set Alembic actually creates for
  this module is exactly those five — a future PR adding a sixth table
  fails this test until someone deliberately edits it.
- A column-name-fragment test scans every agent table for anything that
  looks conversational (`prompt`, `response`, `message`, `conversation`,
  `content`, `transcript`, `history`).
- A column-allowlist test on `AgentUsageMetadata` specifically asserts its
  columns are *exactly* the fixed observability set — stricter than the
  fragment scan, because a metrics table is exactly where a well-meaning
  "let's also log the response for debugging" column tends to appear.
- A structural test asserts `audit.record_tool_call`'s own signature has no
  parameter named `prompt`/`response`/`content`/`input`/`output`/`result`/
  `params`/`args` — so a future call site cannot leak one through it even
  by mistake.
- A dynamic test runs a tool call and asserts the resulting `AuditEvent`
  row holds exactly the fixed operational fields and nothing else.
- A static test scans `session_store.py` for every Redis write call and
  asserts each one passes an explicit expiry.
- An import-boundary test, the same shape as the assistant's.

**`InvestigationSessionStore`** (Redis, key prefix
`kervy:agent:investigation:`, `TTL_SECONDS = 1800`) is the sixth
independent Redis-backed store in this codebase (alongside the Celery
broker, the run kill-switch, the rate limiter, JWT revocation, and the AI
spend cap — `docs/security-model.md` guarantee #27, `docs/revocation.md`).
Unlike most of those, it **fails closed**: an unreadable or expired session
means "not approvable," never "proceed as if approved" — the opposite
choice from the rate limiter's fail-open default, made deliberately because
the failure mode here is a bypassed approval gate rather than a
temporarily-unlimited request. It stores the paused `Investigation`'s state
*and* the remaining `Plan` steps (tool name + structured params — platform-
chosen data the planner produced, not a prompt or a response) needed to
resume execution; nothing else. If a caller never approves or cancels, the
entry simply expires after 30 minutes and the pending action never runs —
the safe default on either side of a lost approval.

## API surface

`app/api/v1/routers/agent.py`, prefix
`/organizations/{organization_id}/agent`:

| Endpoint | Minimum role | Behavior |
|---|---|---|
| `GET /tools` | Viewer | Discovery only — name, description, risk tier, minimum role, and JSON Schema input shape for every enabled tool. No execution. |
| `POST /tools/{tool_name}/call` | Viewer (tool's real minimum enforced internally) | Invoke exactly one tool directly, bypassing the planner — the surface `backend/mcp_server/` calls. A `SENSITIVE` tool refuses here outright (`409`): no shortcut around the approval flow. |
| `POST /investigate` | Analyst | Plan and run a natural-language request against the caller's own permitted tool set, **synchronously**. A `READ_ONLY`/`STANDARD` plan returns its final result in this response; a plan reaching an unapproved `SENSITIVE` step returns `202` with the pending approval instead of running it. |
| `GET /investigate/{id}/status` | Viewer | Read back a **paused** investigation. Nothing to read for one that already finished — its result was returned once, in the original response, and was never written anywhere. |
| `POST /investigate/{id}/approve` | Security Engineer | Resume a paused investigation past its one pending `SENSITIVE` step. |
| `POST /investigate/{id}/cancel` | Security Engineer | Discard a paused investigation without running its remaining steps. |

`call_tool` and `investigate`/`approve_investigation` all share one
enforcement shape: the route dependency is a floor (`Viewer` for
discovery/direct-call, `Analyst`/`Security Engineer` for the planner path),
and the *tool's own* minimum role and risk tier are checked again inside,
exactly as they are inside `run_plan` — a caller below a tool's real bar
gets `403`, never a silent downgrade to whatever the route alone would
have allowed. `tests/security/test_authorization_matrix.py`'s pinned
route→role table covers all six routes.

Streaming (an SSE endpoint mirroring `runs.py`'s live progress stream) is a
stated future enhancement, not built here: `investigate` already returns
synchronously today, so there is no in-flight state an SSE stream would
have anything to report on until execution itself moves to a background
worker.

## Frontend: the AI workspace

`frontend/app/(dashboard)/organizations/[id]/agent/page.tsx` +
`components/agent/agent-workspace.tsx` — a chat-shaped interface that
**does not persist conversation**. The transcript for the current
investigation lives in React state only, cleared on navigation or reload;
no `localStorage`, matching the frontend's only two existing uses of it
(the theme toggle). It follows the same server-fetch-then-client-poll
pattern `run-detail.tsx` already established for runs (poll
`GET .../status` while paused), and an approval prompt reuses
`start-run-form.tsx`'s `z.literal(true, {errorMap})` confirmation-checkbox
pattern rather than inventing a new one.

## Automation and notifications

An investigation that reaches a terminal state — `COMPLETED` or `FAILED`,
never while still `AWAITING_APPROVAL` or on a human `CANCELLED` — fans out
to the organization's subscribed notification channels through the
existing `app.core.integrations` pipeline
(`EventType.AGENT_INVESTIGATION_COMPLETED` /
`AGENT_INVESTIGATION_FAILED`, `event_for_investigation()` in
`app/core/integrations/dispatch.py`), the same way a finished assessment
run already does. Enqueuing happens in the same request transaction (cheap:
one row per subscribed channel); delivery is handed to a worker only if
anything was actually queued, so a slow or unreachable webhook can never
hold the request open — mirroring the run notifier's own split between
"record intent" and "attempt delivery."

The agent can also create a `Workflow` row (`create_workflow`, `STANDARD`
tier) with `TriggerKind.SCHEDULE` — but that trigger kind is not yet fired
by anything (Celery Beat does not exist in this codebase yet, tracked as
pentest-module Phase 8, `docs/roadmap.md`). The agent proposes and stores
the workflow correctly today; actually firing it on a schedule is a
separate, already-tracked gap this framework does not re-solve.

## External API / MCP surface

`backend/mcp_server/` is a hand-rolled JSON-RPC 2.0 stdio server speaking
the slice of MCP this platform needs: `initialize`, `tools/list`,
`tools/call`, `ping`, `notifications/initialized`. No official MCP SDK
dependency was added — the surface is three real methods, and the
codebase's own house style (CSRF, revocation, rate-limiting) already favors
a small hand-rolled protocol implementation over a heavyweight framework
dependency for a narrow, well-specified need.

It is a thin client over the *same* authenticated REST endpoints described
above, built the same way `kervy_cli` is (`kervy_cli.client.ApiClient`,
`kervy_cli.config.Profile` — zero duplication, reused directly):

- `tools/list` calls `GET /organizations/{id}/agent/tools` and translates
  the catalog into MCP's `{name, description, inputSchema}` shape.
- `tools/call` calls `POST /organizations/{id}/agent/tools/{name}/call`
  with the caller's arguments as `params`, and returns the result as MCP
  text content (`isError: true` for a tool-level failure the platform
  reported as a normal outcome — e.g. `tool_not_found` — and a JSON-RPC
  protocol-level error for anything the REST layer refused outright: role
  too low, unknown tool, a `SENSITIVE` tool called directly, bad
  arguments).

Credentials are the same API key an operator already has for the CLI
(`KERVY_API_KEY` / `kervy-ai login`'s saved profile), not a new kind of
secret to provision. `backend/mcp_server/` has **zero imports of
`app.core.agent`** — a structural proof, not just an intent, that an
external MCP client gets no more access than the authenticated REST API
already grants a native caller: every RBAC, tenant-isolation, rate-limit,
and audit control an HTTP caller passes through, an MCP caller passes
through identically, because it is the identical code path.

## Observability

Every tool call produces one `AgentUsageMetadata` row
(`app/models/agent.py`): `tool_name`, `provider`, `model`, `tokens_sent`,
`tokens_received`, `cost_usd`, `duration_ms`, `status`, `error_code`,
`request_id`. What is deliberately absent from this table, and from every
`AuditEvent` a tool call produces, is anything resembling the prompt sent,
the response received, or the tool's own output — see `Zero persistence`
above for how that absence is enforced rather than assumed.

## Database schema

The closed, five-table allowlist (`app/models/agent.py`):

| Model | Purpose |
|---|---|
| `Agent` | One row per organization — enabled, default provider, default autonomy mode |
| `AgentProvider` | An org-configured provider (`anthropic`/`openai`/`gemini`/`openai_compatible`), never a secret value |
| `AgentTool` | Per-org enable/disable and role-override for a tool the code registry defines — configuration only |
| `AgentConfiguration` | Fine-grained runtime policy — tool allowlist, rate-limit overrides — as schema-validated JSON |
| `AgentUsageMetadata` | Append-only usage/cost/performance row per tool execution |

## Related documents

- `docs/guardrails.md` §1.4 — the agent's guardrails alongside the
  platform's other AI/LLM and human-in-the-loop controls.
- `docs/security-model.md` guarantees #29–#30 — the platform-level
  statements this page's mechanisms back.
- `docs/ai-security-testing.md` — how the assistant this agent extends is
  itself governed, and how the platform's separate AI *security testing*
  engine (attacking someone else's LLM application) differs from both.
- `docs/roadmap.md` — the phase-by-phase build history, including what was
  deliberately deferred (SSE streaming, `AgentTool.minimum_role_override`
  enforcement, per-tool rate limiting, Celery Beat-fired scheduled
  workflows).
