# Workflows

A workflow is five stages: something happens, a plan is derived from it,
actions run, evidence is sealed, a result is decided.

That is not a new capability. It is the shape this platform already had, made
explicit and stored, so two questions become answerable from a record instead of
from logs:

* **Why did this run do what it did?** The plan is derived from the trigger and
  the target's configuration and nothing else, and every action it *skipped* is
  stored with its reason.
* **Did anything change between these two commits?** Two plans have the same
  digest exactly when they would do the same things.

## The stages

| Stage | What it does | What it may depend on |
|---|---|---|
| `trigger` | Records what happened | A repository change, a pull request, a schedule, or a person |
| `plan` | Derives the action list | The trigger and the target's configuration — nothing else |
| `actions` | Runs what the plan named | The same scan path the API uses, under the same scope engine |
| `evidence` | Seals what was observed | Redaction happens before the write, as everywhere else |
| `result` | Decides pass or fail | `gate.evaluate` over findings' **real fields** |

There is deliberately no branching, no user-defined step and no expression
language. A plan is a list of actions the platform already knows how to run,
and that limitation is what keeps the result deterministic.

## A workflow gains no authority

Triggering a workflow requires **security engineer** — the same role
`POST /runs` requires. A workflow that could start a scan with less authority
than starting a scan would be a way around the role, not a feature.

Defining or changing one requires **admin**, because the gate is what decides
whether a release ships. A change to `gate_config` is recorded in the audit log
as a change to the gate, not as an unlabelled "updated".

The actions themselves run through the same authorization check and the same
scope engine as any other assessment. If that check refuses, the workflow is
recorded as `refused` with the reason — not `failed`, because "we were not
authorized to do this" and "we tried and it broke" are different facts.

## An AI recommendation cannot change a gate decision

This is the phase's acceptance criterion, and it is enforced structurally
rather than by policy:

* `decide()` in `app/core/workflow/result.py` takes findings and a gate
  configuration. **It has no parameter for drafts, recommendations or
  suggestions**, so there is no argument a caller could pass to influence it.
* It builds its `GateFinding`s from each finding's real columns. AI drafts live
  in a separate table (`ai_drafts`) that this module never imports — asserted by
  a test that parses the module's imports rather than grepping its text.
* `tests/test_workflow.py` stores a draft proposing a different severity and a
  different status, re-runs the gate, and asserts the decision is byte-identical.

Adding a `drafts` parameter to `decide()` makes
`test_the_decision_function_takes_no_recommendation_parameter` fail. That is
how the property is kept, not by remembering it.

## A misconfigured gate never passes

A gate configuration is validated at two points:

1. **On write.** `POST`/`PATCH .../workflows` parses it through the same
   `load_config` the CLI gate uses and returns 422 if it does not parse. A typo
   like `max_hihg: 0` is rejected where someone typed it.
2. **On evaluation.** If a stored configuration somehow cannot be parsed, the
   workflow run is recorded as `refused`. It is never silently replaced with the
   default, and it never reports a pass.

## The API

```
POST   /api/v1/organizations/{org}/workflows                              admin
GET    /api/v1/organizations/{org}/workflows                              analyst
GET    /api/v1/organizations/{org}/workflows/{id}                         analyst
PATCH  /api/v1/organizations/{org}/workflows/{id}                         admin
DELETE /api/v1/organizations/{org}/workflows/{id}                         admin
POST   /api/v1/organizations/{org}/workflows/{id}/runs                    security engineer
GET    /api/v1/organizations/{org}/workflows/{id}/runs                    analyst
POST   /api/v1/organizations/{org}/workflows/{id}/webhook-secret          admin
POST   /api/v1/organizations/{org}/workflows/{id}/runs/{run_id}/approve   security engineer
POST   /api/v1/organizations/{org}/workflows/{id}/runs/{run_id}/reject    security engineer
POST   /api/v1/webhooks/workflows/{id}                                    HMAC signature (see below)
```

Creating one:

```bash
curl -X POST "$AEGIS/organizations/$ORG/workflows" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "main branch",
        "target_id": "'"$TARGET"'",
        "trigger_kind": "repository_change",
        "gate_config": {"fail_on": ["critical", "high"], "max_medium": 5}
      }'
```

Triggering one. A caller may describe the trigger and nothing else — not the
plan, not the actions, not the gate:

```bash
curl -X POST "$AEGIS/organizations/$ORG/workflows/$WF/runs" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"ref": "refs/heads/main", "commit": "'"$GITHUB_SHA"'"}'
```

The response carries the plan, the digest, the five stage records, and the gate
decision with the same exit codes `docs/cicd.md` documents:

| Exit code | Meaning |
|---|---|
| 0 | Gate passed |
| 1 | Gate failed |
| 2 | Configuration error |
| 3 | Authorization error |
| 4 | Scope violation |

## Automation: the scheduler and the inbound webhook (Phase 8)

Two more ways to trigger a workflow, alongside the manual API call — both
**unattended**: no human is present at the moment either one fires.

**Scheduling.** Set `trigger_kind: "schedule"` and
`schedule_interval_minutes` (a 60-minute floor — a stated safety rail
against unattended, high-frequency scanning of a live target, not an
arbitrary number) when creating or updating a workflow. `next_run_at` is
computed and re-armed automatically; there is no cron-expression support —
a fixed interval matches this module's own "not a general workflow engine"
stance. Celery Beat ticks every 60 seconds and fires
`aegis.dispatch_scheduled_workflows`, which advances each due workflow's
`next_run_at` *before* its run executes, so a slow run never causes a
duplicate dispatch on the next tick.

**The inbound webhook.** `POST /api/v1/webhooks/workflows/{id}` —
deliberately **not** under `/organizations/{org}/...`: its caller has no
session for any organization, so its authentication is an HMAC signature,
not membership. Enable it with `POST .../webhook-secret` (admin), which
returns a secret **once**, in plaintext, never again. Sign the request the
same way `app/core/integrations/signing.py` already signs this platform's
own *outbound* webhooks — `X-Aegis-Signature`/`X-Aegis-Timestamp`,
HMAC-SHA256 over `v1:<timestamp>:<body>` — because this is the first thing
in the codebase to call that module's own `verify()` as a receiver rather
than only document it as the reference one should be written against. The
body is this platform's own minimal shape, not a code host's:

```json
{"kind": "repository_change", "ref": "refs/heads/main", "commit": "<sha>"}
```

`kind` is restricted to `repository_change`/`pull_request` — `schedule` and
`manual` make no sense from an inbound call and are refused at the schema
level. Replay protection is a Redis-backed store keyed by the signature
itself, **failing closed**: if Redis cannot be reached, the delivery is
refused (503), never silently accepted as unseen — the opposite choice from
the rate limiter's own deliberate fail-open, because replay protection
exists specifically to refuse something that looks legitimate.

## The approval gate for unattended triggers

Every other target-touching action on this platform requires a human
explicitly present at the moment of the call — `POST /runs`'s own confirmed
authorization, `START_SCAN`'s `authorization_confirmed=True`. Scheduling and
the webhook are the first two triggers with no human present at all, so:

**Any run triggered by Celery Beat or the webhook, whose plan would queue a
scan-touching action (`APPSEC_SCAN`/`API_SCAN`/`AI_SCAN`/`DAST_SCAN`/
`PUBLISH_PR`), always pauses — status `awaiting_approval` — before that
action queues.** No opt-out, no configuration exception: mirrors
`app.core.assistant.autonomy.TARGET_TOUCHING`'s "no mode can grant this"
idiom. A manually-triggered run never pauses — the caller's own
authenticated, role-checked call *is* the approval, exactly as before this
phase.

A security engineer resolves a paused run:

```bash
curl -X POST "$AEGIS/organizations/$ORG/workflows/$WF/runs/$RUN/approve" \
  -H "Authorization: Bearer $TOKEN"
# or
curl -X POST "$AEGIS/organizations/$ORG/workflows/$WF/runs/$RUN/reject" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason": "not authorized this week"}'
```

Approving queues the scan through the exact same `queue_run()`
`POST /runs` and the agent's `start_scan` tool already call — never a
second, parallel path — **attributed to the approver**: `queue_run()`
requires a real `user_id`, which an unattended trigger has none of until a
human supplies one by approving. Once that scan reaches a terminal state,
a decoupled follow-up task (the same pattern `notify_run_finished` already
is) gates the run over the findings it produced, using the same unmodified
`finish()` a manual trigger's synchronous call always has.

## What is not built

Stated rather than implied:

* **Scan actions are planned here and executed by the assessment path.**
  Triggering a workflow through the API records the trigger, the plan and the
  gate decision over findings that already exist. It does not queue an
  assessment run on its own — one code path for "run an assessment", not two.
  `docs/roadmap.md` records this as the phase's deliberate boundary; Phase 8's
  scheduler and webhook both still go through `queue_run()` rather than a
  second path, once a run is (or needs no) approval.
* **No vendor-specific webhook translators.** The inbound endpoint accepts
  this platform's own minimal, HMAC-signed shape only — translating GitHub's
  or GitLab's own webhook payload into it is a separate, later increment.
* **No CLI for any workflow operation.** `aegis-ai` has no `workflow`
  subcommand group at all yet, scheduling and webhooks included.
* **No rate limit on the inbound webhook.** `app.core.ratelimit`'s
  per-route policies are each a route's own dependency, and this endpoint
  has none — a flood of requests still costs an HMAC verification and a
  Redis round-trip each before being refused. Deferred rather than adding
  a new policy without the same deliberate "which window, which key, which
  fail direction" review every existing one already got.
