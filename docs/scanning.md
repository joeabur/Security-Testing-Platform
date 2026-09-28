# Running a scan

## What a run needs

| | Required | Why |
|---|---|---|
| A target | yes | `base_url`, `kind`, `environment` |
| Rules of engagement | yes | the scope envelope; a run without one is refused |
| An authorization grant, currently valid | yes | the human act; `409` without it |
| An adapter | for AI probes | how to talk to the application |
| An OpenAPI document | for API probes | the attack surface. Without it the API engine has almost nothing to test |
| Synthetic accounts | for authorization probes | BOLA and function-level authz need two identities |
| A code scope | for AppSec engines | refuses to run if absent or ambiguous |
| An asset scope (`root_domain`) | for a `domain` target's engine | refuses to run if absent or malformed; `allowed_subdomain_patterns` bounds which discovered hosts get probed, defaulting to the root domain only |

Skipping an optional input does not fail the run. It narrows coverage, and the
report's coverage section names what was not tested — silence would read as
"clean".

## Profiles

`profile` selects the check set: `connectivity` for a smoke test, `full` for
everything the target's configuration supports. Anything the configuration does
not support is reported as a `not tested` marker rather than silently skipped.

## Lifecycle

```
queued ──▶ running ──▶ completed
              │
              ├──▶ failed        (an engine error, recorded with the reason)
              ├──▶ cancelled     (a human asked; the kill switch is honoured mid-flight)
              └──▶ expired       (the authorization window closed during the run)
```

Progress is available as JSON polling or an SSE stream at
`…/runs/{id}/events`. Cancellation goes through the Redis kill switch, so it
works across processes — the API can stop a run the worker is executing.

## What is recorded on the run

The authorization digest and the rules-of-engagement digest are stored on the
run itself. If the target's configuration changes later, what a past run
executed under is still knowable. So is `probes_executed` — the list of probes
that actually ran, which is what a retest uses to distinguish "this is fixed"
from "this was not re-tested".

## Budgets and halting

Requests, concurrency, rate, tokens, estimated cost and wall-clock minutes.
Exhausting one stops the run **cleanly with a reason**, not as a failure. A
scope violation is a halt: the engine refused, and continuing would mean
ignoring the refusal.

## Retest

A retest re-runs the probes that produced a set of findings and records
`reproduced`, `not_reproduced` or `not_tested` for each, with the evidence from
both sides.

`not_tested` is a real outcome and exists because of a bug worth remembering:
an early version inferred "the probe ran" from whether it wrote a result, so a
genuinely fixed finding — where the probe ran and found nothing — was reported
as `not_tested`. The run now records which probes executed, so the three
outcomes are distinguishable.

## Reading results

- `…/runs/{id}/results` — raw `ScanResult`s, including `not tested` markers.
- `…/organizations/{id}/findings` — normalized, scored, deduplicated findings.
- `…/runs/{id}/report?report_format=…` — `markdown`, `html`, `pdf`, `json`,
  `sarif`, `csv`.
- `…/runs/{id}/evidence` and `…/evidence/verify` — the manifest and a chain
  check.

A `ScanResult` is what a probe observed. A `Finding` is what the platform
concluded, after normalization, fingerprinting, scoring and deduplication
against what it already knew. Reports are built from findings.
