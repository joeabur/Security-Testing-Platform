# Troubleshooting

## A run is refused with `409`

There is no authorization grant for the target, or the current one has expired.
This is the platform working. Create one:

```
POST /organizations/{org}/targets/{target}/authorization
```

`valid_from` must be in the past and `valid_until` in the future.

## A run completes but the scan found almost nothing

Nearly always a missing input. Check, in this order:

1. **No OpenAPI document uploaded.** The API probes derive their surface from
   it. Without one you get a handful of transport-level findings and nothing
   else. `PUT …/targets/{id}/openapi`.
2. **No synthetic accounts.** BOLA (`KERVY-API-050`) and function-level
   authorization (`KERVY-API-051`) need two identities. Without them the report
   says `KERVY-API-000 — not tested`.
3. **No adapter configured.** No AI findings without one.
4. **Credential variables missing from the worker.** See below.

The report's **coverage section** names every gap. Read it before concluding the
target is clean.

## Authorization probes report nothing, but accounts are configured

The credential variables are missing from the **worker's** environment.

Credentials are stored by variable name, and the process that resolves a name to
a value is the one that makes the request — the worker, not the API. Exporting
them only in the API shell produces exactly this symptom: a run that completes
with no authorization findings.

```bash
# In the worker's shell, before starting it
export KERVY_LAB_ACME_TOKEN=... KERVY_LAB_GLOBEX_TOKEN=...
```

## Every request to the demo lab is refused as out of scope

The lab runs on loopback, and loopback is blocked by default. That default is
correct. Opt in explicitly in the rules of engagement:

```json
"allowed_ip_ranges": ["127.0.0.0/8"]
```

## `scope_violation` against a real target

Use the dry run to see the decision without sending anything:

```
POST /organizations/{org}/targets/{id}/scope/explain
kervy-ai scope explain --target <id> --url https://...
```

It names the rule that refused. Common causes: the hostname is not in
`allowed_domains`; the target resolves to a private address and
`allowed_ip_ranges` does not cover it; the method is not in `allowed_methods`; a
redirect pointed out of scope.

## `blocked_ip` for `169.254.169.254`

The cloud metadata service is refused unconditionally and cannot be allowlisted.
This is deliberate. If a target genuinely resolves there, something is wrong
with the target's DNS, not with the scanner.

## `dns_resolution_failed`

The hostname did not resolve, so the engine cannot prove it is not internal and
refuses. It is not a halt — the rest of the run continues. Check the name from
the worker's network.

## An AppSec engine reports `KERVY-APPSEC-000 — not tested`

Its tool is not on the worker's `PATH`. The marker names which one. Install it
and re-run, or record that pillar as out of scope for the engagement.

## The code scan refuses to start

`code_scope` is absent or ambiguous. The AppSec engines fail closed rather than
guess which files they may read.

## A notification channel will not save

- `422` with "not permitted": the host is not sanctioned. Vendor kinds are
  pinned in code; a generic webhook host must be in
  `KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS`.
- `422` naming a variable: that environment variable is not set in the API
  process. The channel is checked at creation so it cannot fail later during an
  incident.
- `422` about `signing_secret_env_var`: a generic webhook must be signed.

## Notifications are not arriving

Check the delivery history — `GET …/notification-channels/{id}/deliveries`:

| Status | Meaning |
|---|---|
| `refused` | Configuration or policy. Never retried; `last_error` says why |
| `failed` | Transport failure; will be retried (30s, 120s, 600s) |
| `dead_letter` | Retries exhausted |
| `delivered` | Sent |

A channel subscribed only to `retest.completed` or `gate.failed` receives
nothing: those event types are defined but not yet emitted
(`docs/integrations.md`).

## Publishing to a pull request returns 200 but `posted` is false

The record carries a scrubbed `detail`. Usually the token lacks `checks:write`
on that repository, or the GitHub App is not installed on it. The response never
includes the token or GitHub's response body.

## `MissingGreenlet` in a worker log

A lazy SQLAlchemy relationship was accessed in an async context. Load it
explicitly with a `select` or `selectinload`. This has bitten before, in the
notification worker.

## Tests fail in confusing, unrelated ways

Two pytest sessions are running at once. They truncate the same test database.
Run one at a time.

## Postgres or Redis unreachable after a restart

```bash
pg_isready || sudo pg_ctlcluster 16 main start
redis-cli ping || redis-server --daemonize yes
```

## Still stuck

`docs/security-review.md` lists known gaps; `docs/limitations.md` lists what the
tool cannot do. If the behaviour contradicts a guarantee in
`docs/security-model.md`, that is a security report — see `SECURITY.md`.
