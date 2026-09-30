# Outbound integrations

Kervy sends notifications to Slack, Microsoft Teams, a signed generic webhook,
or email. This document is written around the two questions that decide whether
a notification feature is safe, because they are the ones a reviewer will ask.

## Can a channel become an SSRF primitive?

No, and not because the destination is trusted. Four independent controls stand
between an organization admin and an outbound request:

1. **The scope engine still decides.** A delivery goes through the same
   `GatedTransport` as every other outbound request in the platform, under a
   context (`app/core/integrations/egress.py`) whose `allowed_domains` holds
   exactly the resolved destination host and whose `allowed_ip_ranges` is
   empty. Loopback, link-local, RFC1918 and the cloud metadata service are
   refused for a notification exactly as for a target — including the DNS-rebind
   case, because the engine re-resolves the host at send time.
2. **The allowlist is derived, never passed.** There is no parameter on the
   egress context through which a caller could widen it, so a notification
   context can never stand in for a target authorization.
3. **Vendor kinds are pinned to vendor hosts.** A `slack_webhook` channel can
   only ever reach `hooks.slack.com`; a `msteams_webhook` channel only
   `*.webhook.office.com` or `*.logic.azure.com`.
4. **A new destination is an operator decision, not a database row.** A
   `generic_webhook` host must appear in `KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS`,
   and an SMTP relay in `KERVY_NOTIFY_ALLOWED_SMTP_HOSTS`. Both live in the
   environment. An admin chooses among destinations an operator has sanctioned;
   they cannot invent one.

SMTP is the one honest exception and is documented as such. It is not HTTP, so
it cannot travel through `GatedTransport`. Instead `send_email` asks the same
`ScopeEngine` to adjudicate the relay host first, then connects with STARTTLS
required. The engine does not see that socket — a smaller guarantee than the
webhook path has, and `tests/security/test_scope_controls.py` pins `smtplib` to
that one module so a second socket-level path cannot be added quietly.

## Can a notification leak what the platform redacts?

Evidence bundles are redacted before they are written (§13), and a notification
must not be the hole in that. So:

* A payload is assembled from a fixed set of scalar fields — identifiers, enum
  values, counts, a finding title, a link back into the platform. Never a
  response body, an evidence bundle, a judge transcript or a code snippet.
* `render` runs the assembled text through the secret detector and **refuses**
  rather than truncates. A truncated alert missing the one line somebody needed
  is worse than a delivery marked `refused` with a reason.
* Every error string stored or returned is scrubbed twice: absolute URLs are
  replaced by their redacted shape, then the secret detector runs. URL paths are
  stripped outright rather than pattern-matched, because a webhook token is
  opaque random text that no issuer pattern recognises.

## Credentials

A channel row holds the **name** of an environment variable, never a value:

| Field | Holds |
|---|---|
| `endpoint_env_var` | name of the variable with the webhook URL |
| `endpoint_redacted` | `https://host/…/…` — scheme, host, path *shape* |
| `signing_secret_env_var` | name of the variable with the HMAC secret |
| `smtp_password_env_var` | name of the variable with the relay password |

A Slack incoming webhook URL is a credential, because its path *is* the token.
That is why the whole URL is held by reference and why no API response, audit
record or log line contains it.

## Events

| Event | Fires when |
|---|---|
| `assessment.completed` | a run finished |
| `assessment.failed` | a run ended in failure |
| `finding.created` | a finding was promoted |
| `finding.critical` | …and it is critical |
| `retest.completed` | **defined, not yet emitted** — see below |
| `gate.failed` | **defined, not yet emitted** — see below |
| `agent_investigation.completed` | a native-agent investigation reached `COMPLETED` |
| `agent_investigation.failed` | a native-agent investigation reached `FAILED` |

The two agent events fire only on a terminal state — never while an
investigation is `AWAITING_APPROVAL`, and never on a human `CANCELLED`. The
payload carries the same fixed scalar shape as every other event (§ below);
`event_for_investigation()` (`app/core/integrations/dispatch.py`) builds it
from the investigation's own outcomes, never from the request text or a
tool's raw output — the same zero-persistence discipline `docs/agent.md`
describes for the agent's own storage.

`retest.completed` and `gate.failed` are part of the event vocabulary and a
channel may subscribe to them, but nothing emits them yet: the retest worker and
the CI gate have not been wired to `enqueue`. A channel subscribed only to those
will receive nothing. Said plainly here rather than left for someone to discover
during an incident; tracked in `docs/roadmap.md`.

A channel subscribes to specific events and may set `min_severity` as a floor.
An event no channel subscribes to produces no delivery row at all. An event
whose severity cannot be ranked is **not** dropped: a missed security
notification is the costliest failure mode here.

`finding.critical` is its own event type so a channel can page on criticals
without also taking every low.

## Delivery, retry and dead-letter

A delivery row is written **before** the attempt, so a worker that dies mid-send
leaves the work findable rather than lost. Then:

* `delivered` — 2xx.
* `failed` — retryable (5xx, 429, 408, socket error). Retried after 30s, 120s,
  600s; four attempts in total.
* `dead_letter` — retries exhausted. Visible, never silently dropped.
* `refused` — a misconfigured channel, a host the policy does not permit, a
  payload the redactor stopped, or a scope-engine decision. **Never retried**:
  the same configuration fails the same way, and a retry loop against a bad
  config is how rate limits get hit.

Every attempt writes an audit event, including the ones that never reached the
network. "Was the team told about that critical finding?" is a question an
incident review asks, and a refused delivery that left no trace is the answer
nobody can give.

A retry rebuilds the event from the delivery row's snapshot rather than
re-reading the finding. Re-deriving it would silently notify about the
finding's *current* state, which is how a "critical finding" alert arrives about
something a human already closed.

## Signing a generic webhook

Headers: `X-Kervy-Timestamp`, `X-Kervy-Signature` (`v1=<hex>`), `X-Kervy-Event`.
The signature is `HMAC-SHA256(secret, "v1:<timestamp>:<body>")` over the exact
bytes sent — not a re-serialization, which is how signature mismatches happen.
Verify with a 300-second tolerance; the timestamp is inside the signed string so
a captured request cannot be replayed forever.
`app/core/integrations/signing.py` holds the reference implementation of both
sides.

## Configuration

```bash
KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS='["siem.internal.example"]'
KERVY_NOTIFY_ALLOWED_SMTP_HOSTS='["smtp.example.com"]'
KERVY_PUBLIC_BASE_URL=https://kervy.example.com   # absent: no link is rendered
```

A link is omitted rather than guessed when no base URL is set. A broken link in
an alert teaches readers to ignore alerts.

## CLI

```bash
kervy-ai channels list
kervy-ai channels add --name sec-alerts --kind slack_webhook \
  --event finding.critical --event assessment.failed \
  --endpoint-env-var KERVY_SLACK_WEBHOOK
kervy-ai channels test --channel <id>          # non-zero if it cannot deliver
kervy-ai channels deliveries --channel <id>
```

`--endpoint-env-var` takes a variable *name*. A flag that took the URL would put
a credential in the operator's shell history.

## Roles

| Action | Minimum role |
|---|---|
| create, update, delete, test | admin |
| list channels, list deliveries | analyst |

Creating a channel is admin because a channel is a standing outbound path for
the organization's findings. Reading is analyst so the people triaging findings
can see whether an alert actually went out without being able to re-point it.
