# Outbound integrations

email, three SIEM-specific adapters — Splunk HEC, Microsoft Sentinel and a
generic CEF-over-webhook kind (§ below) — and opens tickets in Jira Cloud or
ServiceNow. This document is written around the two questions that decide
whether a notification feature is safe, because they are the ones a reviewer
will ask.

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
   `*.webhook.office.com` or `*.logic.azure.com`; a `siem_sentinel` channel
   only `*.ingest.monitor.azure.com` — every Data Collection Endpoint Azure
   Monitor issues lives under that domain; `ticket_jira` only
   `*.atlassian.net`; `ticket_servicenow` only `*.service-now.com`.
4. **A new destination is an operator decision, not a database row.** A
   `generic_webhook`, `siem_splunk_hec` or `siem_generic_cef` host must appear
   in `KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS` (Splunk HEC is almost always
   self-hosted, so it carries no built-in vendor host at all), and an SMTP
   relay in `KERVY_NOTIFY_ALLOWED_SMTP_HOSTS`. Both live in the environment.
   An admin chooses among destinations an operator has sanctioned; they
   cannot invent one. `ticket_jira`/`ticket_servicenow` take this a step
   further: the admin names only a site/instance *label* (`jira_site`,
   `servicenow_instance`), not a URL, and the full host is built from it, so
   there is no URL field for an admin to repoint at all.

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
| `auth_token_env_var` | Splunk HEC only: name of the variable with the HEC token |
| `azure_client_secret_env_var` | Sentinel only: name of the variable with the Entra ID app's client secret |
| `jira_api_token_env_var` | name of the variable with the Jira API token |
| `servicenow_password_env_var` | name of the variable with the ServiceNow password |

A Slack incoming webhook URL is a credential, because its path *is* the token.
That is why the whole URL is held by reference and why no API response, audit
record or log line contains it. Sentinel's `sentinel_endpoint`,
`azure_tenant_id`, `azure_client_id`, `sentinel_dcr_immutable_id` and
`sentinel_stream_name` are stored directly rather than by reference — none of
the five carries a credential in its own right (a Data Collection Endpoint URL
has no token in its path, unlike a Slack webhook), only the app registration's
client *secret* does. A Jira or ServiceNow channel has no URL at all either —
`jira_site`/`jira_email`/`jira_project_key`/`jira_issue_type` and
`servicenow_instance`/`servicenow_table`/`servicenow_username` are identifiers,
not secrets, and are stored directly the same way `smtp_host`/`smtp_username`
already are.

## Events

| Event | Fires when |
|---|---|
| `assessment.completed` | a run finished |
| `assessment.failed` | a run ended in failure |
| `finding.created` | a finding was promoted |
| `finding.critical` | …and it is critical |
| `retest.completed` | a `RunKind.RETEST` run finished |
| `gate.failed` | a workflow run's gate decision refused it |
| `agent_investigation.completed` | a native-agent investigation reached `COMPLETED` |
| `agent_investigation.failed` | a native-agent investigation reached `FAILED` |

The two agent events fire only on a terminal state — never while an
investigation is `AWAITING_APPROVAL`, and never on a human `CANCELLED`. The
payload carries the same fixed scalar shape as every other event (§ below);
`event_for_investigation()` (`app/core/integrations/dispatch.py`) builds it
from the investigation's own outcomes, never from the request text or a
tool's raw output — the same zero-persistence discipline `docs/agent.md`
describes for the agent's own storage.

`retest.completed` fires alongside a retest run's own `assessment.completed`
(`_notify_run`, `app/workers/notifications.py`), carrying `reproduced` /
`not_reproduced` / `not_tested` verdict counts in `facts` — the whole reason a
retest was requested, which a channel subscribed to `assessment.completed`
alone would have to infer from generic counts.

`gate.failed` fires only when a workflow run's gate decision refuses it — a
passing gate is already covered by the `workflow.completed` audit event, and
only the failing outcome is worth paging on. Scheduled from each of
`finish()`'s three call sites (`app/core/workflow/service.py`) once their own
transaction commits, and built by `_notify_workflow_gate_failed` from the
run's own stored `gate_reasons`/`gate_counts` rather than values passed at
call time, so a retry always reflects what was actually decided.

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

## SIEM channels: Splunk HEC, Microsoft Sentinel, generic CEF

Three adapters, not one generic shape, because each vendor's wire format and
authentication differ enough that forcing them through `generic_webhook`
would mean shipping a payload the vendor's own parser does not expect.

**`siem_splunk_hec`** — Splunk's HTTP Event Collector. Each delivery is one
`POST` carrying `Authorization: Splunk <token>` (HEC's own documented scheme,
not Bearer or Basic) and a body shaped `{"time": <epoch seconds>,
"sourcetype": "kervy:security_event", "event": {…}}`, where `event` holds the
same scalar fields every other channel kind renders.

**`siem_sentinel`** — Microsoft Sentinel's Logs Ingestion API. Two network
calls per delivery: a client-credentials exchange against Entra ID
(`https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`, scope
`https://monitor.azure.com/.default`), each in its own single-host scope
context so a bug in one context's allowlist can never widen the other; then a
`POST` of a one-record JSON array to
`{sentinel_endpoint}/dataCollectionRules/{dcr_immutable_id}/streams/{stream_name}`
with the fetched bearer token. A successful upload answers `204`, the API's
own documented response — not `200`/`201`. Requires an Entra ID app
registration with access to the target Data Collection Rule; set up the DCR,
the custom table and the app registration in the Azure portal first.

**`siem_generic_cef`** — Common Event Format over a signed webhook, for a
SIEM with no dedicated adapter here (QRadar, Elastic, Sumo Logic, Chronicle,
…). One line: `CEF:0|Kervy|SecurityTestingPlatform|1.0|<event type>|<title>
|<severity 0-10>|<extension>`. Severity is mapped from this platform's own
CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL band to CEF's integer scale
(10/7/5/3/1 — CEF names no canonical word-to-number table, so this mapping is
ours). Signed exactly like `generic_webhook`: `signing_secret_env_var` is
required, and the same `X-Kervy-*` headers apply.

```bash
kervy-ai channels add --name splunk --kind siem_splunk_hec \
  --event finding.critical --endpoint-env-var KERVY_SPLUNK_HEC_URL \
  --auth-token-env-var KERVY_SPLUNK_HEC_TOKEN

kervy-ai channels add --name sentinel --kind siem_sentinel \
  --event finding.critical \
  --sentinel-endpoint https://my-dce.eastus-1.ingest.monitor.azure.com \
  --azure-tenant-id <tenant-id> --azure-client-id <client-id> \
  --azure-client-secret-env-var KERVY_SENTINEL_CLIENT_SECRET \
  --sentinel-dcr-immutable-id <dcr-immutable-id> \
  --sentinel-stream-name Custom-KervySecurityEvent
## Ticketing channels: Jira Cloud, ServiceNow

A `ticket_jira`/`ticket_servicenow` channel does not notify about a finding —
it *creates a record* in someone else's system, the one thing every other
kind in this document deliberately does not do. `send.py`'s
`send_jira_ticket`/`send_servicenow_ticket` make exactly one creation call
per delivery and parse the vendor's own response for the identifier it
assigned, which is written back to `NotificationDelivery.external_reference`
so a reader can find the ticket without re-deriving it.

**Jira Cloud** — `POST /rest/api/3/issue` against
`https://<jira_site>.atlassian.net`, `Authorization: Basic` over
`<jira_email>:<api token>` (Atlassian's own documented alternative to
OAuth for a dedicated integration account). The `description` field is
Atlassian Document Format, not plain text — `render.py`'s `_jira` builds a
single paragraph with `hardBreak` nodes between the same fact lines every
other renderer produces. A successful create answers `201` with
`{"key": "SEC-123", ...}`; that key is `external_reference`.

**ServiceNow** — `POST /api/now/table/<servicenow_table>` against
`https://<servicenow_instance>.service-now.com`, `Authorization: Basic`
over `<servicenow_username>:<password>` — ServiceNow's Table API documents
this as a supported alternative to OAuth2, chosen here for the same reason
Splunk HEC's header auth was chosen over Sentinel's two-call OAuth flow in
the SIEM integration: one of the two vendors in a pair gets the simpler
path so the pair is not two OAuth integrations in one increment. Severity
maps to ServiceNow's `urgency`/`impact` (1 = most urgent, matching
ServiceNow's own direction, the opposite of this platform's own severity
order): CRITICAL/HIGH → 1, MEDIUM → 2, LOW/INFORMATIONAL → 3. A successful
create answers `201` with `{"result": {"number": "INC0012345", ...}}`;
`number` is `external_reference`, falling back to `sys_id` if a customised
table's response ever omits it.

**Why there is no "off-domain" rejection test for these two, unlike
Sentinel's.** Sentinel's channel stores a full endpoint URL, so policy has
to check a host it did not choose. A Jira/ServiceNow channel stores only
the site/instance *label* — `send.py` builds `https://<label>.atlassian.net`
(or `.service-now.com`) itself — so the result can never be a different
host by construction. What *can* go wrong is the label itself carrying a
path separator or similar, which would not change which host the request
reaches (the label is appended after an already-fixed authority) but could
still rewrite the request's path in a way a reviewer should not have to
reason through case by case. `jira_site`/`servicenow_instance` are
therefore restricted to a DNS-label charset at the schema layer
(`^[a-z0-9-]+$`), and `jira_project_key`/`servicenow_table` — the other two
identifiers that end up in a URL — get their own patterns for the same
reason. `send.py` applies `urllib.parse.quote` to `servicenow_table` again
at the point of use, belt-and-braces rather than trusting the schema check
alone, the same two-layer discipline the SIEM integration's Sentinel
adapter applies to its own path-building identifiers.

Two ticketing-specific CLI examples:

```bash
kervy-ai channels add --name sec-tickets --kind ticket_jira \
  --event finding.critical \
  --jira-site mycompany --jira-email bot@example.com \
  --jira-api-token-env-var KERVY_JIRA_API_TOKEN \
  --jira-project-key SEC --jira-issue-type Bug

kervy-ai channels add --name sec-incidents --kind ticket_servicenow \
  --event finding.critical \
  --servicenow-instance mycompany --servicenow-table incident \
  --servicenow-username kervy-bot \
  --servicenow-password-env-var KERVY_SERVICENOW_PASSWORD
```

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
