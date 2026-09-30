# The dashboards

Two dashboards exist, for two different audiences, and neither replaced the
other:

- **The Next.js app in `frontend/`** is the primary, richly interactive
  product UI — organizations, targets, runs, workflows, repositories, the
  native AI agent workspace, and (pentest module Phase 10) an at-a-glance
  security-operations overview. It talks to the same `/api/v1` the CLI and
  CI use.
- **The server-rendered dashboard at `/app`**, documented below, is a
  lighter, no-JS-build, read-only operational view served by the same
  FastAPI application as the API — useful where standing up the Next.js
  build isn't wanted, or as a fast, dependency-free check on an
  organization's state.

Both read from the same core query module
(`app/core/dashboard/queries.py`), not two independent implementations of
"how many open findings does this org have" — see "Every number is a query"
below and `docs/architecture.md`'s "two dashboards, one set of queries"
decision.

## The security-operations dashboard (Next.js, pentest module Phase 10)

`GET /organizations/{organization_id}/dashboard/summary` (`Role.VIEWER`,
the same floor as every other read-only organization-scoped list endpoint)
returns a single `DashboardSummary`: open findings by severity, 7-day
run/gate activity, remediation and pending-retest counts, coverage by
pillar, and the five most recent runs, five most recent workflow runs, and
ten highest-risk open findings. The Next.js frontend renders this at
`/organizations/{id}` (the organization's landing page, replacing what used
to be a redirect straight to its targets list).

Every number in that response is a call into
`app/core/dashboard/queries.py` — the same module `/app`'s own overview
page below calls. Two additions specific to this endpoint:

- **Coverage by pillar is organization-wide**, not per-run. It reads the
  same `PILLAR_PREFIXES` table `app/core/reporting/build.py`'s per-report
  coverage section uses (now published from `app/core/reporting/model.py`
  so both readers share one prefix table) directly against `scan_results`,
  so "has SAST ever produced a real result anywhere in this org" and "did
  SAST run in this one report" can never disagree about what counts as
  SAST.
- **"Pending retests" is `Finding.status == RETEST_REQUIRED`**, full stop —
  no second query against `retest_results`. A remediation is a claim until
  a retest checks it (`Finding`'s own status-machine docstring), so the
  finding status already *is* the pending-retest count.

This is still not a findings-management UI: it is a ten-row summary, on
purpose, with no filtering, pagination, or status transitions of its own —
each top finding links out to the fuller `/organizations/{id}/findings`
view instead (pentest-module Phase 11), which is where that management
surface actually lives now. There is also no historical trend (every
count is "right now" or "last 7 days" — no time-series storage) and no
cross-organization view (every query is organization-scoped at the
database level, same as everywhere else in this platform).

## The findings view (`/organizations/{id}/findings`, pentest module Phase 11)

The fuller view the paragraph above refers to. Two server-rendered pages,
no client-side state beyond the one status-transition form:

- `/organizations/{id}/findings` — every finding the organization has
  (not just the dashboard's top ten), filterable by `severity` and
  `status` via plain `method="get"` form fields (no JavaScript needed to
  filter), paginated 25 at a time. Filters and page number both live in
  the URL's query string, so a filtered, paginated view is a link a
  reviewer can share or bookmark, the same as everywhere else server
  components are used in this frontend.
- `/organizations/{id}/findings/{findingId}` — full detail (description,
  impact, remediation, reproduction steps, risk inputs, severity
  rationale) plus a status-transition form. The form's options are never
  a free-text or full-enum dropdown: they come from
  `ALLOWED_FINDING_TRANSITIONS` (`lib/types.ts`), a frontend mirror of
  `ALLOWED_TRANSITIONS` in `app/models/finding.py` — the same
  "duplicated, with a comment pointing at the source of truth" idiom
  `ANONYMOUS_CSRF_PATHS` already uses for a backend constant the frontend
  must not drift from, checked by a dedicated test
  (`lib/__tests__/types.test.ts`) that fails loudly if the two ever
  diverge.

`GET .../findings` gained optional `limit`/`offset` query parameters to
support pagination. Both default to "unbounded" — a caller that never
passes either (the CLI, the CI gate, every route this frontend doesn't
touch) gets the exact same full, ordered response it always has; the
pagination is opt-in, not a breaking change to an endpoint other clients
already depend on.

### Duplicate linking

The findings list has an `include_duplicates` checkbox (off by default,
same server-side query-string idiom as the severity/status filters above)
and a "Duplicate" badge on any row currently linked. The finding detail
page has a "Duplicate" card: a link form (the other finding's id plus an
optional note) when unlinked, or the recorded note and an "Unlink" button
when linked — `components/findings/finding-duplicate-form.tsx`, calling
`POST`/`DELETE .../findings/{id}/duplicate`. A second card, "Duplicates of
this finding", lists the reverse direction (`GET .../duplicates`) when
non-empty. Nothing here infers a duplicate; the form only ever records a
human's own explicit judgment — see `docs/authorization-and-scope.md` and
`app/core/findings/service.py::link_duplicate` for the two-level-only
invariant this UI does not itself enforce (the API's `409` on a violation
surfaces as an ordinary form error).

### Agent tool configuration

The native agent workspace's "Available tools" card
(`components/agent/agent-workspace.tsx`) shows each tool's `enabled` state
(a "Disabled" badge when off) and its effective minimum role next to its
code default when an organization has raised the bar above it. An inline
form per tool (`components/agent/agent-tool-config-form.tsx`) — an enabled
checkbox and a minimum-role `<select>` — calls
`PUT .../agent/tools/{tool_name}/config` directly. See `docs/agent.md`.

### Exploitation tier: authorization and fire/approve/reject

Two new surfaces, since the exploitation tier had no dashboard presence at
all before this (it predates the security-operations dashboard's own
Phase 10). The target detail page gained an "Exploitation authorization"
card (`components/targets/exploitation-authorization-grant-form.tsx`), a
near-mirror of the existing Authorization card, making explicit in the UI
that this is a second, distinct grant — not implied by ordinary
Authorization. The run detail page gained an "Exploitation fires" section
(`components/runs/exploitation-fires.tsx`, shown once a run is
`completed`): a create-fire form, a self-polling list of fires that stops
once every fire is terminal, and approve/reject actions on any fire still
`awaiting_approval`. Nothing here enforces dual control client-side — the
same person attempting to approve their own request gets the API's `403`
back as an ordinary form error, consistent with this frontend having no
role-gating convention anywhere (every form renders unconditionally; the
backend's RBAC is the only enforcement). See
`docs/authorization-and-scope.md`.

### Report download

The run detail page's "Report" card (`components/runs/report-download.tsx`,
shown once a run is past `draft`/`queued`) is a format `<select>`
(markdown/HTML/PDF/JSON/SARIF/CSV), an audience-template `<select>`
(technical/executive/developer/compliance), and a download button —
`GET .../report` has rendered every one of these since Phase 9's reporting
work, but nothing in the dashboard ever called it before this. Downloading
uses `clientApiDownload` (`lib/api-client.ts`), not `clientApiFetch`: the
response is a file with a `Content-Disposition` header rather than JSON,
so it reads the blob and the filename the backend already chose, then
triggers the browser's save dialog via a transient object-URL anchor
instead of navigating to the API URL directly. A `501` (PDF requested
without the optional `weasyprint` dependency present) surfaces as a plain
message naming the problem, not a raw error.

## The Jinja2+HTMX dashboard (`/app`, pentest module Phase 17)

A server-rendered dashboard at `/app`, served by the same FastAPI application as
the API. Jinja2 templates, one inline stylesheet, no build step and no
`node_modules`.

```
/app                                        organizations you belong to
/app/organizations/{org}                    overview
/app/organizations/{org}/findings           open findings, filterable by severity
/app/organizations/{org}/runs               assessment runs
/app/organizations/{org}/workflows          workflows and their runs
/app/organizations/{org}/targets            configuration, and what blocks a scan
```

It authenticates with the session cookie the API's `/auth/login` and
`/auth/register` set. There is no sign-in form: a second credential path is a
second thing to get wrong.

### It is read-only, and that is a scope decision now, not a security one

Every route under `/app` is a `GET`. Not "mostly", and not "for now" —
`tests/test_web.py::test_every_dashboard_route_is_a_get` walks the route table
and fails if a non-GET route is ever added.

CSRF protection exists now (`docs/csrf.md`) and would cover a dashboard write
route the same way it covers the API's. No write route is built here anyway,
so the dashboard still shows the action, disables it, and says both why and
which API call performs it instead:

> **Start a run** *(disabled)*
> The dashboard is read-only: write handlers are not built. CSRF protection
> now exists (`docs/csrf.md`), so this is a scope decision rather than a
> security constraint — the reason it was one has been removed. Use the API
> or the CLI. `POST /api/v1/organizations/{organization_id}/runs`

That is §27's *"every visible action works or is disabled with a reason"* met
honestly. A greyed-out button with no explanation is a dead end; so is hiding
the button and leaving the operator to wonder.

These routes are the obvious place to put a write handler if one is ever
built — and the route-table test above is what will make that a deliberate
change rather than an accident.

### Every number is a query

§27's other rule: *no hardcoded dashboard values*. Every figure this dashboard
renders comes from `app/core/dashboard/queries.py`, and nothing else is passed
to a template. A template that wanted a number not in that module would have
to add it there first. (That module lived at `app/web/queries.py` through
Phase 17; it moved to `app/core/` in Phase 10 specifically so the Next.js
summary endpoint above and this page could both call it, rather than each
computing the same counts independently.)

`tests/test_web.py::test_every_number_on_the_overview_comes_from_a_query` reads
the card values and the severity table **back out of the rendered HTML** and
requires the whole set to equal what the query returns, before and after rows
change. The first version of that test checked the query object instead and
passed when a card was replaced with a literal `0`; it was rewritten after that
failure, and now fails on exactly that edit.

Two rules the queries follow:

* **Zero and unknown are different.** A count of zero findings is a fact and
  renders as `0`. A value that was never decided is not, and renders as what it
  is: a workflow run whose gate did not run shows *not decided*, never *pass*;
  a finding with no evidence bundle shows *none*, never an empty cell. Today
  every count on the overview is computable, so none of them is nullable — if
  one ever isn't, it says so rather than rendering a confident `0`.
* **Everything is organization-scoped at the database level**, so a missing
  filter is a missing row rather than a leaked one. Each route depends on
  `require_membership(...)`, and a non-member gets the same **404** the API
  gives — 403 would confirm the organization exists.

### The targets page names what blocks a scan

A target with no authorization grant is refused at run time. A dashboard that
listed only its name would leave an operator to discover that by trying, so the
page states the blockers: no valid authorization grant, no rules of engagement,
no adapter configured. An expired grant renders as `expired`, never as
`granted` — the window is checked per request, and the dashboard must not say
the opposite of what the orchestrator is about to do.

### HTMX

The templates carry `hx-get` / `hx-target` attributes and the handlers honour
the `HX-Request` header, returning the fragment instead of the page. One
handler, one query, two renderings — a partial with its own handler would be a
second source of truth for the same numbers.

**HTMX itself is not committed**, and the base template renders no `<script>`
tag unless you vendor it:

```bash
curl -fsSL -o backend/app/web/static/htmx.min.js \
  https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js
```

There is deliberately no CDN tag. Fetching unpinned third-party script onto the
page where findings are read is a supply-chain decision, and whoever makes it
should be the person who checked the hash.
`tests/test_web.py::test_no_template_carries_a_cdn_script_tag` enforces that
every script a template loads is served by this application.

**Nothing breaks without it.** Every page is a complete server-rendered
document reachable by an ordinary link; HTMX only swaps a fragment instead of
the page.

### Templates escape what they render

A findings dashboard renders attacker-influenced text: a probe's payload,
echoed back by the target and stored on the finding. Autoescaping is on and
asserted, because rendering that raw would make this platform's own dashboard
the stored-XSS sink it tests its clients for.

## What replaced what

Nothing did. Through Phase 17 this section correctly said the Next.js app
was "the Phase-1 auth scaffold and not the dashboard" — that stopped being
true well before pentest-module Phase 10: the Next.js frontend grew into
the full product UI (organizations, targets, runs, workflows, repositories,
the native agent) across the phases `docs/roadmap.md` records, then gained
its own security-operations overview in Phase 10. The two dashboards now
serve different, deliberate purposes (above) rather than one having
superseded the other.
