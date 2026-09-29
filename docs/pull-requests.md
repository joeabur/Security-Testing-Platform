# Pull-request integration

Kervy posts a run's findings back to a GitHub pull request as a **check run**
with inline annotations. This document is written around the boundary, because
writing into someone else's repository is the most externally-visible thing this
platform does.

## What this layer can and cannot do

**Can:** read a pull request's changed files, create a check run, post a
`COMMENT` review.

**Cannot:** push a commit, open or merge a pull request, update a branch
reference, write or delete a file, approve a review, or request changes.

That is not a list of things we chose not to build and might add. It is
enforced three ways:

1. **There is no method for it.** `GitHubClient` exposes exactly
   `pull_request_files`, `create_check_run` and `post_review`.
2. **A static test pins that.** `tests/security/test_scope_controls.py` greps
   `app/core/vcs` for `PUT`/`PATCH`/`DELETE` and for the `/merges`,
   `/git/refs`, `/git/commits` and `/contents` endpoints, and fails if any
   appears. It was verified against a planted violation.
3. **The scope engine refuses the verbs.** The egress context allows `GET` and
   `POST` only, so a call added in future is refused before it leaves the
   process rather than relying on review to catch it.

An "autofix" that pushes a commit to a customer's repository stays out of
scope (`docs/roadmap.md`), and this is how it stays out.

## Egress

Same pattern as notifications and the AI provider. The allowlist is derived
from a `Destination` that policy already checked, holds one API host, and no
caller can widen it:

* A `github` connection reaches **`api.github.com` and nothing else**, pinned in
  code. A database row cannot redirect it — attempting to set `api_host` on one
  is refused at creation.
* A `github_enterprise` connection's host is site-specific, so it must appear in
  `KERVY_VCS_ALLOWED_HOSTS`, held in the environment. An organization admin picks
  among hosts an operator sanctioned; they cannot invent one.
* `allowed_ip_ranges` is empty, so sanctioning a host does **not** sanction an
  internal address behind it. A self-hosted instance on RFC1918 is a deliberate
  widening of the rules of engagement, not something this context grants quietly.

## Credentials

The connection row stores `token_env_var` — a variable *name*. The token is read
at publish time, travels in an `Authorization` header, and appears in no URL, no
log line, no audit record, no API response and no error string. A GitHub token
grants read (and check-write) access to a customer's source, so §5's rule that
credentials never live in the database is at its most load-bearing here.

The migration has no column that could hold one, and a test reads every column
of a stored connection to prove the token is in none of them.

## What gets posted

A check run whose conclusion comes from the **same `evaluate()` the CI gate
uses**, so a pull request and a pipeline cannot disagree about whether the same
findings are a blocker.

| Conclusion | When |
|---|---|
| `failure` | the gate failed |
| `success` | the gate passed and something was actually assessed |
| `neutral` | nothing was assessed |

`neutral` rather than `success` for an empty run is deliberate: "we checked and
found nothing" and "nothing was checked" must not look the same on a pull
request. `action_required` is never used — it invites a human to trigger a
remediation that does not exist.

**Annotations go only where they will render.** GitHub accepts an annotation
only on a line the diff touches and *silently discards* the rest, so the diff's
added lines are read first (parsing each file's patch hunks) and findings are
filtered against them. Anything that cannot be anchored — a finding in untouched
code, a finding with no line, an HTTP surface like `GET /orders/{id}` that is
not a file, or an overflow past GitHub's 50-annotation cap — moves into the check
run's body, where a reviewer still sees it. Both counts are recorded, so
"12 of 30 annotated" is a fact rather than something to infer.

**New findings are separated from pre-existing ones.** A pull request touching
one file is not presented as having introduced eighty issues the repository
already had. Findings first seen in the published run lead; the rest are counted
below.

**No evidence is posted.** Title, severity, rationale, remediation, probe id and
fingerprint — never an evidence bundle, a response body, or a code span a
secrets engine matched. Everything passes the same `scrub` the notification
layer uses on the way out.

## Usage

```bash
kervy-ai pr publish \
  --connection <connection-id> \
  --owner acme --repo api --pr 412 \
  --sha $GITHUB_SHA \
  --run <run-id>
```

Exits non-zero when the check run concluded `failure`, so a CI job can use this
in place of a separate gate step and get one verdict instead of two that could
disagree.

## Roles

| Action | Minimum role |
|---|---|
| create, update, delete a connection | admin |
| publish to a pull request | security engineer |
| list connections and post history | analyst |

Publishing is **security engineer, not admin**, on purpose: posting a check run
is part of running an assessment, and requiring an admin for it would push teams
towards putting an admin credential in CI — the outcome the API-key role cap
exists to prevent.

## What is not built

* **No webhook receiver.** Kervy does not listen for `pull_request` events and
  scan automatically; publishing is invoked by CI or by hand. Ingesting webhooks
  means an inbound authenticated endpoint, replay protection and a decision about
  what a push from a fork may trigger — worth doing deliberately rather than
  bolted on.
* **No GitLab, Bitbucket or Azure DevOps.** The contract is provider-shaped, so
  adding one is an adapter, but only GitHub exists today.
* **No re-posting or de-duplication.** Publishing twice for the same head SHA
  creates two check runs. The post history records both; nothing updates the
  first.
* **No review comments in addition to annotations.** `post_review` exists and is
  tested, but `publish` uses the check run alone: two writes mean two chances to
  half-succeed, and a review comment on a line the check run already annotated
  is the same message twice.
* **No autofix**, per the boundary above.
