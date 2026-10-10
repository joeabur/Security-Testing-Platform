# Running Kervy in CI

> Scope note: this document covers the `kervy-ai` CLI, API keys and the
> security gate — Phase 10 of `docs/BUILD_SPEC.md` §26. The workflows in
> `.github/workflows/` that test *this repository* are described at the end.

## The short version

```yaml
- name: Kervy security gate
  env:
    KERVY_BASE_URL: https://kervy.internal/api/v1
    KERVY_API_KEY: ${{ secrets.KERVY_API_KEY }}
    KERVY_ORGANIZATION: ${{ vars.KERVY_ORGANIZATION }}
  run: |
    pip install kervy-security-backend
    kervy-ai ci --target "$KERVY_TARGET" --config security-gate.yaml
```

Exit codes, from §20, are the contract:

| Code | Meaning | What a pipeline should do |
|---|---|---|
| 0 | pass | continue |
| 1 | the gate failed | fail the build; the findings are real |
| 2 | configuration error | fail the build; **nothing was tested** |
| 3 | authentication error | fail the build; the credential is wrong or expired |
| 4 | scope violation | fail the build; the platform refused, so the scan is not a clean result |

The distinction between 1 and 2–4 is the important one. A gate that reported
"no findings" because it could not authenticate would be worse than no gate
at all, so a refusal never exits 0.

## GitLab CI, Jenkins, Azure DevOps

Nothing above is GitHub-specific — `kervy-ai` is a plain CLI exit-code
contract, and every CI system already fails a job on a non-zero exit from
a script step, so there's no special-case handling to add anywhere below.
These are the same three environment variables and the same `ci` command
as "The short version" above, in each platform's own syntax.

**GitLab CI** (`.gitlab-ci.yml`) — set `KERVY_API_KEY` as a masked,
protected CI/CD variable in the project's own Settings → CI/CD → Variables
rather than in this file; GitLab injects it as an environment variable
automatically, the same way `secrets.KERVY_API_KEY` works in the GitHub
Actions example:

```yaml
kervy-security-gate:
  stage: test
  image: python:3.12-slim
  variables:
    KERVY_BASE_URL: https://kervy.internal/api/v1
    KERVY_ORGANIZATION: your-org-slug
  script:
    - pip install kervy-security-backend
    - kervy-ai ci --target "$KERVY_TARGET" --config security-gate.yaml
```

**Jenkins** (`Jenkinsfile`, declarative pipeline) — `credentials()` binds a
secret already stored in the Jenkins Credentials store to an environment
variable for the stage; it is never written into the `Jenkinsfile` itself:

```groovy
pipeline {
    agent any
    environment {
        KERVY_BASE_URL     = 'https://kervy.internal/api/v1'
        KERVY_ORGANIZATION = 'your-org-slug'
        KERVY_API_KEY      = credentials('kervy-api-key')
    }
    stages {
        stage('Security gate') {
            steps {
                sh 'pip install kervy-security-backend'
                sh 'kervy-ai ci --target "$KERVY_TARGET" --config security-gate.yaml'
            }
        }
    }
}
```

**Azure DevOps** (`azure-pipelines.yml`) — `$(KERVY_API_KEY)` resolves from
a secret pipeline variable or a linked variable group (marked "Keep this
value secret" in the UI), mapped into the step's environment the same way
`secrets.KERVY_API_KEY` is mapped in the GitHub Actions example:

```yaml
steps:
  - script: |
      pip install kervy-security-backend
      kervy-ai ci --target "$KERVY_TARGET" --config security-gate.yaml
    env:
      KERVY_BASE_URL: https://kervy.internal/api/v1
      KERVY_ORGANIZATION: your-org-slug
      KERVY_API_KEY: $(KERVY_API_KEY)
      KERVY_TARGET: $(KERVY_TARGET)
    displayName: Kervy security gate
```

## Why the gate ignores some findings

`kervy-ai gate` will **not** fail a build on:

- **Single-shot findings.** One observation is not a measurement. The AI
  engine reports an attack success rate with a confidence interval precisely
  so that a finding can say how sure it is; a result seen once says very
  little, and a pipeline that fails on it fails arbitrarily. `require_stability`
  defaults to `[deterministic, probabilistic]` and you can add `single_shot`
  if you understand the trade-off — but it is never the default.
- **Low-confidence findings**, below `min_confidence` (default `medium`).
- **Design-review findings.** An observation about declared tool permissions
  is for a human to weigh, not for a deploy to die on.
- **Findings somebody already ruled on** — `false_positive`, `accepted_risk`
  or `closed`. Otherwise triage is decorative: an accepted risk would keep
  failing the build anyway.

This is deliberate, and it is the difference between a tool a team keeps and
one they switch off in week two. A flaky gate does not make anyone safer; it
teaches people to add `|| true`.

Every exclusion is printed, with its reason:

```
security gate: PASS
counts: critical=0, high=0, informational=0, low=0, medium=1
not counted (2):
  - [CRITICAL] Direct prompt injection: stability is single_shot, which this gate
    does not act on. One observation is not a measurement, and a pipeline that
    fails on one fails arbitrarily.
  - [HIGH] Tool scoping: ignored until 2026-12-31: accepted risk, TICKET-987
```

"Why did this not fail?" has to be answerable from the CI log alone.

## `security-gate.yaml`

```yaml
security_gate:
  fail_on: [critical, high]      # this severity and anything worse
  max_high: 0                    # null means no limit
  max_medium: 5
  min_confidence: medium
  require_stability: [deterministic, probabilistic]
  ignore:
    - fingerprint: sha256:...
      reason: "accepted risk, TICKET-987"
      expires: 2026-12-31
```

Notes that have bitten people:

- `fail_on: [high]` also fails on critical. The list means "this bad and
  worse", not "exactly this".
- `max_high` and `fail_on` are independent. Setting `fail_on: [critical]`
  without also relaxing `max_high` still fails on a high finding, because the
  default limit is zero.
- An unknown key is an error, not a warning. A typo'd `max_hihg: 0` that
  silently did nothing would leave you believing you had a gate you did not
  have.
- `reason` and `expires` on an ignore are both required. An exclusion nobody
  revisits is how a gate quietly stops covering the thing it was added for.

## API keys

Create one per pipeline from the API or the CLI, as an admin. There is no
dashboard UI for this yet — API and CLI only, same as several other
admin-only actions in this platform.

```bash
kervy-ai apikey create --name ci-staging --scope read --scope scan \
  --expires 2027-01-01T00:00:00Z                                        # admin
kervy-ai apikey list                                                     # admin
kervy-ai apikey revoke "$KEY_ID"                                         # admin
```

or, equivalently:

```bash
curl -X POST "$KERVY_BASE_URL/organizations/$ORG/api-keys" \
  -H "Authorization: Bearer $SESSION" \
  -d '{"name": "ci-staging", "scopes": ["read", "scan"], "expires_at": "2027-01-01T00:00:00Z"}'
```

The secret is in that response and nowhere else, ever. Store it in your CI
secret store immediately.

What a key **cannot** do, by design:

- create a target,
- grant or amend an authorization,
- add or change a member,
- mint another key.

The highest role any scope maps to is security engineer. A credential that
lives in a CI runner is the most exposed thing this platform issues, and the
authorization grant — the human act that makes a scan lawful — is not
something it should ever be able to perform. If your pipeline needs a new
target scanned, a person authorizes it first.

Scopes:

| Scope | Grants |
|---|---|
| `read` | see targets, runs, findings, reports and evidence manifests |
| `triage` | `read`, plus moving findings through their lifecycle and assigning remediation |
| `scan` | `read`, plus starting assessments and retests |

Keys record `last_used_at`, so you can find the ones nothing is using and
revoke them.

## Finishing a target's configuration

`target add` only creates the target row. Rules of engagement, the adapter,
the code scope and the runtime-protection declaration are each their own
resource, matching the API:

```bash
kervy-ai target roe --target "$TARGET_ID" --file roe.yaml                 # admin
kervy-ai target adapter --target "$TARGET_ID" --file adapter.yaml         # security engineer
kervy-ai target code --target "$TARGET_ID" --file code.yaml               # admin
kervy-ai target runtime-protection --target "$TARGET_ID" --file rp.yaml   # admin
```

`adapter` is the one of the four a CI credential (`scan` scope) can call —
it configures how the platform talks to the target, not whether testing it
is authorized. `roe`, `code`, and `runtime-protection` need an admin
session (`kervy-ai login`), same as `auth grant` above: each is a claim
someone accountable is making about scope or protection, not a pipeline
setting.

## Scanning source code without the full target workflow

If all a pipeline needs is SAST/SCA/secrets/IaC over a repository — no live
target, no adapter, no operator-granted authorization — `kervy-ai repo` is
the shorter path (`docs/repositories.md` has the full design):

```bash
kervy-ai repo add --name "$REPO_NAME" --url "$REPO_URL" --branch "$BRANCH" --authorized
kervy-ai repo scan "$REPOSITORY_ID" --wait   # not yet supported; see below
```

`repo add`/`repo scan` need `security_engineer` — no admin step, because
adding a repository is its own consent (`--authorized`) rather than a claim
someone else has to sign off on. `repo scan` does not yet support `--wait`
or `--dry-run` the way `scan` does for a full target; poll `kervy-ai runs
show "$RUN_ID"` for now.

## AI-drafted text

`kervy-ai assist` mirrors the assistant API exactly (`docs/ai-security-testing.md`):
requesting a draft is `analyst`, accepting one into the record is
`security_engineer` — reading a suggestion is cheap, and putting it into
the record is not.

```bash
kervy-ai assist status                                                   # viewer
kervy-ai assist draft --run "$RUN_ID" --field run_summary                # analyst
kervy-ai assist draft --run "$RUN_ID" --field remediation \
  --scan-result "$SCAN_RESULT_ID"                                        # analyst
kervy-ai assist drafts --run "$RUN_ID"                                   # viewer
kervy-ai assist accept "$DRAFT_ID"                                       # security engineer
```

`--field run_summary` needs no `--scan-result`; every other field does —
the same requirement the API enforces with a `422`.

## Workflows

`kervy-ai workflow` covers the full lifecycle (`docs/workflows.md`):
defining or changing one is `admin`, because the gate decides whether a
release ships; triggering one, and resolving a run an unattended trigger
paused, is `security_engineer` — the same role starting a scan directly
requires, because a workflow must never be a way to start one with less
authority.

```bash
kervy-ai workflow create --name "main branch" --target "$TARGET_ID" \
  --gate-config security-gate.json                                      # admin
kervy-ai workflow list                                                   # analyst
kervy-ai workflow show "$WORKFLOW_ID"                                    # analyst
kervy-ai workflow update "$WORKFLOW_ID" --disable                        # admin
kervy-ai workflow trigger "$WORKFLOW_ID" --ref refs/heads/main \
  --commit "$GITHUB_SHA"                                                 # security engineer
kervy-ai workflow runs "$WORKFLOW_ID"                                    # analyst
kervy-ai workflow webhook-secret "$WORKFLOW_ID"                          # admin; shown once
kervy-ai workflow approve "$WORKFLOW_ID" --run "$WORKFLOW_RUN_ID"        # security engineer
kervy-ai workflow reject "$WORKFLOW_ID" --run "$WORKFLOW_RUN_ID" \
  --reason "not authorized this week"                                   # security engineer
```

`approve`/`reject` act on a run Celery Beat or the inbound webhook queued
unattended and paused before it would touch a scan-touching action — see
`docs/workflows.md`'s "approval gate for unattended triggers". `--gate-config`
takes a path to a JSON file (the same shape the API's `gate_config` field
validates through `load_config`), and `--schedule-minutes` only means
anything with `--trigger-kind schedule` (a 60-minute floor, the same safety
rail the API enforces).

## Typical pipeline shapes

**Gate an existing run** (the scan runs on a schedule; the pipeline only
checks it):

```bash
kervy-ai gate --run "$RUN_ID" --config security-gate.yaml
```

**Scan and gate in one step**, which is what `ci` is for:

```bash
kervy-ai ci --target "$TARGET_ID" --fail-on critical,high --timeout 2400
```

`ci` waits for the run to reach a terminal state, then gates on the findings
*that run* produced — not on the organization's whole backlog, which would
fail your build for something another team has open. If the run halted (a
budget was exhausted, the scope engine refused, the kill switch was pulled)
it exits 4 rather than gating: a run that was stopped did not finish looking,
and its findings are not a basis for passing a build.

**Check scope before scanning anything**, which is worth doing in a pipeline
that generates its own target URLs:

```bash
kervy-ai scope explain "$TARGET_ID" --url "https://$HOST/api/health"   # exits 4 if refused
```

## Catching an AI regression between versions

`kervy-ai gate`/`ci` answer "does this run have findings bad enough to fail
the build" — a single run's absolute severity. They do not answer "did this
*change* make the model easier to attack than it was last time", because a
`RetestResult` is presence/absence by fingerprint, not a rate. `kervy-ai test
ai` is the developer-loop command for that second question: it compares the
AI probes' attack success rates between two runs of the same target, using
the same Wilson-interval non-overlap rule the AI engine itself uses for
attack-vs-control (`docs/ai-security-testing.md`), applied a second time to
baseline-vs-current. A few points of difference in a stochastic model's rate
is not reported as a regression; the two runs' 95% confidence intervals have
to stop overlapping before it is.

```bash
# Scans the target, compares the result against the most recent prior
# completed run for the same target, and fails the build on a regression.
kervy-ai test ai --target "$TARGET_ID" --ci
```

```bash
# Compare two runs that already exist (e.g. a scheduled nightly run against
# last week's), without starting a new scan.
kervy-ai test ai --current "$THIS_WEEK_RUN_ID" --baseline "$LAST_WEEK_RUN_ID" --ci
```

Without `--current`, it starts a new `profile=ai` scan and waits for it the
same way `ci` does. Without `--baseline`, it picks the most recent other
completed run for the same target — if none exists yet (the first time this
runs against a target), it exits 2 rather than silently treating "no
baseline" as "no regression possible." `--ci` is what turns the comparison
into a build gate; without it, the command only reports, which is the shape
to use while first establishing a baseline. `--report report.json` (or
`.md`) writes the full per-probe comparison, including probes that newly
appeared, were resolved, or were unchanged — not only the regressions.

## This repository's own workflows

| Workflow | What it does |
|---|---|
| `ci.yml` | ruff, mypy, pytest with coverage, frontend lint, typecheck and build |
| `security.yml` | Bandit, Semgrep against the platform's own ruleset, detect-secrets |
| `deps.yml` | pip-audit against the installed environment, npm audit |
| `codeql.yml` | CodeQL for Python and TypeScript |
| `container.yml` | Trivy image scan (vulnerabilities, misconfiguration, secrets) for the backend, worker and demo-target images |
| `sbom.yml` | CycloneDX SBOMs for the backend environment and the frontend lockfile, plus the ML-BOM |
| `framework-drift.yml` | weekly check that pinned framework mappings (§3.4) still match the upstream version |
| `lab-e2e.yml` | a real assessment run against the demo lab over real sockets |
| `release.yml` | on a tag: re-verify, then build, sign and attest the release artifacts (`docs/releasing.md`) |

`security.yml` runs the same Semgrep rules the product's SAST engine ships,
including `kervy.ungated-http-client` — the rule that catches an HTTP client
built outside the scope engine. A security tool that does not run its own
rules against itself is making a claim it has not tested. That rule currently
has exactly three suppressions, each annotated at the line it applies to: the
gated transport itself (`app/core/scope/transport.py`), which *is* the choke
point, and two in the CLI's client (`kervy_cli/client.py`) — the pre-session
CSRF fetch and the general request path — which talk to the Kervy API rather
than to a target.

detect-secrets runs against `.secrets.baseline` rather than as a bare scan.
A bare scan is red on day one here — migration revision hashes, environment
variable *names* like `KERVY_API_KEY`, and the credentials the vulnerable lab
fixture contains on purpose — and a job that is red from the start is a job
the team turns off. The baseline records those as hashes, never as values, so
the step fails only on something new. Re-audit it with
`detect-secrets audit .secrets.baseline`.

`container.yml` scans three images on different terms, matrixed per image
rather than one severity for all of them: `backend` and `worker` fail on
`HIGH,CRITICAL`, because they are products; `demo-target` fails only on
`CRITICAL` (`scanners: misconfig,secret` still runs at `HIGH,CRITICAL` for all
three) — its application-layer findings are the point of it, not a defect to
scan away. All three images build from `python:3.12-slim`, so
`.trivyignore` at the repo root applies to each: two dated, documented
exemptions for OS-package (openssl) advisories with no patched Debian package
resolvable yet, not for anything this repository's own code or dependencies
introduce. Revisit each entry once Debian ships the fix; don't carry either
past that point.

`deps.yml`'s pip-audit step carries four `--ignore-vuln` exemptions
(`PYSEC-2026-2132`, `PYSEC-2026-3481`, `PYSEC-2026-3482`, `PYSEC-2026-3483`),
each dated and justified inline in the workflow: a `semgrep>=1.173` upgrade
would fix all four but hard-pins a `pyjwt` version that conflicts with this
project's own `pyjwt>=2.14` fix, and none of the four is reachable through how
this codebase actually calls `click` or `mcp`. Read the comment in
`.github/workflows/deps.yml` for the current, dated reasoning before adding or
removing one — it is revisited, not evergreen.

`lab-e2e.yml` runs the lab under uvicorn on loopback rather than in Docker
(no container runtime needed in CI) and, before the assessment, asserts the
lab still refuses to start with a provider credential in its environment —
the property that makes running it in CI safe at all.

## The backend's dependency lock

`backend/pyproject.toml` declares its dependencies as ranges (`fastapi>=0.115`,
`bandit>=1.7`, and so on) — deliberately permissive, so a patch release never
needs a pyproject.toml edit to pick up. Left alone, that means every `pip
install` — a CI run today, a Docker build tomorrow, a contributor's laptop a
month from now — can each resolve to a *different* concrete version, since
"latest satisfying the range" moves as PyPI publishes new releases. This repo
has hit that exact class of drift for real more than once (several `git log`
entries exist solely to re-pin something after an upstream release moved):
`asteval`, `cyclonedx-python-lib`, and `pip-audit`'s own ignore list all carry
comments in `pyproject.toml`/`deps.yml` explaining a version-drift incident.

`backend/uv.lock` (generated by [uv](https://docs.astral.sh/uv/)) is the fix:
it resolves the whole dependency tree once and records the exact version of
every package, transitive dependencies included. `backend/constraints.lock.txt`
is a flat, plain-pip-readable projection of that same lock (`name==version`
per line, no `uv` required to read it) — every `pip install` in this repo's
CI, both Dockerfiles, and a contributor's own local install now passes it via
`-c constraints.lock.txt`, so all four install the identical tree uv.lock
describes, not whatever today's range resolution happens to be.

**Regenerate both together** — never hand-edit either — with:

```bash
cd backend && python -m scripts.relock
```

Do this when `pyproject.toml`'s dependencies change, or periodically to pick
up patch releases; then run the test suite (`pytest -q`) before committing
the result, the same review any dependency bump gets. `detect-secrets` is
deliberately excluded from `constraints.lock.txt`: `security.yml` pins it to
an exact, manually-reviewed version independent of this lock, because
`detect-secrets-hook` treats *any* version mismatch against
`.secrets.baseline` as "needs updating" — bumping it is its own deliberate
step (see that workflow's own comment).

**`deps.yml`'s Python job is the one install site that intentionally does
not use the lock.** Its entire purpose is a weekly fresh resolution — each
run picks up whatever a range currently resolves to, specifically so a newly
published CVE in a dependency the lock hasn't caught up to yet gets noticed.
Pinning it to `constraints.lock.txt` would make it re-audit the same already-
reviewed tree forever and defeat the job.
