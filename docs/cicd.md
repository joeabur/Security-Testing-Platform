# Running Aegis in CI

> Scope note: this document covers the `aegis-ai` CLI, API keys and the
> security gate — Phase 10 of `docs/BUILD_SPEC.md` §26. The workflows in
> `.github/workflows/` that test *this repository* are described at the end.

## The short version

```yaml
- name: Aegis security gate
  env:
    AEGIS_BASE_URL: https://aegis.internal/api/v1
    AEGIS_API_KEY: ${{ secrets.AEGIS_API_KEY }}
    AEGIS_ORGANIZATION: ${{ vars.AEGIS_ORGANIZATION }}
  run: |
    pip install aegis-ai-security-backend
    aegis-ai ci --target "$AEGIS_TARGET" --config security-gate.yaml
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

## Why the gate ignores some findings

`aegis-ai gate` will **not** fail a build on:

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

Create one per pipeline, from the UI or the API, as an admin:

```bash
curl -X POST "$AEGIS_BASE_URL/organizations/$ORG/api-keys" \
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
aegis-ai target roe --target "$TARGET_ID" --file roe.yaml                 # admin
aegis-ai target adapter --target "$TARGET_ID" --file adapter.yaml         # security engineer
aegis-ai target code --target "$TARGET_ID" --file code.yaml               # admin
aegis-ai target runtime-protection --target "$TARGET_ID" --file rp.yaml   # admin
```

`adapter` is the one of the four a CI credential (`scan` scope) can call —
it configures how the platform talks to the target, not whether testing it
is authorized. `roe`, `code`, and `runtime-protection` need an admin
session (`aegis-ai login`), same as `auth grant` above: each is a claim
someone accountable is making about scope or protection, not a pipeline
setting.

## Scanning source code without the full target workflow

If all a pipeline needs is SAST/SCA/secrets/IaC over a repository — no live
target, no adapter, no operator-granted authorization — `aegis-ai repo` is
the shorter path (`docs/repositories.md` has the full design):

```bash
aegis-ai repo add --name "$REPO_NAME" --url "$REPO_URL" --branch "$BRANCH" --authorized
aegis-ai repo scan "$REPOSITORY_ID" --wait   # not yet supported; see below
```

`repo add`/`repo scan` need `security_engineer` — no admin step, because
adding a repository is its own consent (`--authorized`) rather than a claim
someone else has to sign off on. `repo scan` does not yet support `--wait`
or `--dry-run` the way `scan` does for a full target; poll `aegis-ai runs
show "$RUN_ID"` for now.

## Typical pipeline shapes

**Gate an existing run** (the scan runs on a schedule; the pipeline only
checks it):

```bash
aegis-ai gate --run "$RUN_ID" --config security-gate.yaml
```

**Scan and gate in one step**, which is what `ci` is for:

```bash
aegis-ai ci --target "$TARGET_ID" --fail-on critical,high --timeout 2400
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
aegis-ai scope explain "$TARGET_ID" --url "https://$HOST/api/health"   # exits 4 if refused
```

## This repository's own workflows

| Workflow | What it does |
|---|---|
| `ci.yml` | ruff, mypy, pytest with coverage, frontend lint and typecheck |
| `security.yml` | Bandit, Semgrep against the platform's own ruleset, detect-secrets |
| `deps.yml` | pip-audit against the installed environment, npm audit |
| `codeql.yml` | CodeQL for Python and TypeScript |
| `sbom.yml` | CycloneDX SBOMs for the backend environment and the frontend lockfile |

`security.yml` runs the same Semgrep rules the product's SAST engine ships,
including `aegis.ungated-http-client` — the rule that catches an HTTP client
built outside the scope engine. A security tool that does not run its own
rules against itself is making a claim it has not tested. That rule currently
has exactly two suppressions, each annotated at the line it applies to: the
gated transport itself, which *is* the choke point, and the CLI's client,
which talks to the Aegis API rather than to a target.

detect-secrets runs against `.secrets.baseline` rather than as a bare scan.
A bare scan is red on day one here — migration revision hashes, environment
variable *names* like `AEGIS_API_KEY`, and the credentials the vulnerable lab
fixture contains on purpose — and a job that is red from the start is a job
the team turns off. The baseline records those as hashes, never as values, so
the step fails only on something new. Re-audit it with
`detect-secrets audit .secrets.baseline`.

Not yet present, and tracked in `docs/roadmap.md` rather than stubbed:
`container.yml` (Trivy), `lab-e2e.yml` (needs the Phase 12 demo lab),
`release.yml` (needs the Phase 13 release process) and `framework-drift.yml`
(needs the pinned framework corpus from §3.4).
