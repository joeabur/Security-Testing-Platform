# Repositories: the fast path onto code scanning

Aikido, Snyk and similar tools start from "connect a repository" — paste a
URL, pick a branch, scan. This platform's existing code-scanning support
(`docs/BUILD_SPEC.md` Addendum v2.1 §3) is real and complete — SAST
(semgrep, bandit), SCA (pip-audit), secrets (detect-secrets/gitleaks), IaC
(checkov), plus the container/license/EOL/name-confusion engines — but it
is reached through the same `Target` → `Authorization` →
`Rules-of-Engagement` sequence built for a live network assessment: a base
URL to probe, an operator-role authorization grant, a YAML RoE document.
None of that has anything to do with scanning source code someone already
has read access to.

`app/core/repositories/service.py` is the shortcut. It composes the same
three rows that workflow would eventually produce, from three inputs: a
repository URL, an optional branch, and an explicit affirmation that the
caller has the right to have it scanned.

## What "connecting a repository" actually creates

| Full workflow | This shortcut |
|---|---|
| `Target` with a `base_url` to probe | `Target` of kind `code_repo`, `base_url` is the repository's own URL — there is nothing else to reach |
| `Authorization` granted by an operator (often someone else), with a reference and a signed-off validity window | `Authorization` self-affirmed by whoever connected it, `reference` says so plainly, valid for ten years |
| `Rules of Engagement` — domains, methods, budgets, `code_scope` | Only `code_scope` is real; `allowed_domains`, `allowed_methods` etc. are empty, because this target is never dialled |

`TargetKind.CODE_REPO` is what keeps this safe: `app/workers/tasks.py`
builds a `DastCheck` only for `kind is TargetKind.WEB_APP`, and an
`AiSecurityCheck` only when an adapter is configured. A `CODE_REPO` target
has neither, so a scan runs only the AppSec engines, against a checkout,
with no code path that could reach a network host at all.

## Adding one

```
aegis-ai repo add \
  --name "Payments service" \
  --url https://github.com/acme/payments.git \
  --branch main \
  --authorized
```

`--authorized` is required — the CLI refuses before sending anything if
it's missing, and the API refuses too (`422`) if the field arrives `false`.
It is the one piece of consent this flow asks for: not a signature from
someone else, an affirmation from whoever is adding the repository, audited
the same way every other security-relevant action on this platform is
(`app/audit/service.py`, action `repository.add`).

Equivalent API call: `POST /organizations/{organization_id}/repositories`
— see `app/schemas/repository.py` for the full body shape, including the
optional `languages`, `allowed_paths`/`excluded_paths` (default: everything)
and `max_repo_size_mb` fields.

The same host- and scheme-allowlisting `app/core/appsec/checkout.py`
already enforces for a target-attached repository applies here — `https`
or `file` only, no inline credentials in the URL, and the clone is
allowlisted to exactly the host the repository names, not a general list.

## Scanning one

```
aegis-ai repo scan <repository-id>
```

Queues an `AssessmentRun` against the connected repository's `Target`,
through the same `queue_run` every other scan uses — it shows up in
`aegis-ai runs list`, has the same audit trail, and its findings promote
into the same `Finding` rows the findings board and remediation/retest
workflow already work with.

## Listing, reading, removing

```
aegis-ai repo list
aegis-ai repo show <repository-id>
aegis-ai repo remove <repository-id>
```

`repo show` includes the repository's ten most recent scans and a count of
its currently-open findings by severity. `repo remove` needs
`Role.ADMIN` — one step above the `Role.SECURITY_ENGINEER` that adding and
scanning need, the same asymmetry the rest of this platform draws between
a reversible action and one that removes something other people may rely
on.

The dashboard's Repositories page (`/app/organizations/{id}/repositories`)
is read-only, like every other page there (`app/web/router.py`'s own
docstring explains why): it lists connected repositories and their latest
scan status, and shows the two write actions above as disabled buttons
naming the CLI/API call that performs them.

## What this is not

A per-organization quota, an auto-discovery flow that lists every repository
in a connected GitHub org, or a replacement for the full workflow. An
operator who needs a live network target's own authorization/RoE
machinery — a signed-off grant from someone else, a real validity window
someone reviews, network-scope controls — still uses `aegis-ai target
add`/`auth grant`/`target roe` exactly as before. This is the alternative
for the one case that workflow was never shaped for: source code.
