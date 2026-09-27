# Deployment

For running this beyond a single machine or Compose stack — a cloud-hosted
deployment handling many organizations and concurrent assessments — see
[`docs/scaling-architecture.md`](scaling-architecture.md), which builds on
everything below rather than replacing it.

## Components

| Process | Scale | Needs |
|---|---|---|
| API (uvicorn) | horizontal | Postgres, Redis |
| Worker (Celery) | horizontal | Postgres, Redis, **outbound network to targets**, credential variables, scanner binaries, `EVIDENCE_ROOT` |
| Frontend (Next.js) | horizontal | the API |
| PostgreSQL | one primary | |
| Redis | one | broker and kill switch |

The worker is the only component that talks to targets. It is also the only one
that needs the credential variables and the scanner binaries, and the only one
that writes evidence.

## Network posture

The worker makes outbound requests **by design** — that is the product. The
scope engine bounds them, but defence in depth belongs at the network edge too:

- Put the worker on a subnet with no route to your own internal infrastructure,
  unless an engagement specifically covers it.
- Block the cloud metadata endpoint at the network level as well. The engine
  refuses it unconditionally; a second control costs nothing.
- Egress-filter to the destinations engagements actually need where you can.

The API needs no outbound access at all. Notifications and pull-request
publishing happen in the worker.

## Evidence storage

`EVIDENCE_ROOT` holds the most sensitive artifact the platform produces:
redacted but real exchanges with a customer's system.

- A filesystem path, not a bucket with a public URL, and not served except
  through the authenticated API.
- Shared across API and worker replicas — both read it.
- Back it up with the same care as the database; a report without its evidence
  is unverifiable.
- **Unencrypted at rest unless `AEGIS_EVIDENCE_ENCRYPTION_KEY` is set**
  (`docs/configuration.md`); off is the default. Set it, or use an encrypted
  volume regardless — this is a stated residual either way
  (`docs/threat-model.md`).
- Have a retention and deletion policy. `purge` genuinely deletes.

## Database

- Separate credentials for the application role.
- Consider `REVOKE UPDATE, DELETE ON audit_logs` for the app role. The
  application never issues them, so revoking costs nothing and turns a
  by-construction guarantee into an enforced one.
- Migrations are forward and backward tested; run `alembic upgrade head` as a
  deploy step, before the new code serves traffic.
- **The runtime database role must not be a superuser, and must not own the
  application's tables without `FORCE ROW LEVEL SECURITY`.** Migration
  `b2e6f4a91c7d` enables Postgres Row-Level Security (`docs/security-model.md`
  guarantee #26) on the 14 tenant-scoped tables and sets `FORCE`, which closes
  the table-owner exemption — but Postgres exempts a **superuser** from RLS
  unconditionally, with no override available from inside the database. If the
  role the application connects as is a superuser (true of the default
  `postgres` role many hosted Postgres quickstarts create), RLS is silently a
  no-op: no error, no warning, every policy simply never evaluated. Create a
  dedicated, non-superuser role for the application and grant it only what
  the schema needs.

## Configuration

See `docs/configuration.md`. The production-specific items:

- `ENVIRONMENT=production` — startup **refuses** with the development JWT
  secret, which is the intended behaviour.
- `SESSION_COOKIE_SECURE=true` behind TLS.
- Credential variables in the **worker's** environment, not only the API's.
- `AEGIS_NOTIFY_ALLOWED_WEBHOOK_HOSTS`, `AEGIS_NOTIFY_ALLOWED_SMTP_HOSTS`,
  `AEGIS_VCS_ALLOWED_HOSTS` set to the minimum. These are the operator's control
  over where data may go; an empty list is the safe default.
- `PLUGINS_CONFIG` only if you use plugins. There is no sandbox.

## Scanner binaries

The worker needs semgrep, bandit, pip-audit, checkov, gitleaks and trivy on its
`PATH` for the corresponding engines. Any that are missing produce an explicit
`not tested` finding rather than a silent gap, so a partial install degrades
honestly — but check the coverage section of a report if you expected AppSec
results and did not get them.

Trivy runs offline against whatever database the image already has. Refresh it
as part of your image build, or its findings will go stale quietly.

## Scaling and backpressure

Concurrency is bounded per run by the rules of engagement, not globally. Several
large concurrent assessments can saturate a worker; scale worker replicas rather
than raising per-run budgets, since the budgets are also the customer's
protection against your scan.

## Upgrades

1. `alembic upgrade head`.
2. Roll the API.
3. Roll the worker.

In that order. The worker is what runs assessments; rolling it against an
un-migrated database is the failure mode to avoid.

## What is not provided

- No Helm chart or Kubernetes manifests — `docs/scaling-architecture.md` has
  an illustrative, unexercised sketch, not a shipped one.
- No Terraform.
- No multi-region or HA guidance beyond "run more replicas".
- No SSO/SAML/OIDC — local accounts only.
- No backup tooling; use your database's.
- `docker compose up --build` is written but **unverified** (see
  `docs/installation.md`), so treat the compose path as a starting point rather
  than a tested deployment.
