# Scaling to a cloud-hosted deployment

`docs/deployment.md` covers running this platform correctly on one machine
or one Docker Compose stack. This page is the next step up: the reference
architecture, component-by-component scaling design, and setup path for
running it as a cloud-hosted service handling many organizations and many
concurrent assessments.

**Status, stated plainly:** this is a reference design grounded in the
actual code (`app/core/config.py`, `app/core/evidence/store.py`,
`docker-compose.yml`, the Dockerfiles), not a tested deployment. No Helm
chart, Terraform module, or cloud account has exercised it end to end — the
same honesty `docs/deployment.md` already applies to `docker compose up`
applies here, one layer up. Where a component needs a code change to scale
past single-node (evidence storage, below), that is said explicitly rather
than implied to already exist.

## When you need this page and when you don't

Six processes, all stateless except the two datastores
(`docs/architecture.md`, `docs/deployment.md`): API, worker, beat, frontend,
PostgreSQL, Redis. `docs/deployment.md`'s "run more replicas" is a complete
answer up to real load — a handful of API replicas and a worker pool sized
to your concurrent-assessment count, behind a load balancer, against a
right-sized managed Postgres and Redis, is a legitimate production
deployment on its own. Reach for this page when at least one of these is
true:

- Worker capacity needs to scale on its own signal (queue depth), not a
  fixed replica count you tune by hand.
- You want the datastores, evidence storage, and secrets on managed cloud
  services rather than self-run containers.
- You're deploying through a cloud provider's orchestrator (Kubernetes,
  ECS, or similar) rather than `docker compose`, and want a reference
  topology before writing your own manifests.
- More than a few organizations will run concurrent assessments, and you
  want the isolation and blast-radius questions answered before that's true
  rather than after.

## Reference architecture

```
                              ┌─────────────┐
                     users ──▶│     CDN /   │
                              │   ingress   │
                              └──────┬──────┘
                    ┌────────────────┼────────────────┐
                    ▼                                  ▼
            ┌───────────────┐                  ┌───────────────┐
            │   frontend    │                  │      API      │
            │  (N replicas, │─────HTTP────────▶│  (N replicas, │
            │   stateless)  │                  │   stateless)  │
            └───────────────┘                  └───────┬───────┘
                                                         │
                              ┌──────────────────────────┼──────────────────────┐
                              ▼                          ▼                      ▼
                      ┌───────────────┐         ┌───────────────┐     ┌────────────────┐
                      │ managed        │         │ managed Redis │     │ evidence store  │
                      │ PostgreSQL     │◀───────▶│ (broker, kill │     │ (shared volume  │
                      │ (primary [+RR])│         │  switch, rate │     │  or filesystem) │
                      └───────┬────────┘         │  limit, JWT   │     └────────┬────────┘
                              │                   │  revocation)  │              │
                              │                   └───────┬───────┘              │
                              │                           │                      │
                              │              ┌────────────┴─────────────┐        │
                              │              ▼                          ▼        │
                              │      ┌───────────────┐          ┌───────────────┐│
                              └─────▶│    worker      │─────────▶│    worker     ││
                                     │  pool (scales  │  scope-  │  pool (cont.) ││
                                     │  on queue      │  gated   │               ││
                                     │  depth)        │  egress  │               ││
                                     └───────┬────────┘          └───────┬───────┘│
                                             │                            │       │
                                             └────────────────────────────┴───────┘
                                                          │
                                    ┌─────────────────────┼─────────────────────┐
                                    ▼                      ▼                     ▼
                                 target              AI provider          Slack/SMTP/
                              (authorized)                              api.github.com
```

Nothing in this diagram changes the one architectural claim
`docs/architecture.md` makes: everything that leaves the worker still
passes through `ScopeEngine` + `GatedTransport`. Scaling the box around it
does not relax what's inside it — the 409-without-authorization refusal,
the budget enforcement, the cloud-metadata block, all still apply
per-request, per-replica, with no shared bypass.

## Component-by-component

### API and frontend

Stateless, horizontally scalable behind a standard load balancer or
ingress controller with no special affinity — any replica can serve any
request (guarantee #12 in `docs/security-model.md`: every query filters by
`organization_id`, so there's no in-memory per-request state to pin a
session to a specific pod). Scale on CPU/request-rate like any stateless
HTTP service. The API needs **no outbound network access at all**
(`docs/deployment.md`) — give it an egress policy that denies everything by
default; it has no legitimate reason to reach a target, an AI provider, or
the internet.

### Worker pool

The one component that talks to targets, needs credential variables, needs
scanner binaries, and writes evidence (`docs/deployment.md`). Two things
matter for scaling it correctly:

- **Scale on queue depth, not CPU.** A worker spends most of a run's wall
  clock waiting on HTTP responses from the target, not computing — CPU
  utilization under-reports load. Scale on the Celery queue's pending-task
  count (Redis `LLEN` on the broker's queue key, or Celery's own
  `inspect().active()`/`reserved()`), so replica count tracks concurrent
  assessments rather than how busy each worker happens to look.
- **Scale replicas, not per-run budgets.** `docs/deployment.md` already
  states this and it's worth repeating here because it's the mistake
  autoscaling makes easy: the rules-of-engagement budget on a run (max
  requests, concurrency, wall-clock minutes) is the customer's protection
  against the scan, not a throughput knob. Under load, add worker replicas
  to run more assessments in parallel; do not raise `max_concurrency` or
  `requests_per_second` on individual runs to compensate.

Give the worker pool its own network policy, separate from the API's: no
route to your own internal infrastructure unless an engagement specifically
covers it, and the cloud metadata endpoint blocked at the security-group or
network-policy level as well as by the engine's own unconditional refusal
(defense in depth costs nothing here — `docs/deployment.md`).

### Beat (Celery Beat)

The one component this design does **not** scale out. `beat` fires
`dispatch_scheduled_workflows` on a timer and enqueues it for the worker
pool to run — it never talks to a target and needs no scanner binaries or
credential variables (`docs/deployment.md`). Celery Beat itself is not
safe to run with more than one replica: two live instances both fire the
same schedule, so pin this to exactly one — a Kubernetes `Deployment` with
`replicas: 1` (not a `ScaledObject`), or its orchestrator's equivalent of a
singleton. Losing it briefly during a roll delays a scheduled workflow; it
does not corrupt anything.

### PostgreSQL

One primary. A read replica helps report/finding-listing read load if your
dashboard or API traffic skews read-heavy, but writes (runs, findings,
audit log) still go to the primary — there is no write-sharding or
multi-primary design here, and none is needed until you are past what a
single well-sized managed instance (RDS, Cloud SQL, or equivalent) handles,
which is a high bar for this workload shape.

**Connection pooling matters more here than in most services.** Each API
and worker replica opens its own async connection pool
(SQLAlchemy + asyncpg); a large worker fleet under a queue-depth autoscaler
can open connections faster than a naive Postgres `max_connections` budget
tolerates. Put PgBouncer (or your managed provider's built-in pooler, e.g.
RDS Proxy) in front of Postgres in transaction-pooling mode, and size each
replica's pool conservatively rather than relying on Postgres's own limit
as the backstop.

Apply the existing production checklist (`docs/configuration.md`,
`docs/deployment.md`) unchanged: separate app-role credentials, consider
revoking `UPDATE`/`DELETE` on `audit_logs` at the database level, and run
`alembic upgrade head` as an explicit deploy step before new code serves
traffic — never rely on an ORM to create schema at startup.

### Redis

One logical Redis, used for four distinct things: the Celery broker, the
run kill switch, the rate limiter's counters, and JWT revocation
(`docs/rate-limiting.md`, `docs/revocation.md`). At cloud scale, run it as
a managed, HA instance (ElastiCache, Memorystore, or equivalent) rather
than a single container — but size the HA guarantee to the control that
needs it most, because **these four uses do not fail the same way**:

| Use | On Redis unavailable |
|---|---|
| Rate limiter | Fails **open**, logs at error level (`docs/rate-limiting.md`) |
| Run kill switch | A run in flight loses cancellation ability, not correctness |
| JWT revocation | Fails **closed** — every JWT-authenticated request is refused (`docs/revocation.md`) |
| Celery broker | New runs cannot be queued |

A Redis outage under this design does not silently weaken authorization —
it makes the platform loudly unavailable for authenticated JWT traffic
(API keys are unaffected; they check `ApiKey.revoked_at` in Postgres, not
this store). That is the deliberate tradeoff already documented for a
single instance; an HA Redis with automatic failover is what turns "loudly
unavailable for a few seconds during failover" into the actual operational
experience, rather than a longer outage. Don't put revocation on a
best-effort cache tier to save cost — it is the one Redis-backed control
here that is a real authorization decision, not a mitigation layered on
top of one.

### Evidence storage — the one place "just add replicas" doesn't apply

**Stated accurately rather than aspirationally:** `EVIDENCE_ROOT`
(`app/core/config.py`) is a plain filesystem path.
`app/core/evidence/store.py` writes bundles and a hash-chained manifest
directly to `Path` objects — there is no object-storage backend in the
code today. Two ways to scale this, in order of effort:

1. **Shared network filesystem, no code change.** Mount the same network
   volume (EFS, Filestore, Azure Files, or equivalent) at `EVIDENCE_ROOT`
   on every API and worker replica. This is a direct drop-in — the API and
   worker already assume evidence is "shared across replicas — both read
   it" (`docs/deployment.md`); a network filesystem is what makes that true
   once they're on different hosts. This is the honest, minimal-risk path
   and what this reference architecture assumes by default.
2. **Object storage (S3/GCS-backed), a real code change.** Would mean
   adding a storage backend behind `app/core/evidence/store.py`'s
   read/write/verify interface that speaks to a bucket instead of a
   `Path`, keeping the same content-addressing and hash-chain semantics.
   Worth doing if network-filesystem cost or operational overhead becomes
   the bottleneck, but it is new work, not configuration — don't plan a
   deployment assuming it exists until it's built.

Whichever storage layer, the guarantees that already exist keep holding:
never a public URL, served only through the authenticated API
(`docs/security-model.md` guarantee #22), encrypted at rest only if
`KERVY_EVIDENCE_ENCRYPTION_KEY` is set before the deployment starts
collecting evidence (no retrofit tool exists — set it up front, or rely on
the storage layer's own encryption-at-rest, e.g. an encrypted EFS volume or
an encrypted EBS-backed node, as the residual control either way).

## Orchestration

No Helm chart or Terraform ships with this repository
(`docs/deployment.md`'s "what is not provided" already says so, and this
page doesn't change that). The container images do exist and build from
`Dockerfile.backend`, `Dockerfile.worker`, and `Dockerfile.frontend` — `beat`
builds from `Dockerfile.worker` too, just with a different `command`
(`docker-compose.yml`). Any orchestrator that runs OCI images works. A
Kubernetes-shaped sketch of the same six components, illustrative only
(unexercised against a real cluster) — showing `api` and `worker` in full and
`beat` as the one-line addition each needs (a `replicas: 1` `Deployment`
running `celery … beat` instead of `celery … worker`, no volume, no queue-depth
scaler):

```yaml
# api-deployment.yaml — illustrative, not shipped or tested
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kervy-api
spec:
  replicas: 3
  selector:
    matchLabels: { app: kervy-api }
  template:
    metadata:
      labels: { app: kervy-api }
    spec:
      containers:
        - name: api
          image: <registry>/kervy-backend:v0.1.0
          command: ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
          envFrom:
            - secretRef: { name: kervy-api-secrets }
          ports: [{ containerPort: 8000 }]
          readinessProbe:
            httpGet: { path: /api/v1/health, port: 8000 }
          # No egress needed — deny by default at the NetworkPolicy level.
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kervy-worker
spec:
  replicas: 4
  selector:
    matchLabels: { app: kervy-worker }
  template:
    metadata:
      labels: { app: kervy-worker }
    spec:
      containers:
        - name: worker
          image: <registry>/kervy-worker:v0.1.0
          command: ["celery", "-A", "app.workers.celery_app.celery_app", "worker", "--loglevel=info"]
          envFrom:
            - secretRef: { name: kervy-worker-secrets }  # includes target credential vars
          volumeMounts:
            - { name: evidence, mountPath: /evidence }
      volumes:
        - name: evidence
          persistentVolumeClaim: { claimName: kervy-evidence-nfs }
          # backed by EFS/Filestore/Azure Files — see "Evidence storage" above
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kervy-beat
spec:
  replicas: 1   # never more — two live Beats both fire the same schedule
  selector:
    matchLabels: { app: kervy-beat }
  template:
    metadata:
      labels: { app: kervy-beat }
    spec:
      containers:
        - name: beat
          image: <registry>/kervy-worker:v0.1.0   # same image as the worker
          command: ["celery", "-A", "app.workers.celery_app", "beat", "--loglevel=info"]
          envFrom:
            - secretRef: { name: kervy-worker-secrets }
          # No volumeMounts, no lab network, no queue-depth ScaledObject: it
          # never reaches a target and never writes evidence.
---
# KEDA-style illustration: scale the worker pool on Celery queue depth,
# not CPU. Any queue-depth-aware autoscaler (a custom HPA external metric,
# a cloud provider's own scaler) achieves the same intent.
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: kervy-worker-scaler
spec:
  scaleTargetRef: { name: kervy-worker }
  minReplicaCount: 2
  maxReplicaCount: 20
  triggers:
    - type: redis
      metadata:
        address: <redis-host>:6379
        listName: celery
        listLength: "5"   # target: ~5 queued tasks per replica before scaling out
```

If you'd rather stay off Kubernetes: ECS Fargate (task definitions mapping
1:1 to these same six containers — `beat` as its own service pinned to
`desiredCount: 1`, never behind the worker's autoscaling policy — an
autoscaling policy on the worker service driven by a custom CloudWatch metric
fed from queue depth) or a
plain autoscaling group of VMs running the containers under systemd both
work with no architectural change — the components and their scaling
signals are the same regardless of orchestrator.

## Secrets, at cloud scale

`docs/configuration.md`'s credentials-by-reference model — the database
stores an environment variable **name**, never a value, and the process
that makes the request (the worker, for target credentials) is the one
that must have the variable — maps directly onto a cloud secrets manager:

- Put the actual values in AWS Secrets Manager, GCP Secret Manager, or
  equivalent, and inject them into the worker's environment via the
  orchestrator's native secret-mounting (a Kubernetes `Secret` backed by
  the External Secrets Operator, ECS's `secrets` task-definition field,
  etc.) rather than baking them into the image or a plain env file.
- Grant the worker's own identity (IRSA on EKS, Workload Identity on GKE,
  a task role on ECS) read access to exactly the secrets it needs — this
  is the cloud-native equivalent of the "the process that makes the
  request is the one that must have the variable" rule, extended to *who
  is allowed to grant that variable* as well.
- `JWT_SECRET`, `KERVY_RATE_LIMIT_PEPPER`, `KERVY_CSRF_SECRET`, and
  `KERVY_EVIDENCE_ENCRYPTION_KEY` are platform secrets, not per-target
  credentials — they belong in the API's and worker's secret store
  alongside `DATABASE_URL` and `REDIS_URL`, rotated independently of any
  customer's target credentials.

## CI/CD and release path

`.github/workflows/release.yml` already does the release-integrity half of
this: on a `v*.*.*` tag, it re-runs the full suite and security scanners
against the tagged commit, then signs artifacts with Sigstore (keyless) and
attests SLSA provenance (`docs/releasing.md`). A cloud deploy pipeline adds
one stage after that: build and push the three images
(`Dockerfile.backend`, `Dockerfile.worker`, `Dockerfile.frontend`) to your
registry, tagged with the same release tag, then apply your orchestrator's
update (a `kubectl set image` / Helm upgrade / ECS service update
equivalent) — gated on the release workflow's own success, so a deploy
never ships from a commit that didn't pass CI and didn't get signed.

Verify what you deploy before you deploy it: `docs/releasing.md` has the
Sigstore verification commands. A deploy pipeline that pulls an image by
tag without checking its provenance attestation is trusting the registry,
not the release process.

## Upgrade ordering, unchanged

`docs/deployment.md`'s sequence holds regardless of scale, and matters more
with more replicas in flight: `alembic upgrade head` first, then roll the
API, then roll the worker. Use your orchestrator's rolling-update
primitive (Kubernetes `RollingUpdate` strategy, ECS's deployment
circuit-breaker) for each roll rather than a hard cutover, so in-flight
requests and in-flight runs drain rather than being cut off mid-scan — a
run that loses its worker mid-execution should fail visibly (recorded as
an incomplete run), not silently vanish.

## Multi-tenancy at this scale

The platform is already multi-organization: every table is filtered by
`organization_id`, cross-tenant access returns 404 rather than confirming
another organization's existence, and this is enforced at the database
query level, not the UI (`docs/security-model.md` guarantee #12,
`docs/rbac.md`). That holds at any scale on a single shared database and
does not need re-architecting to add cloud replicas.

What it does **not** provide, stated rather than implied: per-tenant
database isolation (separate schema or database per organization), a
per-tenant evidence-encryption key (one static
`KERVY_EVIDENCE_ENCRYPTION_KEY` for the whole deployment —
`docs/roadmap.md`), and per-tenant resource quotas beyond each target's own
rules-of-engagement budget. If a customer's contract requires physical
data isolation rather than the row-level isolation this platform enforces,
that is a separate deployment (its own database, its own evidence root,
its own worker pool) rather than a configuration flag on a shared one — the
codebase does not have a "dedicated tenant" mode to turn on.

## Observability

What exists today: structured JSON audit log entries for auth and
membership actions (`docs/security-model.md`), and the rate limiter's
`rate_limit_store_unavailable` error-level log line
(`docs/rate-limiting.md`) as the one place the codebase explicitly asks to
be alerted on. What does not exist: application metrics (request latency,
queue depth as an exported metric rather than something you read from
Redis directly, per-engine scan duration) and distributed tracing. At
cloud scale, put a log-aggregation sink (CloudWatch Logs, Cloud Logging, or
equivalent) in front of every component's stdout — the containers already
log there — and alert on the audit log's own hash-chain verification
failing, on `rate_limit_store_unavailable`, and on Celery queue depth
growing unboundedly (the signal that the worker pool is undersized or
stuck), since those three cover the failure modes this design already
knows how to name. Metrics and tracing beyond that are infrastructure you
add, not something the application emits yet.

## What this page does not give you

Stated the same way `docs/deployment.md` states its own gaps:

- **No tested Helm chart, Terraform module, or Kubernetes manifests** — the
  YAML above is illustrative, not shipped, not exercised against a real
  cluster.
- **No object-storage-backed evidence store exists in the code.** The
  network-filesystem path is the only scale-out option that needs zero
  code changes; object storage is future work, named as such above.
- **No autoscaler ships with the repository.** KEDA/queue-depth scaling is
  described as a pattern, not provided as a configuration file.
- **No multi-region or disaster-recovery design.** "Run more replicas" and
  a managed database's own HA/failover feature are the extent of the
  guidance here, same as `docs/deployment.md`.
- **No load-tested capacity numbers.** Nothing in this document claims a
  specific replica count handles a specific request rate — size by
  measuring your own workload against a staging deployment, not by the
  numbers in the illustrative YAML above.
