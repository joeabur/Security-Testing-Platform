# Installation and quickstart

Two paths: Docker Compose, and running the services directly. The second is
the one **verified end to end in this repository's own environment**, and the
transcript of that verification is at the bottom — including the two steps that
are easy to miss and quietly produce a thin scan.

## Requirements

| | Version | Why |
|---|---|---|
| Python | 3.12 | `tomllib`, `StrEnum`, and the typing syntax the codebase uses |
| PostgreSQL | 16 | JSONB, partial indexes, `Identity()` on the audit chain |
| Redis | 7 | Celery broker and the cross-process kill switch |
| Node | 20 | the Next.js scaffold (optional — the API is usable without it) |

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

The API is then on <http://localhost:8000> (docs at `/docs`), the frontend on
<http://localhost:3000>.

> **Not verified here.** The environment this was built in blocks Docker Hub
> blob downloads at the proxy (HTTP 403 from the registry CDN), so the images
> could not be pulled and `docker compose up --build` has never actually run.
> The compose file and Dockerfiles are written and reviewed but unexercised;
> treat them as unverified until you run them. Everything below *has* run.

The demo lab is a separate profile, deliberately:

```bash
docker compose --profile demo up
```

It attaches to an `internal: true` network with no gateway and publishes no
ports, so it has no route out even if its code tried to take one. It also
refuses to start if any of thirteen AI provider credential variables is set.

## Running the services directly

```bash
# 1. Services
pg_isready || sudo pg_ctlcluster 16 main start
redis-cli ping || redis-server --daemonize yes

createdb -U postgres kervy

# 2. Backend
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

export DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/kervy
export REDIS_URL=redis://localhost:6379/0
export JWT_SECRET=change-me-for-anything-but-local
export EVIDENCE_ROOT=$PWD/var/evidence

alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second shell, the worker. **Export the demo lab's credential variables
here**, not only in the API shell — see the note on credentials below:

```bash
cd backend && source .venv/bin/activate
export DATABASE_URL=... REDIS_URL=... JWT_SECRET=... EVIDENCE_ROOT=...
export KERVY_LAB_ACME_TOKEN=lab-token-acme-user
export KERVY_LAB_GLOBEX_TOKEN=lab-token-globex-user

celery -A app.workers.celery_app.celery_app worker --loglevel=info
```

In a third shell, the lab:

```bash
cd demo-target
LAB_HOST=127.0.0.1 python -m lab.main vulnerable-ai-app --port 8081
```

### Why the worker needs the credential variables

Synthetic account credentials are stored **by environment-variable name**, never
by value (`docs/configuration.md`). The process that resolves a name to a value
is the one that makes the request — the worker. Exporting them only in the API
shell leaves the worker unable to authenticate, so the authorization probes
(BOLA, function-level authz) have no credentials to compare and report nothing.

That is not a bug and not a silent failure — the run still completes and the
report's coverage section says what was not tested — but it is the difference
between a 6-finding scan and a 7-finding one, and it cost a re-run to notice.

## Quickstart against the demo lab

Every call below was executed against the running stack. The full script is
`docs/examples/quickstart.py`.

```bash
# 1. Register, and keep the token. Login and register need a pre-session
# CSRF token first (docs/csrf.md) — a cookie jar file carries it from the
# GET to the POST the way a browser's cookie jar would.
JAR=$(mktemp)
curl -s -c "$JAR" localhost:8000/api/v1/auth/csrf -o /dev/null
CSRF=$(awk -F'\t' '$6 ~ /kervy_csrf_anon$/ {print $7}' "$JAR")
REGISTER_RESPONSE=$(curl -s -b "$JAR" localhost:8000/api/v1/auth/register \
  -H 'content-type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -d '{"email":"you@example.test","full_name":"You","password":"Correct-Horse-Battery-Staple-9"}')  # pragma: allowlist secret
TOKEN=$(echo "$REGISTER_RESPONSE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
rm -f "$JAR"
AUTH="authorization: Bearer $TOKEN"

# 2. An organization
ORG=$(curl -s localhost:8000/api/v1/organizations -H "$AUTH" \
  -H 'content-type: application/json' -d '{"name":"Acme"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

# 3. The lab as a target
TGT=$(curl -s localhost:8000/api/v1/organizations/$ORG/targets -H "$AUTH" \
  -H 'content-type: application/json' \
  -d '{"name":"Demo lab","environment":"test","kind":"llm_app","base_url":"http://127.0.0.1:8081"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
```

**Try to run a scan now.** It is refused with `409`, because no authorization
grant exists. That refusal is the product, not an obstacle:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  localhost:8000/api/v1/organizations/$ORG/runs -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"target_id\":\"$TGT\",\"authorization_confirmed\":true}"
# 409
```

Then the four configuration steps — rules of engagement, an authorization
grant, the adapter, and the attack surface. See
`docs/authorization-and-scope.md` for what each field means; note especially
that `allowed_ip_ranges: ["127.0.0.0/8"]` is a **deliberate opt-in**, because
loopback is blocked by default and the lab lives there.

```bash
BASE=localhost:8000/api/v1/organizations/$ORG/targets/$TGT

curl -s -X PUT $BASE/rules-of-engagement -H "$AUTH" -H 'content-type: application/json' -d '{
  "allowed_domains":["127.0.0.1"],"excluded_domains":[],
  "allowed_ip_ranges":["127.0.0.0/8"],
  "allowed_paths":[],"excluded_paths":[],
  "allowed_methods":["GET","POST"],"forbidden_headers":[],"safe_mode":true,
  "budgets":{"max_requests":600,"max_concurrency":4,"requests_per_second":200.0,
             "max_tokens_sent":200000,"max_tokens_received":200000,
             "max_estimated_cost_usd":5.0,"max_wall_clock_minutes":10}}'

curl -s -X POST $BASE/authorization -H "$AUTH" -H 'content-type: application/json' -d '{
  "authorized_by_name":"A Person","authorized_by_role":"CISO",
  "authorized_by_email":"ciso@example.test","reference":"QUICKSTART",
  "valid_from":"2026-09-20T00:00:00Z","valid_until":"2026-09-27T00:00:00Z"}'

curl -s -X PUT $BASE/adapter -H "$AUTH" -H 'content-type: application/json' \
  -d '{"adapter_kind":"chat_http","adapter_config":{"endpoint":"/api/chat"}}'

# The lab publishes its own OpenAPI document. Uploading it is what gives the
# API probes a surface — without this step a scan finds very little.
curl -s http://127.0.0.1:8081/openapi.json -o /tmp/lab-openapi.json
curl -s -X PUT $BASE/openapi -H "$AUTH" -F 'file=@/tmp/lab-openapi.json;type=application/json'

# Two synthetic accounts, by variable NAME. ord-7001 belongs to globex, so
# reading it with the acme token is the BOLA the lab seeds.
curl -s -X PUT $BASE/accounts/acme_user -H "$AUTH" -H 'content-type: application/json' -d '{
  "label":"acme_user","credential_env_var":"KERVY_LAB_ACME_TOKEN",
  "owned_object_ids":["ord-5001"],"is_privileged":false}'
curl -s -X PUT $BASE/accounts/globex_user -H "$AUTH" -H 'content-type: application/json' -d '{
  "label":"globex_user","credential_env_var":"KERVY_LAB_GLOBEX_TOKEN",
  "owned_object_ids":["ord-7001"],"is_privileged":false}'
```

Now the scan, and the report:

```bash
RUN=$(curl -s -X POST localhost:8000/api/v1/organizations/$ORG/runs -H "$AUTH" \
  -H 'content-type: application/json' \
  -d "{\"target_id\":\"$TGT\",\"authorization_confirmed\":true,\"profile\":\"full\"}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')

# Poll, or watch the SSE stream at .../runs/$RUN/events
curl -s localhost:8000/api/v1/organizations/$ORG/runs/$RUN -H "$AUTH"

curl -s "localhost:8000/api/v1/organizations/$ORG/runs/$RUN/report?report_format=markdown" \
  -H "$AUTH" -o report.md
```

## What the verified run produced

Against the lab, through the real Celery worker and the real scope engine:

```
4  run WITHOUT authorization        409  <- refused, as designed
11 run status                       completed
12 scan results                     10 results, 10 distinct codes
   KERVY-AI-000, KERVY-AI-020, KERVY-AI-900, KERVY-API-002, KERVY-API-010,
   KERVY-API-011, KERVY-API-013, KERVY-API-020, KERVY-API-021, KERVY-API-050
13 findings                         7
14 download report markdown         200  19596 bytes
14 download report sarif            200  19330 bytes
14 download report json             200  18037 bytes
15 evidence chain verify            ok=True
```

The lab's planted AWS key and both static tokens appear in **none** of the three
report formats — checked by grep, not by assumption.

## The web UI

The frontend covers register, log in, and create an organization. Targets, runs,
findings, reports and evidence are API endpoints without pages yet; the
dashboard is Phase 17. Use <http://localhost:8000/docs> or the `kervy-ai` CLI
(`docs/cicd.md`) in the meantime. This is stated here rather than discovered
after installing.

## Troubleshooting

See `docs/troubleshooting.md`. The three most common: a run refused with `409`
(no authorization grant), a run that reports `scope_violation` against the lab
(`allowed_ip_ranges` missing `127.0.0.0/8`), and a scan with suspiciously few
findings (the OpenAPI document was never uploaded, or the worker is missing the
credential variables).
