# API security testing

The API engine tests a target's HTTP surface, derived from an uploaded OpenAPI
document. Without that document the engine has almost no surface to work with —
which is why the quickstart uploads one, and why a scan that skips the step
produces a short result list rather than an error.

## Probes

| Code | What it reports | OWASP API Top 10 |
|---|---|---|
| `KERVY-API-001` | Authenticated endpoint answers unauthenticated requests | API2 |
| `KERVY-API-002` | API served over plaintext HTTP | API8 |
| `KERVY-API-003` | Credentials passed in the URL | API8 |
| `KERVY-API-010` | Security response headers missing | API8 |
| `KERVY-API-011` | Permissive CORS policy | API8 |
| `KERVY-API-012` | Error responses expose internal details | API8 |
| `KERVY-API-013` | Debug endpoint reachable (e.g. `/.env`) | API8 |
| `KERVY-API-020` | No rate limit advertised | API4 |
| `KERVY-API-021` | Oversized page size accepted | API4 |
| `KERVY-API-030` | Request body binds privileged fields | API3 |
| `KERVY-API-031` | Write operation reuses a read schema | API3 |
| `KERVY-API-040` | Invalid input causes a server error | API8 |
| `KERVY-API-041` | Input violating the declared schema is accepted | API8 |
| `KERVY-API-050` | Object readable by an account that does not own it (BOLA) | API1 |
| `KERVY-API-051` | Administrative endpoint reachable by an unprivileged account | API5 |
| `KERVY-API-060` | GraphQL introspection enabled | API8 |
| `KERVY-API-061` | GraphQL query depth/complexity unbounded | API4 |
| `KERVY-API-062` | GraphQL errors expose internal details | API8 |
| `KERVY-API-000` | **Not tested** — a coverage marker, not a finding | — |

## Authorization testing needs synthetic accounts

BOLA (`050`) and function-level authorization (`051`) cannot be tested without
two identities and knowledge of what each owns. That is what a synthetic account
is:

```json
{
  "label": "acme_user",
  "credential_env_var": "KERVY_LAB_ACME_TOKEN",
  "owned_object_ids": ["ord-5001"],
  "is_privileged": false
}
```

`credential_env_var` is the **name** of an environment variable. The credential
is never in the database, and the process that resolves it is the worker. The
probe then asks a simple, checkable question: does `acme_user`'s token retrieve
an object that `globex_user` owns? If yes, that is BOLA, and the evidence is the
exchange that showed it.

Configure accounts and you get authorization coverage. Skip them and the report
says `KERVY-API-000 — not tested`, which is the honest outcome rather than a
silently missing category.

## Analysis mode

Under `safe_mode: true` (the default), mass assignment runs in **analysis
mode**: it reads the declared schemas and reports where a write operation binds
fields a client should not control, without attempting the write. Those findings
carry `DESIGN_REVIEW` confidence, which is a materially different claim from a
confirmed exploit and is rendered as such in every report format.

Turning safe mode off is an explicit rules-of-engagement decision, recorded on
the run.

## What the engine does not do

- **It does not crawl.** The surface comes from the OpenAPI document. A DAST
  crawler is Phase 15.
- **It does not test business logic.** Whether a workflow can be abused in a way
  the spec permits is not something a generic probe can decide.
- **It does not attempt injection payloads against a live database.** Input
  validation probes look for schema violations and error disclosure, not SQLi
  exploitation.
- **It reports missing rate limiting from what is advertised**, not by flooding
  the target. `KERVY-API-020` checks for the absence of rate-limit headers; a
  target that rate-limits without advertising it will be reported and is a false
  positive worth knowing about (`docs/limitations.md`).

## Verifying the engine

`backend/tests/test_api_engine.py` and `test_api_engine_e2e.py` run the probes
against a deliberately vulnerable fixture and a hardened control. The control is
the important half: every probe must report **nothing** against a correctly
written app, or its clean state is unreachable and users learn to ignore it.

`backend/tests/test_lab_e2e.py` runs the whole thing against the real demo lab
over a real socket, and names each seeded flaw individually so a regression says
which one stopped being found.
