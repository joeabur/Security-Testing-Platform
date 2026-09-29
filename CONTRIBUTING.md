# Contributing

## Before anything else

Read `docs/acceptable-use.md`. This is authorized-testing software: a
contribution that makes unauthorized testing easier, or that weakens the
authorization boundary for convenience, will be declined regardless of how well
it is written.

## Setup

See `docs/installation.md` for the full path. The short version:

```bash
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
alembic upgrade head
```

Tests need a real PostgreSQL and Redis — not sqlite, not a mock. The scope
engine, the audit hash chain and the evidence store all depend on database
behaviour that an in-memory substitute does not reproduce.

## The checks that must pass

```bash
make lint        # ruff
make typecheck   # mypy --strict on app and kervy_cli
make test-backend
```

All three, before you open a pull request. `ruff format --check` is part of
lint, so run `ruff format .` rather than arguing with it.

Do not run two pytest sessions at once: they truncate the same test database and
produce failures that have nothing to do with your change.

## Rules that are not negotiable

These are the invariants the project exists to uphold. A pull request that
breaks one will be declined even if every test passes, because the test is then
the thing that is wrong.

1. **The scope engine is the single outbound control point.** No engine, probe,
   adapter, worker, CLI path or plugin constructs an HTTP client. Everything
   goes through `GatedTransport`. A static test enforces this; if your change
   needs an exception, the answer is a new gated context (see
   `app/core/integrations/egress.py`), not a new client.
2. **No flag disables scope enforcement.** Not an environment variable, not a
   config key, not a "development mode".
3. **Credentials are never stored in the database or a YAML file.** Store the
   *name* of an environment variable. That applies to target credentials,
   webhook URLs, SMTP passwords and code-host tokens alike.
4. **Never persist an unredacted secret, even temporarily**, and never log one.
   Redaction happens before the write, not after.
5. **Never invent an identifier.** No CVE, GHSA, CWE or rule ID may appear in a
   finding unless it came from the tool that reported it and passed the
   verification in `app/core/appsec/identifiers.py`.
6. **No weaponized payloads, no harmful-content corpora, no exploit code.** AI
   probes detect using per-run random markers.
7. **The AI layer never executes.** It cannot run a scan, grant authorization,
   or modify a finding's real (non-draft) fields under any configuration.
8. **No fake functionality.** A stub that looks like a feature is worse than a
   missing feature. If something is not built, say so in `docs/roadmap.md` and
   make the code say so too — a "not tested" marker beats silence.

## What a good change looks like

**Tests that can fail.** The habit in this repository is to prove a test has
teeth by deliberately breaking what it guards and watching it fail. Several
tests carry a comment recording that. If you add a control, break it once to
confirm the test catches it, then put it back.

**Comments that explain the decision, not the syntax.** The code says what it
does. A comment should say why it is this way and what the alternative would
have cost. The existing modules are the reference for the level expected.

**Honest deferrals.** If you leave something out, say so in `docs/roadmap.md`
with the reason. That is a normal, welcome contribution — a half-built feature
presented as complete is not.

**Small, complete pull requests.** One concern per branch, with the
documentation and the migration in the same change as the code.

## Commits

Conventional commits: `feat(scope): …`, `fix(reporting): …`, `docs: …`,
`test(vcs): …`. The body should say why, not restate the diff.

## Migrations

```bash
alembic revision -m "what it does"
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
```

Both directions must work. Two specifics that have bitten before: a Postgres
ENUM must be created explicitly before `add_column` uses it and dropped in the
downgrade, and adding a NOT NULL column to a populated table needs a
`server_default` followed by `alter_column(server_default=None)`.

## Adding a probe or an engine

Probes and engines are explicitly registered — `app/core/probes/registry.py`,
`app/core/appsec/registry.py`. Something not listed there does not run, which is
deliberate. New detection needs a fixture that proves it fires, and a hardened
control fixture that proves it does not fire spuriously.

For third-party tools, prefer a plugin: `docs/plugin-development.md`.

## Licence

Apache-2.0. By contributing you agree your contribution is licensed under it.
The patent grant is why (`docs/decisions/0004-licence.md`).
