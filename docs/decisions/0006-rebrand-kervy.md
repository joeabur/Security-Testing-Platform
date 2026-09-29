# ADR 0006: Rebrand from "Aegis AI Security" to "Kervy Security"

## Status

Accepted, with a known follow-up (unchanged from ADR 0003: the PyPI/npm/
GitHub/trademark namespace check was never run for "Aegis" and has not
been run for "Kervy" either).

## Context

The product name was changed by explicit user instruction on 2026-09-29,
in the working session recorded at
`docs/roadmap.md`'s "Rebrand — Aegis AI Security → Kervy Security" entry.
ADR 0003 had already anticipated exactly this: it asked for the product
name and package/binary names to be kept as single named constants rather
than scattered string literals, specifically "so that ... the rename is a
one-commit change". That discipline is what made this rename mechanical
rather than a redesign — a text substitution across the codebase plus one
new Postgres migration, not a re-architecture.

## Decision

Adopt "Kervy Security" as the product name and `kervy-security` as the
repository slug (the package names in `backend/pyproject.toml` and
`frontend/package.json` are `kervy-security-backend`/
`kervy-security-frontend`). The CLI binaries are `kervy-ai`/`kervy-mcp`,
matching ADR 0003's own "not the bare product name, to reduce collision
risk" reasoning.

Every place the old name appeared was renamed, not only branding text: the
full list is in `docs/roadmap.md`'s rebrand entry (env vars, HTTP headers,
cookie names, Redis key prefixes, finding/probe-ID codes, Celery names,
directory/package names, and the Postgres RLS session variable, the last
of which needed a dedicated migration rather than a text edit — see that
entry for why). This ADR records the decision and its scope; the roadmap
entry records the mechanics and what was verified.

**Historical documents are not retold.** ADR 0003, `CHANGELOG.md`'s
released `[0.1.0]` section's narrative prose, and every already-applied
Alembic migration keep describing what genuinely happened under the name
that was genuinely in use at the time, per this project's own "a migration
is a record of what ran, not a place to retell it" discipline — applied
here to decision records and changelog narrative too, not only to SQL.
Where a stale name would leave a reader unable to actually *use* the
documented thing (a CLI command, an env var), that literal reference was
updated instead of left to bit-rot; see the roadmap entry for the exact
line between "historical narrative, left alone" and "a reference someone
still needs to work, updated".

## Follow-up (not blocking anything already shipped)

Same three checks ADR 0003 left open, now against the new name:

- PyPI: package name availability for `kervy-ai` / `kervy-security`
- npm: package name availability (frontend tooling, any published CLI
  wrapper)
- GitHub: organization/repo name collision check, and — separately from
  a namespace check — whether the hosted repository itself should be
  renamed; not done as part of this ADR, since that changes the clone URL
  and is a higher-stakes action than a codebase-content rename
- A basic trademark search for "Kervy Security" in the security-tooling
  space

Record the outcome here or in a follow-up ADR before tagging a public
release.
