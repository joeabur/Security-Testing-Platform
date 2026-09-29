# ADR 0003: Product name was "Aegis AI Security" (`aegis-ai-security`); superseded

## Status

Superseded by [ADR 0006](0006-rebrand-kervy.md) — the product is now named
"Kervy Security". This record is kept as written at the time for the same
reason migrations are never edited after they run: it documents a decision
that was genuinely made, under a name that was genuinely chosen then,
and rewriting it to read as though "Kervy" were always the answer would
misstate what the namespace check below was actually evaluating.

## Context

The v2.0 spec explicitly warned that `aegis` is heavily used already (Aegis
Authenticator, several existing security products, PyPI squatting) and asked
for a PyPI/npm/GitHub/trademark check before committing to a name, suggesting
the placeholder be kept as a single constant so a rename stays a one-commit
change. The Master Build Prompt names the product outright: "Aegis AI
Security", repository `aegis-ai-security`.

## Decision

Adopt "Aegis AI Security" as the product name and `aegis-ai-security` as the
repository name, as specified by the Master Build Prompt. The CLI binary is
named `aegis-ai` (not bare `aegis`) specifically to reduce collision risk
with the existing `aegis` PyPI/npm namespace noted in the v2.0 spec.

The product name and package/binary names are kept as single named constants
(`PRODUCT_NAME` in shared config, the `pyproject.toml` package name, the CLI
entry-point name, the frontend's site title) rather than scattered string
literals, so that if the still-owed PyPI/npm/GitHub/trademark search turns up
a genuine conflict, the rename is a one-commit change as the v2.0 spec
required.

**That is what happened**: ADR 0006 records the actual rename, carried out
by the same "single constant, not scattered literals" discipline this
paragraph asked for up front.

## Follow-up (not blocking Phase 1)

Superseded — see ADR 0006. The namespace/trademark check below was never
completed for "Aegis"; whether it is still owed for "Kervy" is ADR 0006's
own open question, not this one's.

- ~~PyPI: package name availability for `aegis-ai` / `aegis-ai-security`~~
- ~~npm: package name availability (frontend tooling, any published CLI wrapper)~~
- ~~GitHub: organization/repo name collision check~~
- ~~A basic trademark search for "Aegis AI Security" in the security-tooling space~~
