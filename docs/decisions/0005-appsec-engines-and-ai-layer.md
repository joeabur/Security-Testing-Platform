# 0005 — Reconciling the AppSec Addendum and the Implementation Specification

**Status:** Accepted
**Date:** 2026-09-18
**Supersedes:** nothing. Extends 0001 (storage & product shape), 0002 (task queue), 0003 (naming).

## Context

Two further specifications arrived after Phases 1–6 had shipped:

1. **AppSec Addendum v2.1** — adds SAST, DAST, SCA, standalone secret
   detection and a RASP-effectiveness engine, plus an AI-assistant layer.
   Written against "v2.0" numbering and explicitly additive.
2. **Implementation Specification** — reframes the product as an *AI-powered
   Application Security Automation Platform*, imposes a simplicity
   constraint on the stack, names SAST/SCA/Secrets/IaC as the MVP engine
   set, and makes AI a first-class platform layer rather than a scanner.

They agree with each other and with v3.0 on the things that matter most —
the scope engine is the single outbound control point, evidence is redacted
before persistence, AI output is never evidence, nothing bypasses
authorization. They disagree on stack choices, phase numbering, engine
priority, and how far the AI layer may act.

Both later documents instruct: inspect the repository first, reuse what
works, do not rebuild functioning components, and identify conflicts before
implementing. This ADR is that identification step.

## Decision

The full resolution table lives in `docs/BUILD_SPEC.md` §4.5. The three
decisions that a reader is most likely to question:

### Keep PostgreSQL, Redis and Celery despite the simplicity constraint

The Implementation Specification lists these among things not to introduce
"unless a demonstrated requirement in the existing codebase makes them
necessary". That clause is already satisfied, and the requirements are
tested rather than assumed:

- **Postgres** — multi-tenant isolation, JSON and ENUM columns, and the
  hash-chained audit log. 276 tests run against it.
- **Redis** — cross-process run cancellation. A cancel issued in the API
  process must stop a run already executing in a worker; `tests/test_runs_api.py`
  covers exactly that path.
- **Celery** — runs execute outside the request cycle and stream real
  progress. Two bugs found in Phase 4 (unregistered task, event-loop reuse)
  were only exposed by running a real worker.

Replacing them with SQLite and in-process asyncio would delete six phases of
tested behaviour to satisfy a constraint whose own escape clause is met. A
single-process "local profile" is worth having and is tracked as a later
simplification; it is not a reason to rewrite working infrastructure now.

### Replace the Next.js frontend with Jinja2 + HTMX

This is the one stack conflict where the later document plainly wins, and
the reasoning is the mirror image of the one above: there is no working
component to preserve. The Next.js app is a thin auth-only scaffold — login,
register, create-organization — with no dashboard built on it. The REST API
it calls is unchanged, so the dashboard is rewritten, not the platform.
Keeping Next.js would mean carrying a second toolchain, a second dependency
tree and a second CI job for a surface that has not been built yet.

### The AI layer gets an autonomy ladder, but `EXECUTE` never reaches a target

The Addendum forbids the assistant from executing anything; the
Implementation Specification lists `EXECUTE` among its autonomy modes. These
reconcile cleanly once the question is "execute *what*":

- `EXECUTE` may produce artifacts — a report, a summary, a draft.
- Anything that would consume budget, send a request to a target, grant or
  extend authorization, or change a finding's real fields stays at
  `APPROVAL_REQUIRED` or above, whatever the configured mode.

This is not a compromise between the documents so much as a reading of both:
§2 and §6 outrank every later document, and both later documents say so
themselves.

## Consequences

- Phases 1–13 keep their numbers. New work is Phases 14–18, so no shipped
  commit message, roadmap entry or ADR reference becomes wrong.
- RASP is reduced from an engine to an interface, per the later document.
  The `runtime_protection` fields stay in the domain model so the engine can
  be added without a rewrite.
- The secret detectors written in Phase 6 are reused by the standalone
  secrets engine rather than reimplemented. Two implementations would mean
  two redaction policies, which is how the "never persist a secret"
  invariant gets broken.
- The CLI is `kervy`, with `kervy-ai` as an alias, superseding ADR 0003's
  command name (the *project* name is unchanged).
- The platform must work with no AI provider configured. That is a testable
  property, not an aspiration: the existing suite has to keep passing with
  the AI layer absent.
