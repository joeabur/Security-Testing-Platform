# Reporting

## Formats

| Format | Use |
|---|---|
| `markdown` | reading, pasting into a ticket |
| `html` | sharing; self-contained, no external assets |
| `pdf` | attaching to an engagement report (WeasyPrint) |
| `json` | programmatic consumption; canonical, stable key order |
| `sarif` | code hosts and IDEs; **SARIF 2.1.0**, validated against the OASIS schema |
| `csv` | spreadsheets and bulk triage |

Every format renders from the same stored findings and evidence. The golden
snapshots in `backend/tests/golden/` pin each one, so a change to a renderer
shows up as a diff in review rather than as a surprise in someone's report.

## Audiences

Four templates, because the same findings answer different questions:

| Template | Answers |
|---|---|
| `executive` | what is the risk, what should we do, what did we not check |
| `technical` | what was found, where, with what evidence and reproduction |
| `developer` | what do I change, in which file or endpoint, and why |
| `compliance` | which framework controls are covered, and which are not |

## What every finding carries

- A **severity rationale**, generated from the score's inputs — no bare severity.
- **Mapping versions** with retrieval dates for every framework reference.
- An **evidence hash** and, where one exists, a reference to the sealed bundle.
- **Reproduction steps**, built from what the probe actually sent, never from a
  template.
- For probabilistic findings, the **attack success rate and its interval**.

## Duplicates

A finding a human has explicitly linked as a duplicate of another
(`POST …/findings/{id}/duplicate`, see `docs/detection-methodology.md` for
the mechanism and its two-level-only limit) is excluded from a report's
counts and its findings-by-severity section by default — recording the link
is what stops the same underlying defect from being counted twice just
because two different engines found it. `GET
…/organizations/{id}/findings?include_duplicates=true` is the escape hatch
for an audience that needs to see everything, including what was folded in.

## The coverage section

Every report names the framework categories that were **not** tested, and why —
no adapter, no synthetic accounts, no OpenAPI document, a missing tool. This is
the section that makes the rest of the report trustworthy: a report that lists
five findings and says nothing about coverage invites the reader to assume the
other categories are clean.

Findings with no measurement print an explicit "not measured" line rather than
an empty space.

## Redaction

Evidence is redacted **before** it is written, so a report renders from data
that never contained the secret. The verification is not theoretical: the
quickstart run's three report formats were grepped for the demo lab's planted
AWS key and both static tokens, and contained none of them.

## Access control

Downloading a report is **viewer**. Downloading an evidence bundle is
**analyst** — a bundle contains far more raw material than a report.

There are **no public report URLs by default.** Reports are served through the
authenticated API, not from object storage with a signed link. Evidence lives on
a filesystem path (`EVIDENCE_ROOT`), not behind a URL.

Every download is audited.

## Evidence verification

```
GET …/runs/{id}/evidence          → the manifest
GET …/runs/{id}/evidence/verify   → re-walks the chain AND re-hashes the files
```

Re-hashing matters: a check that only walked the chain would pass after someone
replaced a bundle's contents without touching the manifest. `kervy-ai evidence
verify` exits non-zero on a broken chain, because evidence that cannot be
trusted makes the report that rests on it worthless.
