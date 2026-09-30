# Detection methodology

How a claim in a report is arrived at, and what each kind of claim is worth.

## The measurement

For a probe with an adversarial component, each trial runs the attack prompt and
a **control** prompt. The control is benign but would produce the same
observable if the application simply behaves that way. Both run N times.

```
ASR      = attack successes / attack trials
control  = control successes / control trials
```

Both are reported with a **Wilson score 95% confidence interval**.

### Why Wilson

Trial counts are small (tens, not thousands) and rates cluster near 0 or 1 —
exactly where the normal approximation fails, producing intervals that extend
below 0 or above 1. Wilson is well behaved at the boundaries and does not
require a large-sample assumption the data does not support.

### The decision rule

> A finding is raised only when the **attack's lower bound exceeds the
> control's upper bound**.

If the intervals overlap, the platform cannot distinguish "the attack worked"
from "it does that anyway", and reports nothing. That rule is deliberately
conservative and is the main reason this engine reports less than a
pattern-matching scanner would.

## Stability

| Stability | Criterion | Confidence ceiling |
|---|---|---|
| `deterministic` | reproduced on every trial | none |
| `probabilistic` | reproduced on some trials, ASR + interval attached | none |
| `single_shot` | observed once, not repeated | **MEDIUM** |

The cap on single-shot findings is enforced in the risk model, not left to a
reviewer's judgement.

## Markers, not harmful content

Detection uses a per-run random canary (`KERVY-CANARY-<random>`). A probe
succeeds when the marker appears where it should not. There is no harmful-content
corpus, no jailbreak library, and no rubric to disagree about — see
`docs/ai-security-testing.md`.

## Static findings

SAST, SCA, secrets, IaC, supply-chain and container findings come from tools
whose output is normalized into the same `ScanResult` shape. Two rules apply:

**Every identifier is verified.** A CVE, GHSA, OSV or CWE identifier reaches a
finding only if the tool reported it and it matches the expected shape
(`app/core/appsec/identifiers.py`). An identifier that had to be repaired is one
the tool did not actually report, so it is dropped rather than fixed up. There
are no invented identifiers anywhere in a report.

**A missing tool is a visible gap.** If semgrep, trivy or gitleaks is not
installed, the engine emits `KERVY-APPSEC-000 — not tested` naming the tool,
rather than returning nothing. An empty result set reads as "clean", which is a
very different claim from "not checked".

## Pentest tooling (nmap NSE)

`app/core/pentest/engine.py` runs nmap NSE scripts in the same tiered shape
as everything else in this platform, and assigns confidence by how the
observation was made, not by how bad it would be:

| Tier | Result | Confidence | Why |
|---|---|---|---|
| `vulnerability_scan` | `KERVY-PENTEST-101` | `MEDIUM` | a text match against nmap's own `VULNERABLE` convention, not a database-verified advisory id |
| `validation` | `KERVY-PENTEST-102` | `HIGH` | the script printed output only because an anonymous/default-credential check itself succeeded — directly observed |
| `exploitation`, simulate marker | `KERVY-PENTEST-108` | `DESIGN_REVIEW` | nothing was executed; the marker only names what would be eligible to fire |
| `exploitation`, fired for real | `KERVY-PENTEST-103` | `HIGH` | a live-observed result of a script that actually ran, under a live `ExploitationAuthorization` |

Reaching `max_depth=exploitation` inside an ordinary run never produces
anything above `DESIGN_REVIEW` confidence — the `HIGH`-confidence
exploitation finding only exists after the separate, dual-control fire
described in `docs/scanning.md` and `docs/authorization-and-scope.md`.

## Cross-engine duplicate linking is a human judgment, not a heuristic

Fingerprinting (below) deduplicates one probe's own findings run over run.
It does not, and is not meant to, notice that a SAST hit and a DAST hit
describe the same underlying defect — that comparison would need a
similarity heuristic across engines with different surfaces and evidence
shapes, and inventing one would be exactly the kind of confident-and-wrong
finding this platform refuses elsewhere.

So the link is explicit and human: `POST …/findings/{id}/duplicate`
(`app/core/findings/service.py::link_duplicate`) records that one finding
is a duplicate of another, with a note and who linked it. It is **two-level
only** — a finding that is itself a duplicate cannot become a primary, and a
primary that already has duplicates pointing at it cannot become one — so
there is never a chain to walk, only ever one level of indirection.
`GET …/findings/{id}/duplicates` lists what currently points at a given
finding, `DELETE …/findings/{id}/duplicate` undoes the link, and a report's
own counts exclude linked duplicates by default (`docs/reporting.md`).

## Fingerprints

A finding's identity is computed from the probe id, the normalized surface, and
an evidence signature — **never from response text**, and for static findings
**never from the line number**.

Line numbers drift when unrelated code above changes, so fingerprinting on them
would split one long-lived issue into a new finding on every such commit and
destroy the lifecycle guarantee. Static findings use a normalized code-span
signature instead.

Paths are normalized relative to the workspace root. An earlier version leaked
the checkout directory into the fingerprint, so the same file scanned from two
checkouts produced two findings; there is now a regression test that scans one
file from two directories and asserts a single fingerprint.

## Evidence

Every finding that rests on an observation carries a sealed evidence bundle:

- **Redacted before it is written.** Not after. Secrets are replaced by a digest
  and a masked preview; the bundle refuses to be written if a secret survives.
- **Content-addressed**, so the same observation stored twice is one bundle.
- **Hash-chained**, so tampering with any bundle breaks verification of every
  bundle after it. `…/evidence/verify` re-walks the chain *and* re-hashes the
  files, so replacing a file without updating the chain is caught too.

Some probes establish an authorization or configuration decision where the
response body adds nothing but risk. Those bundles record
`[NOT RETAINED] N byte body` with the reason, rather than storing text that
could contain customer data.

## What a report will not contain

- An identifier the tool did not produce.
- A severity without a generated rationale explaining the score.
- A probabilistic finding without its ASR and interval.
- A framework mapping without the pinned upstream version and retrieval date.
- A claim that a category is clean when it was not tested — untested categories
  are named in the coverage section.

## Verifying the methodology

- `backend/tests/test_determinism_harness.py` — the ASR machinery against a
  deterministic fake provider with known behaviour; the reported numbers must
  match the mathematics exactly.
- `backend/tests/test_findings_and_risk.py` — fingerprint stability, including
  the two-checkout regression.
- `backend/tests/test_evidence.py` — redaction property tests, chain
  verification, and purge.
- `backend/tests/test_appsec_engines.py` — every seeded flaw found in a
  vulnerable fixture, **nothing** reported against a hardened control.
- `backend/tests/test_pentest_engine.py` — tier/confidence gating, including
  the simulate-only split for `exploitation`.
- `backend/tests/test_pentest_exploitation.py` — the three-allowlist fire
  gate and the dual-control approve/reject flow.
- `backend/tests/test_findings_api.py` — the duplicate-link endpoints,
  including the two-level-only rejection cases.
