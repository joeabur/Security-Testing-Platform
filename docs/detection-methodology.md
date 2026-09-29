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
