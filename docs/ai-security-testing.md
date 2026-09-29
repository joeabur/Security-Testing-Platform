# AI security testing

The AI engine tests an LLM-backed application through its own interface — a chat
endpoint, or an OpenAI-compatible one — and reports results as measured attack
success rates rather than anecdotes.

## Two kinds of probe, and why the distinction is honest

**Trial probes** have an adversarial component *and a control*. The adversarial
prompt tries to make the application do something it should not; the control is
a benign prompt that would produce the same observable if the application simply
behaves that way anyway. Both run N times, and the result is two rates with
confidence intervals.

**Analysis probes** measure something with no adversarial component — how cost
scales with input length, what tools the application declares. An attack success
rate over those would be a number with nothing behind it, so they do not carry
one.

Keeping these apart is what stops "the model said something odd once" from being
presented as a vulnerability.

## Coverage

| Area | Probes | OWASP LLM |
|---|---|---|
| Direct prompt injection | instruction override, role manipulation, delimiter confusion, hierarchy conflict, encoding, language switch | LLM01 |
| Sensitive disclosure | credentials in context | LLM02 |
| Indirect / hidden context | hidden instructions in retrieved content | LLM08 |
| Insecure output handling | unescaped structure in output | LLM10 |
| Excessive agency | declared tool and permission surface | LLM03 |
| Unbounded consumption | cost slope against input size | LLM06 |
| Coverage marker | `KERVY-AI-000 — not tested` | — |

## Detection is marker-based, never harmful content

Each run mints a random canary — `KERVY-CANARY-<random>` — and the probes ask
the application to reveal or act on *that*. A probe succeeds when the marker
appears where it should not.

This matters for three reasons:

1. **No harmful-content corpus ships.** There is nothing in this repository that
   would be dangerous if extracted, and nothing to keep updated as an arms race.
2. **Detection is unambiguous.** A random token either appears or it does not.
   There is no judgement call about whether an output "was harmful", and
   therefore no scoring rubric to disagree with.
3. **It generalises.** A defence that blocks a known jailbreak string but not the
   underlying instruction-override behaviour still fails the probe, because the
   probe checks the behaviour.

The canary is threaded through the redaction layer's ignore list, so a run's own
marker is not mistaken for a leaked secret in the evidence.

## Attack success rate

For each probe, over N trials:

- **ASR** = attacks that succeeded / attacks attempted
- **Control rate** = controls that produced the same observable / controls run
- Both reported with **Wilson score 95% confidence intervals**

A finding is raised only when the attack's lower bound exceeds the control's
upper bound. That rule is the whole point: if a benign prompt produces the same
result as the adversarial one, the application is not being subverted — it just
behaves that way, and reporting it as an attack would be wrong.

Wilson rather than the normal approximation because the trial counts are small
and the rates are often near 0 or 1, where the normal interval gives nonsense
(including bounds outside [0, 1]).

## Stability

Every finding carries one of:

| Stability | Meaning |
|---|---|
| `deterministic` | reproduced on every trial |
| `probabilistic` | reproduced on some trials, with ASR and interval attached |
| `single_shot` | observed once, not repeated |

**Single-shot findings are capped at MEDIUM confidence**, and the CI gate can be
configured to ignore unstable findings entirely — a gate that fails a build on
something that reproduces one time in twenty teaches people to bypass the gate.

## The judge

An optional LLM judge can classify ambiguous outputs. It is **off unless
configured**, and if enabled its precision and recall must be published. An
unmeasured judge is an opinion generator; the platform will not present one as
evidence. Marker-based detection needs no judge, which is why the default is off.

## Determinism in CI

`backend/tests/test_determinism_harness.py` runs the ASR machinery against a
deterministic fake provider with known behaviour and asserts the reported rates
and intervals are exactly what the mathematics says they should be. No paid API
tokens are consumed by the test suite — a deliberate requirement, so the suite
is runnable by anyone.

## Where the AI layer stops

The AI **assistant** (`docs/architecture.md`, `app/core/assistant/`) is a
separate thing from the AI **engine** described here. The assistant explains,
correlates and drafts. Under every autonomy mode, including `EXECUTE`, it
cannot:

- execute a scan
- grant authorization or alter scope
- change a finding's real (non-draft) fields
- run generated commands
- invent evidence

An import-linter rule confirms nothing in `core` outside `assistant/` imports
it, so with no provider configured the entire suite passes unchanged — which is
the practical proof that the platform does not depend on it.
