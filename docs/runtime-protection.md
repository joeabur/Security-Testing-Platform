# Runtime protection

Kervy records what an operator **claims** protects a target. It does not
measure any of it, and it never will run inside a customer's process.

## Why there is no engine

`docs/BUILD_SPEC.md` §4.5 row 6 settles a conflict between two source
documents. One specifies a full RASP-effectiveness engine; the other says do
not implement RASP and do not let it complicate the architecture. The later,
more restrictive document wins, so Phase 18 ships **extension points only**.

Neither document permits shipping a RASP *agent*, and this one does not either.
A RASP agent is code that loads into a running application and instruments it.
Shipping one would mean asking an operator to execute this project's code inside
their production process — which is the thing §2 forbids outright, and which no
configuration flag makes safe.

So there is no agent, no bootstrap, no `sitecustomize`, no import hook, no
monkey-patch and no instrumentation of any kind.
`backend/tests/test_rasp.py` scans every Python file under `app/` for the ways
an agent gets into a process and fails on any of them. It reads the parsed
source with docstrings removed, because the first version matched the docstring
that explains this rule — a control that fires on its own documentation is a
control somebody deletes.

## What you can declare

```bash
curl -X PUT "$KERVY/organizations/$ORG/targets/$TARGET/runtime-protection" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "controls": [
          {"kind": "waf", "vendor": "Example WAF"},
          {"kind": "prompt_firewall", "telemetry_env_var": "KERVY_WAF_TOKEN"}
        ]
      }'
```

Kinds: `waf`, `rasp_agent`, `input_validation_middleware`, `output_filter`,
`prompt_firewall`, `rate_limiter`, `anomaly_detection`, `other`. A closed set,
so an engine could eventually act on it; `other` exists so an unusual control
is recorded under a name rather than dropped.

Admin only — a declaration here changes how this target's findings read, so
somebody accountable should make it.

`telemetry_env_var` is a variable **name**, validated as one. A URL or a token
pasted there is rejected at the edge, because a secret in a database row is a
secret in every backup, log and support ticket taken afterwards. It is the same
rule every credential on this platform follows.

## A claim is never stored as a measurement

Every control carries an `evidenced` field, and it is a required part of the
record rather than a convention:

| Value | Meaning | Can anything produce it today? |
|---|---|---|
| `claimed` | An operator said so | Yes — this is all the API can write |
| `observed` | An engine saw behaviour consistent with the control | No |
| `not_observed` | An engine tested and did not find it | No |

`ClaimedControl.__post_init__` **raises** if anything tries to construct a
control marked `observed` or `not_observed`, because nothing on this platform
has measured anything and a record that said otherwise would carry that lie
forever. A future engine relaxes this deliberately, together with the test that
asserts it. The API has no `evidenced` input field at all.

## Declaring controls produces a "not tested" line

§14 requires a report to say what it did not cover. A target that declares a
WAF and gets a clean assessment must not read as a WAF that held, so every run
against a target with a declaration emits:

> **Not tested: claimed runtime protection** — This target declares runtime
> protection (waf). This assessment did not measure any of it. No
> runtime-protection engine exists on this platform: the declaration is what an
> operator stated, not something observed.

Impact is stated as *Unknown*, which is the honest impact of a measurement that
did not happen. A test asserts the marker contains no claim-shaped phrase
("is effective", "verified", "protected against", "mitigated") and does
positively say "did not measure".

## What an engine would plug into

`app/core/rasp/contract.py` defines `RuntimeProtectionEngine`: two methods,
matching the AppSec engine contract so the registry, the normalizer and the
report need no new concept.

```python
class RuntimeProtectionEngine(Protocol):
    id: str
    version: str

    def applies_to(self, context: RuntimeProtectionContext) -> bool: ...
    async def run(self, context: RuntimeProtectionContext) -> list[ScanResult]: ...
```

Two properties make the §26 Phase 18 acceptance criterion true rather than
aspirational, and both are asserted:

**No unsafe-mode path.** `RuntimeProtectionContext` has no field that could
relax a control — no `safe_mode`, `force`, `allow_*`, `bypass_*` or
`disable_*` — and the protocol's methods take the context and nothing else, so
an engine cannot be handed its own transport. Measuring whether a WAF blocks
something sounds like it needs an escape hatch; it does not. It needs the
engagement to authorize the request, which the rules of engagement already
decide. A test walks the dataclass fields and the method signatures.

**No dependency on the orchestrator or the scope engine.** The contract imports
neither, so adding an engine does not mean editing them. Checked by parsing the
module's imports rather than grepping its text, since the docstring discusses
both at length.

`RUNTIME_PROTECTION_ENGINES` is an empty tuple, and a separate test reads every
class under `app/` to confirm none would satisfy the protocol — an unregistered
engine would still be a shipped engine.

## If you want to know whether a control works

Test with it disabled, in a non-production environment, under its own
authorization, and compare. That is a real experiment with a real control
group, and it is what the remediation text on the marker says. It is not
something a scanner can infer from the outside, and this platform does not
pretend otherwise.
