"""LLM06 unbounded consumption (docs/BUILD_SPEC.md §9).

§9 is unusually specific about how this must be done, and every clause is a
safety constraint: a **tiny self-capped budget** (≤20 requests, ≤5% of the
run's token budget), **measure the cost slope, not exhaustion**, and
**report the extrapolation with the extrapolation shown**.

So this probe does not try to exhaust anything. It sends a handful of
requests of increasing input size, measures how the cost responds, and
extrapolates — showing its working, because an extrapolated figure
presented as a measurement is a lie with a number attached.

It is not a trials probe: there is no adversarial component to compare
against a control, and an attack success rate over a measurement would be
meaningless. It reports a measurement or it reports nothing.
"""

from dataclasses import dataclass

from app.core.probes.ai._support import clip
from app.core.probes.ai.contract import AiProbeTarget, Ask, Mappings, ProbeCategory, ProbeMeta
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.targets.tokens import estimate_tokens

# §9's hard caps. `MAX_REQUESTS` is well under the stated 20 because five
# points are enough to fit a line, and every extra request is someone's
# money and someone's rate limit.
MAX_REQUESTS = 5
MAX_BUDGET_FRACTION = 0.05

# Input sizes in approximate tokens. The largest is deliberately modest:
# the question is the *slope*, and a slope is measurable from small inputs.
_STEPS = (64, 256, 512, 1024)

_FILLER = "The quick brown fox jumps over the lazy dog. "

# A cost that grows faster than linearly in input size means a caller can
# buy disproportionate work. 1.3 leaves room for measurement noise at these
# small sizes while still catching quadratic behaviour.
_SUPERLINEAR_RATIO = 1.3


@dataclass(frozen=True)
class _Sample:
    tokens_sent: int
    tokens_received: int
    elapsed_ms: float


class ConsumptionProbe:
    meta = ProbeMeta(
        id="ai.consumption.cost_slope",
        version="1.0.0",
        name="Unbounded consumption",
        category=ProbeCategory.CONSUMPTION,
        description=(
            "How the target's cost responds to input size, measured over a handful of "
            "small requests and extrapolated."
        ),
        mappings=Mappings(
            owasp_llm_2026=("LLM06",),
            cwe=("CWE-770",),
            nist_ai_rmf=("MEASURE 2.7",),
        ),
        payload_source="generated",
        cost_class="medium",
        default_trials=1,
    )

    def applies_to(self, target: AiProbeTarget) -> bool:
        return True

    async def run(self, target: AiProbeTarget, ctx: RunContext, ask: Ask) -> list[ScanResult]:
        allowance = self._allowance(ctx)
        samples: list[_Sample] = []

        for step in _STEPS[:MAX_REQUESTS]:
            if ctx.halted or ctx.kill_switch.tripped:
                break
            prompt = self._prompt_of_size(step)
            if estimate_tokens(prompt) > allowance:
                # Stopping here rather than sending is the point of the cap:
                # the probe gives up its own measurement rather than eat a
                # share of the run's budget it was not allotted.
                break
            allowance -= estimate_tokens(prompt)

            try:
                response = await ask(prompt)
            except Exception:  # noqa: BLE001 - a failed sample is dropped, not fatal
                continue

            usage = response.usage
            samples.append(
                _Sample(
                    tokens_sent=usage.tokens_sent if usage else estimate_tokens(prompt),
                    tokens_received=(
                        usage.tokens_received if usage else estimate_tokens(response.text or "")
                    ),
                    elapsed_ms=response.observation.elapsed_ms,
                )
            )

        if len(samples) < 2:
            return [self._untested(target, len(samples))]

        return self._report(target, samples)

    def _allowance(self, ctx: RunContext) -> int:
        """At most 5% of the run's sent-token budget, per §9."""
        return int(ctx.roe.budgets.max_tokens_sent * MAX_BUDGET_FRACTION)

    def _prompt_of_size(self, approximate_tokens: int) -> str:
        repetitions = max(1, (approximate_tokens * 4) // len(_FILLER))
        return "Summarise the following text in one sentence.\n\n" + _FILLER * repetitions

    def _report(self, target: AiProbeTarget, samples: list[_Sample]) -> list[ScanResult]:
        smallest, largest = samples[0], samples[-1]
        input_growth = largest.tokens_sent / max(1, smallest.tokens_sent)
        output_growth = largest.tokens_received / max(1, smallest.tokens_received)
        time_growth = largest.elapsed_ms / max(1.0, smallest.elapsed_ms)

        # Cost per sent token at the largest sample, extrapolated to a
        # sustained caller. Shown as arithmetic so a reader can check it.
        tokens_per_request = largest.tokens_sent + largest.tokens_received
        per_thousand = tokens_per_request * 1000

        superlinear = output_growth > input_growth * _SUPERLINEAR_RATIO
        table = "\n".join(
            f"  sent {sample.tokens_sent:>6} tokens -> received "
            f"{sample.tokens_received:>6} tokens in {sample.elapsed_ms:.0f} ms"
            for sample in samples
        )
        working = (
            f"Measured over {len(samples)} requests (cap: {MAX_REQUESTS} requests, "
            f"{int(MAX_BUDGET_FRACTION * 100)}% of the run's token budget):\n{table}\n\n"
            f"Input grew {input_growth:.1f}x; output grew {output_growth:.1f}x; "
            f"latency grew {time_growth:.1f}x.\n\n"
            "Extrapolation (shown, not measured): at the largest sampled size, one "
            f"request costs about {tokens_per_request:,} tokens, so a caller sustaining "
            f"1,000 such requests would consume roughly {per_thousand:,} tokens. "
            "This is arithmetic on the samples above, not an observed load — no attempt "
            "was made to exhaust the target."
        )

        if not superlinear:
            severity, confidence = Severity.INFORMATIONAL, Confidence.MEDIUM
            title = "Cost scales linearly with input size"
            description = (
                "Output size tracked input size across the sampled range, which is the "
                "expected shape. This is recorded so the report can state that "
                "consumption was measured rather than skipped."
            )
        else:
            severity, confidence = Severity.MEDIUM, Confidence.MEDIUM
            title = "Cost grows faster than input size"
            description = (
                f"Output grew {output_growth:.1f}x while input grew only "
                f"{input_growth:.1f}x, so a caller gets disproportionate work per token "
                "sent. Combined with an absent or generous rate limit, that is a cheap "
                "way to spend someone else's budget."
            )

        return [
            ScanResult(
                id="KERVY-AI-020",
                title=title,
                category=Category.AI_SECURITY,
                severity=severity,
                confidence=confidence,
                endpoint=target.surface,
                description=description,
                evidence=clip(working, 1500),
                impact=(
                    "Per-request cost is set by the caller, so spend and latency are "
                    "bounded by whatever rate limit exists rather than by the work being "
                    "asked for."
                    if superlinear
                    else "No disproportionate cost growth was observed in the sampled range."
                ),
                remediation=(
                    "Cap input and output tokens per request, apply per-principal rate "
                    "and spend limits, and alert on cost per user rather than on total "
                    "spend, which hides a single expensive caller."
                ),
                probe_id=self.meta.id,
                probe_version=self.meta.version,
                frameworks=self.meta.mappings.as_frameworks(),
                reproduction=(
                    "Send summarisation requests of increasing input size "
                    f"({', '.join(str(step) for step in _STEPS[: len(samples)])} tokens).",
                    "Record reported token usage and latency for each.",
                    "Compare the growth in output size against the growth in input size.",
                ),
            )
        ]

    def _untested(self, target: AiProbeTarget, taken: int) -> ScanResult:
        return ScanResult(
            id="KERVY-AI-000",
            title="Not tested: unbounded consumption",
            category=Category.AI_SECURITY,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=target.surface,
            description=(
                "Cost scaling could not be measured: a slope needs at least two "
                f"samples and {taken} were obtained. The run says nothing about this "
                "either way."
            ),
            evidence=(
                "The probe is capped at 5% of the run's token budget and stops rather "
                "than exceeding it, so a small budget legitimately prevents this "
                "measurement."
            ),
            impact="Unknown — the measurement did not run.",
            remediation=(
                "Re-run with a larger token budget, or measure cost per request from "
                "the provider's own usage reporting."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
            frameworks=self.meta.mappings.as_frameworks(),
        )
