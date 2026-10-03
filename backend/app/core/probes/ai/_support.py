"""Shared helpers for the AI probes."""

from app.core.measure.asr import Stability
from app.core.probes.ai.contract import ProbeMeta, ProbeOutcome
from app.core.probes.models import Category, Confidence, ScanResult, Severity

MAX_EVIDENCE_CHARS = 800


def clip(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "… (truncated)"


def confidence_for(outcome: ProbeOutcome) -> Confidence:
    """§7.4 and §11: a single-shot result is capped at medium confidence.

    A deterministic result — every trial succeeded, no control did — is the
    only thing that earns high confidence here.
    """
    if outcome.measurement.stability is Stability.SINGLE_SHOT:
        return Confidence.MEDIUM
    if outcome.measurement.stability is Stability.DETERMINISTIC:
        return Confidence.HIGH
    return Confidence.MEDIUM


def measurement_evidence(outcome: ProbeOutcome) -> str:
    """Evidence that always carries the numbers behind the verdict.

    §7.1 requires the rate, the interval and the control to be visible
    wherever the finding is, so a reader can see how strong the claim is
    instead of taking "vulnerable" on trust.
    """
    attack = outcome.measurement.attack
    control = outcome.measurement.control
    lines = [
        f"Attack success rate: {attack.successes}/{attack.trials} = {attack.rate:.0%} "
        f"(95% CI {attack.lower:.2f}–{attack.upper:.2f})",
        f"Control success rate: {control.successes}/{control.trials} = {control.rate:.0%} "
        f"(95% CI {control.lower:.2f}–{control.upper:.2f})",
        f"Stability: {outcome.measurement.stability.value}",
        f"Decision rule: {outcome.measurement.rule}",
    ]

    success = outcome.first_success()
    if success is not None:
        lines += [
            "",
            f"First successful attempt ({success.attempt_id}):",
            f"  sent:     {clip(success.prompt, 400)}",
            f"  returned: {clip(success.response_text, 400)}",
            f"  detected: {success.reason}",
        ]
    return "\n".join(lines)


def strongest_attempt(per_attempt: dict[str, tuple[int, int]]) -> tuple[str | None, int, int]:
    """The attempt with the most successes; ties go to the one that spent
    fewer trials, so a cheaper technique wins an otherwise equal contest.

    Shared between the single-shot driver and the multi-turn runner: a probe
    offering several framings of one idea should be measured by the
    strongest of them, not their average, in either case.
    """
    if not per_attempt:
        return (None, 0, 0)
    best_id = max(
        per_attempt,
        key=lambda attempt_id: (per_attempt[attempt_id][0], -per_attempt[attempt_id][1]),
    )
    successes, trials = per_attempt[best_id]
    return (best_id, successes, trials)


def scan_result(
    *,
    meta: ProbeMeta,
    result_code: str,
    title: str,
    severity: Severity,
    surface: str,
    description: str,
    impact: str,
    remediation: str,
    outcome: ProbeOutcome,
    reproduction: tuple[str, ...],
    confidence: Confidence | None = None,
) -> ScanResult:
    return ScanResult(
        id=result_code,
        title=title,
        category=Category.AI_SECURITY,
        severity=severity,
        confidence=confidence or confidence_for(outcome),
        endpoint=surface,
        description=description,
        evidence=measurement_evidence(outcome),
        impact=impact,
        remediation=remediation,
        probe_id=meta.id,
        probe_version=meta.version,
        frameworks=meta.mappings.as_frameworks(),
        reproduction=reproduction,
        # Carried structurally as well as in the evidence prose: the risk
        # model scores likelihood from the interval's lower bound, and
        # re-parsing that out of a sentence would be a second place for the
        # number to be wrong.
        measurement=outcome.measurement.as_dict(),
        stability=outcome.measurement.stability.value,
    )
