"""Runs a `MultiTurnProbe`'s plan as repeated conversations and measures the
result, the multi-turn analogue of `app.core.probes.ai.driver`.

Reuses `app.core.measure.asr.measure()` unchanged: a "trial" there is just
an integer success/failure count, agnostic to whether what produced it was
one request or a five-turn conversation. One full run of a
`ConversationScript` — however many turns it takes — is one trial. Running
the same script `N` times (the probe's `default_trials`) is what produces
the attack and control rates `measure()` compares, exactly as the single-
shot driver runs the same `Attempt` `N` times.
"""

from dataclasses import dataclass, replace

from app.core.evidence.bundle import EvidenceBundle, build_bundle
from app.core.measure.asr import DEFAULT_RULE, Measurement, measure
from app.core.probes.ai._support import strongest_attempt
from app.core.probes.ai.contract import AiProbeTarget, Ask, ProbeOutcome, TrialRecord, new_canary
from app.core.probes.ai.multiturn.contract import (
    ConversationScript,
    ConversationTurn,
    MultiTurnProbe,
)
from app.core.probes.models import ScanResult, Severity
from app.core.redaction.secrets import redact
from app.core.scope.context import RunContext

# Mirrors `driver.TrialBudget`/`MAX_TRIALS`: a probe that chains several
# turns per trial must not be allowed to multiply that cost unboundedly.
MAX_TRIALS = 20
MAX_RESPONSE_CHARS = 2000
# A script with more turns than this is a configuration error, not a probe
# that is merely expensive: no shipped script comes close, and a run-time
# ceiling here keeps one misbehaving probe from turning a bounded trial
# budget into an unbounded number of requests.
MAX_TURNS_PER_SCRIPT = 10


@dataclass(frozen=True)
class TrialBudget:
    """Bounds on how many full conversations one probe may run."""

    trials: int = 5

    def resolve(self, requested: int | None) -> int:
        return max(1, min(requested or self.trials, MAX_TRIALS))


def _render_transcript(turns: tuple[ConversationTurn, ...]) -> str:
    """A readable multi-line rendering of the turns sent so far, replayed as
    the context for the next prompt.

    This is the mechanism named in `contract.py`'s module docstring: because
    `Ask` carries no session, the conversation is reconstructed in text and
    resent. Each turn is labelled so the target (and a reader of the
    evidence) can tell prior turns from the new instruction."""
    if not turns:
        return ""
    lines = []
    for turn in turns:
        lines.append(f"[Turn {turn.turn_index}] {turn.prompt}")
        lines.append(f"[Response {turn.turn_index}] {turn.response_text}")
    return "\n".join(lines)


def _compose_prompt(turns: tuple[ConversationTurn, ...], next_template: str, canary: str) -> str:
    rendered_next = next_template.format(canary=canary)
    if not turns:
        return rendered_next
    return (
        "Here is our conversation so far:\n"
        f"{_render_transcript(turns)}\n\n"
        f"Now continue the conversation. [Turn {len(turns) + 1}] {rendered_next}"
    )


async def _run_conversation(
    probe: MultiTurnProbe,
    script: ConversationScript,
    ctx: RunContext,
    ask: Ask,
    canary: str,
) -> tuple[bool, tuple[ConversationTurn, ...]] | None:
    """Run one full pass of `script`. Returns `None` if the run was halted or
    the target raised before a single turn completed — never counted as
    either a success or a performed trial, the same "an unanswered trial is
    not a success" rule `driver._run_set` applies."""
    turns: list[ConversationTurn] = []
    templates = script.turns[:MAX_TURNS_PER_SCRIPT]

    for template in templates:
        if ctx.halted or ctx.kill_switch.tripped:
            break

        prompt = _compose_prompt(tuple(turns), template, canary)
        try:
            response = await ask(prompt)
        except Exception:  # noqa: BLE001 - an unanswered turn ends this attempt, not the run
            break

        safe_text = redact(response.text or "", ignore=(canary,)).redacted_text
        turns.append(
            ConversationTurn(turn_index=len(turns) + 1, prompt=prompt, response_text=safe_text)
        )

        # Early stop: once the probe considers this conversation a success,
        # further turns would only pad the transcript. A probe whose
        # technique only pays off on the final turn simply never stops
        # early, since its own `detect` will not say so until then.
        if probe.detect(script, tuple(turns), canary).succeeded:
            break

    if not turns:
        return None

    detection = probe.detect(script, tuple(turns), canary)
    return detection.succeeded, tuple(turns)


def _record_for(
    script: ConversationScript, succeeded: bool, turns: tuple[ConversationTurn, ...]
) -> TrialRecord:
    reason = (
        f"conversation {script.id} reached the canary by turn {turns[-1].turn_index}"
        if succeeded
        else f"conversation {script.id} did not produce the canary in {len(turns)} turn(s)"
    )
    joined_prompt = _render_transcript(turns)
    joined_response = "\n".join(turn.response_text for turn in turns)
    return TrialRecord(
        attempt_id=script.id,
        prompt=joined_prompt,
        is_control=script.is_control,
        succeeded=succeeded,
        reason=reason,
        response_text=joined_response[:MAX_RESPONSE_CHARS],
        detection_evidence=turns[-1].response_text[:400] if succeeded else "",
    )


async def _run_script_set(
    probe: MultiTurnProbe,
    scripts: tuple[ConversationScript, ...],
    ctx: RunContext,
    ask: Ask,
    trials: int,
    records: list[TrialRecord],
    canary: str,
) -> tuple[int, int]:
    successes = 0
    performed = 0
    for script in scripts:
        for _ in range(trials):
            if ctx.halted or ctx.kill_switch.tripped:
                return successes, performed
            outcome = await _run_conversation(probe, script, ctx, ask, canary)
            if outcome is None:
                continue
            succeeded, turns = outcome
            performed += 1
            if succeeded:
                successes += 1
            records.append(_record_for(script, succeeded, turns))
    return successes, performed


async def _run_each_script(
    probe: MultiTurnProbe,
    scripts: tuple[ConversationScript, ...],
    ctx: RunContext,
    ask: Ask,
    trials: int,
    records: list[TrialRecord],
    canary: str,
) -> dict[str, tuple[int, int]]:
    per_script: dict[str, tuple[int, int]] = {}
    for script in scripts:
        successes, performed = await _run_script_set(
            probe, (script,), ctx, ask, trials, records, canary
        )
        if performed:
            per_script[script.id] = (successes, performed)
    return per_script


async def run_multi_turn_probe(
    probe: MultiTurnProbe,
    target: AiProbeTarget,
    ctx: RunContext,
    ask: Ask,
    *,
    canary: str | None = None,
) -> list[ScanResult]:
    """Execute one multi-turn probe's plan and hand it a measured outcome,
    the direct multi-turn counterpart of `driver.run_ai_probe`.

    Controls run first, for the same reason the single-shot driver runs them
    first: if a benign, unescalated conversation already produces the
    marker, no chained technique can clear the bar, and that is worth
    knowing before spending the trial budget on one that cannot.
    """
    if not probe.applies_to(target):
        return []

    marker = canary or new_canary()
    plan = probe.plan(target, marker)
    if not plan.scripts:
        return []

    trials = TrialBudget(probe.meta.default_trials).resolve(target.trials)
    records: list[TrialRecord] = []

    control_successes, control_trials = await _run_script_set(
        probe, plan.controls, ctx, ask, trials, records, marker
    )
    per_script = await _run_each_script(probe, plan.scripts, ctx, ask, trials, records, marker)

    best_id, attack_successes, attack_trials = strongest_attempt(per_script)

    measurement: Measurement = measure(
        attack_successes=attack_successes,
        attack_trials=attack_trials,
        control_successes=control_successes,
        control_trials=control_trials,
        rule=DEFAULT_RULE,
    )
    outcome = ProbeOutcome(
        measurement=measurement,
        records=tuple(records),
        canary=marker,
        best_attempt_id=best_id,
    )
    return _with_evidence(probe.report(target, outcome), probe, target, outcome)


def _with_evidence(
    results: list[ScanResult],
    probe: MultiTurnProbe,
    target: AiProbeTarget,
    outcome: ProbeOutcome,
) -> list[ScanResult]:
    bundle = _bundle_for(probe, target, outcome)
    if bundle is None:
        return results
    return [
        replace(result, evidence_bundle=bundle)
        if result.severity is not Severity.INFORMATIONAL
        else result
        for result in results
    ]


def _bundle_for(
    probe: MultiTurnProbe, target: AiProbeTarget, outcome: ProbeOutcome
) -> EvidenceBundle | None:
    success = outcome.first_success()
    if success is None:
        return None
    verdict = " — ".join(part for part in (success.reason, success.detection_evidence) if part)
    # `method="CONVERSATION"`: what is reproducible here is the whole
    # transcript, not one request/response pair — `driver.py` uses `"TURN"`
    # for exactly one exchange, and reusing that name for a multi-exchange
    # bundle would misstate what a reader can expect to reproduce.
    return build_bundle(
        probe_id=probe.meta.id,
        probe_version=probe.meta.version,
        method="CONVERSATION",
        url=target.surface,
        request_body=success.prompt,
        response_body=success.response_text,
        detector_verdict=verdict,
        canaries=(outcome.canary,),
        adapter={
            "surface": target.surface,
            "attempt_id": success.attempt_id,
            "measured_attempt_id": outcome.best_attempt_id,
            "trials": outcome.measurement.attack.trials,
        },
    )
