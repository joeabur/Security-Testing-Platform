"""Runs a `CrossIdentityProbe`'s plan as repeated cross-identity exchanges
and measures the result — the cross-identity analogue of
`app.core.probes.ai.multiturn.runner`, which this module mirrors closely
except for who sends each turn.

Reuses `app.core.measure.asr.measure()` unchanged, the same way the
multi-turn runner does: a "trial" is one full pass of a `CrossIdentityScript`
— however many identities and turns it takes — measured exactly like a
single request.
"""

from collections.abc import Mapping
from dataclasses import dataclass, replace

from app.core.evidence.bundle import EvidenceBundle, build_bundle
from app.core.measure.asr import DEFAULT_RULE, Measurement, measure
from app.core.probes.ai._support import strongest_attempt
from app.core.probes.ai.contract import AiProbeTarget, Ask, ProbeOutcome, TrialRecord, new_canary
from app.core.probes.ai.cross_identity.contract import (
    CrossIdentityPlan,
    CrossIdentityProbe,
    CrossIdentityScript,
)
from app.core.probes.ai.multiturn.contract import ConversationTurn
from app.core.probes.models import ScanResult, Severity
from app.core.redaction.secrets import redact
from app.core.scope.context import RunContext

# Mirrors multiturn.runner's own budget/response/turn ceilings — the same
# reasoning applies unchanged: a script that chains several turns per trial
# must not multiply a bounded trial budget into an unbounded request count.
MAX_TRIALS = 20
MAX_RESPONSE_CHARS = 2000
MAX_TURNS_PER_SCRIPT = 10


@dataclass(frozen=True)
class TrialBudget:
    """Bounds on how many full cross-identity exchanges one probe may run."""

    trials: int = 5

    def resolve(self, requested: int | None) -> int:
        return max(1, min(requested or self.trials, MAX_TRIALS))


async def _run_conversation(
    probe: CrossIdentityProbe,
    script: CrossIdentityScript,
    ctx: RunContext,
    ask_as: Mapping[str, Ask],
    canary: str,
) -> tuple[bool, tuple[ConversationTurn, ...]] | None:
    """Run one full pass of `script`. Returns `None` if the run was halted or
    the target raised before a single turn completed — never counted as
    either a success or a performed trial, the same rule
    `multiturn.runner._run_conversation` applies.

    Deliberately does **not** replay prior turns as text into later ones
    (see `contract.py`'s module docstring for why): each turn is sent as
    exactly its own template, substituting `{canary}` where the template
    asks for it and nothing else.
    """
    turns: list[ConversationTurn] = []
    templates = script.turns[:MAX_TURNS_PER_SCRIPT]

    for identity_turn in templates:
        if ctx.halted or ctx.kill_switch.tripped:
            break

        ask = ask_as.get(identity_turn.account_label)
        if ask is None:
            # The script names an account this run has no resolvable
            # credential for. Stop this trial rather than guess who else
            # might stand in for it.
            break

        prompt = identity_turn.prompt_template.format(canary=canary)
        try:
            response = await ask(prompt)
        except Exception:  # noqa: BLE001 - an unanswered turn ends this trial, not the run
            break

        safe_text = redact(response.text or "", ignore=(canary,)).redacted_text
        turns.append(
            ConversationTurn(turn_index=len(turns) + 1, prompt=prompt, response_text=safe_text)
        )

        if probe.detect(script, tuple(turns), canary).succeeded:
            break

    if not turns:
        return None

    detection = probe.detect(script, tuple(turns), canary)
    return detection.succeeded, tuple(turns)


def _record_for(
    script: CrossIdentityScript, succeeded: bool, turns: tuple[ConversationTurn, ...]
) -> TrialRecord:
    reason = (
        f"cross-identity exchange {script.id} reached the canary by turn {turns[-1].turn_index}"
        if succeeded
        else f"cross-identity exchange {script.id} did not produce the canary in "
        f"{len(turns)} turn(s)"
    )
    joined_prompt = "\n".join(f"[Turn {turn.turn_index}] {turn.prompt}" for turn in turns)
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
    probe: CrossIdentityProbe,
    scripts: tuple[CrossIdentityScript, ...],
    ctx: RunContext,
    ask_as: Mapping[str, Ask],
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
            outcome = await _run_conversation(probe, script, ctx, ask_as, canary)
            if outcome is None:
                continue
            succeeded, turns = outcome
            performed += 1
            if succeeded:
                successes += 1
            records.append(_record_for(script, succeeded, turns))
    return successes, performed


async def _run_each_script(
    probe: CrossIdentityProbe,
    scripts: tuple[CrossIdentityScript, ...],
    ctx: RunContext,
    ask_as: Mapping[str, Ask],
    trials: int,
    records: list[TrialRecord],
    canary: str,
) -> dict[str, tuple[int, int]]:
    per_script: dict[str, tuple[int, int]] = {}
    for script in scripts:
        successes, performed = await _run_script_set(
            probe, (script,), ctx, ask_as, trials, records, canary
        )
        if performed:
            per_script[script.id] = (successes, performed)
    return per_script


def _empty_outcome(canary: str) -> ProbeOutcome:
    """A zero-trial outcome, for the `applies_to() is False` / empty-plan
    paths: still routed through `probe.report()` rather than returned
    directly, so a probe can tell a reader why it produced nothing."""
    return ProbeOutcome(
        measurement=measure(
            attack_successes=0, attack_trials=0, control_successes=0, control_trials=0,
            rule=DEFAULT_RULE,
        ),
        records=(),
        canary=canary,
    )


async def run_cross_identity_probe(
    probe: CrossIdentityProbe,
    target: AiProbeTarget,
    ctx: RunContext,
    ask_as: Mapping[str, Ask],
    *,
    canary: str | None = None,
) -> list[ScanResult]:
    """Execute one cross-identity probe's plan and hand it a measured
    outcome, the cross-identity counterpart of
    `multiturn.runner.run_multi_turn_probe`.

    Controls run first, for the same reason every other runner in this
    package does that: if the control (typically the same identity asking
    for its own earlier statement back) already fails, the target has no
    server-side state correlation at all, and the attack script's result
    would be worth knowing before spending the rest of the trial budget on
    it either way.
    """
    marker = canary or new_canary()

    if not probe.applies_to(target):
        # Routed through `report()`, not a silent `[]`, so a probe can
        # record *why* it did not run (no existing AI probe needed this
        # distinction before this one — see `data_leakage.py`'s own
        # "not tested" marker).
        return probe.report(target, _empty_outcome(marker))

    plan: CrossIdentityPlan = probe.plan(target, marker)
    if not plan.scripts:
        return probe.report(target, _empty_outcome(marker))

    trials = TrialBudget(probe.meta.default_trials).resolve(target.trials)
    records: list[TrialRecord] = []

    control_successes, control_trials = await _run_script_set(
        probe, plan.controls, ctx, ask_as, trials, records, marker
    )
    per_script = await _run_each_script(probe, plan.scripts, ctx, ask_as, trials, records, marker)

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
    probe: CrossIdentityProbe,
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
    probe: CrossIdentityProbe, target: AiProbeTarget, outcome: ProbeOutcome
) -> EvidenceBundle | None:
    success = outcome.first_success()
    if success is None:
        return None
    verdict = " — ".join(part for part in (success.reason, success.detection_evidence) if part)
    # `method="CONVERSATION"`, same as multiturn.runner: what is reproducible
    # here is the whole exchange across identities, not one request/response
    # pair.
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
