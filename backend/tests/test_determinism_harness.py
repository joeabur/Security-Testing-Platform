"""The determinism harness (docs/BUILD_SPEC.md §26 Phase 6: "ASR machinery
verified by the determinism harness").

The machinery that decides whether a probabilistic result counts as a
finding is the part of this tool most able to produce confident nonsense, so
it is tested against known-answer statistics and against simulated targets
whose true behaviour is fixed in advance. Every test here asks the same
question: does the rule reach the right verdict about a target we already
know the truth about?
"""

import random

import pytest

from app.core.measure.asr import (
    Stability,
    asr_delta,
    classify_stability,
    measure,
    rate_of,
    wilson_interval,
)


def test_wilson_interval_matches_published_values() -> None:
    """Known-answer check against the standard Wilson formula.

    These are the values the textbook formula gives for n=10; if an
    "optimisation" ever changes them, this fails.
    """
    low, high = wilson_interval(5, 10)
    assert round(low, 4) == 0.2366
    assert round(high, 4) == 0.7634

    low, high = wilson_interval(10, 10)
    assert round(low, 4) == 0.7225
    assert high == 1.0


def test_zero_trials_is_total_ignorance_not_a_measured_zero() -> None:
    """[0, 1], not [0, 0]. The difference is "we did not look" versus "we
    looked and it never happened", and reporting the second when the first
    is true is how a scanner claims a clean bill of health it never earned.
    """
    assert wilson_interval(0, 0) == (0.0, 1.0)
    assert rate_of(0, 0).ci95 == (0.0, 1.0)


def test_wilson_interval_never_leaves_the_unit_interval() -> None:
    for trials in range(1, 40):
        for successes in range(trials + 1):
            low, high = wilson_interval(successes, trials)
            assert 0.0 <= low <= high <= 1.0


def test_more_trials_narrow_the_interval() -> None:
    wide = wilson_interval(2, 4)
    narrow = wilson_interval(50, 100)
    assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])


def test_successes_cannot_exceed_trials() -> None:
    with pytest.raises(ValueError, match="between 0 and trials"):
        wilson_interval(6, 5)


# --- the decision rule against targets whose truth is known --------------


def test_a_target_that_always_yields_is_a_deterministic_finding() -> None:
    outcome = measure(attack_successes=5, attack_trials=5, control_successes=0, control_trials=5)
    assert outcome.is_finding is True
    assert outcome.stability is Stability.DETERMINISTIC


def test_a_target_that_never_yields_is_not_a_finding() -> None:
    outcome = measure(attack_successes=0, attack_trials=5, control_successes=0, control_trials=5)
    assert outcome.is_finding is False


def test_a_target_that_behaves_the_same_way_anyway_is_not_a_finding() -> None:
    """The control is what stops "the model mentioned the marker" from being
    reported as "the injection worked". If the benign request produces the
    same behaviour, the attack demonstrated nothing."""
    outcome = measure(attack_successes=5, attack_trials=5, control_successes=5, control_trials=5)
    assert outcome.is_finding is False


def test_a_weak_effect_at_small_n_is_not_reported() -> None:
    """3/5 versus 1/5 looks suggestive and is not significant at n=5. A tool
    that reports it is manufacturing findings out of sampling noise."""
    outcome = measure(attack_successes=3, attack_trials=5, control_successes=1, control_trials=5)
    assert outcome.is_finding is False
    assert outcome.stability is Stability.PROBABILISTIC


def test_the_same_weak_effect_becomes_reportable_with_enough_trials() -> None:
    """60% versus 20% is a real difference; it just needs the trials to
    establish it. The rule is not insensitive, it is honest about n."""
    outcome = measure(
        attack_successes=60, attack_trials=100, control_successes=20, control_trials=100
    )
    assert outcome.is_finding is True


def test_a_missing_control_can_never_produce_a_finding() -> None:
    """Fail closed: with no baseline there is no way to distinguish an
    effective attack from a target that always does this."""
    outcome = measure(attack_successes=5, attack_trials=5, control_successes=0, control_trials=0)
    assert outcome.is_finding is False


def test_a_single_trial_is_marked_single_shot() -> None:
    """§7.4: single-shot results carry no ASR, and §11 caps their confidence
    at medium — which starts with labelling them correctly here."""
    assert classify_stability(rate_of(1, 1)) is Stability.SINGLE_SHOT
    assert classify_stability(rate_of(0, 1)) is Stability.SINGLE_SHOT


# --- simulation: does the rule hold up over many runs? -------------------


def _simulate(true_attack_rate: float, true_control_rate: float, trials: int, seed: int) -> bool:
    rng = random.Random(seed)
    attack_hits = sum(1 for _ in range(trials) if rng.random() < true_attack_rate)
    control_hits = sum(1 for _ in range(trials) if rng.random() < true_control_rate)
    return measure(
        attack_successes=attack_hits,
        attack_trials=trials,
        control_successes=control_hits,
        control_trials=trials,
    ).is_finding


def test_a_target_with_no_real_effect_almost_never_produces_a_finding() -> None:
    """False-positive behaviour over 500 simulated runs of a target where
    the attack does nothing. The rule is conservative by construction, so
    this should be zero or very close to it — a scanner that cries wolf on
    a clean target is worse than useless."""
    false_positives = sum(1 for seed in range(500) if _simulate(0.3, 0.3, trials=5, seed=seed))
    assert false_positives == 0


def test_a_genuinely_vulnerable_target_is_caught_at_the_default_trial_count() -> None:
    """The counterpart: a target that always yields to the attack and never
    to the control is detected every time at the default 5 trials."""
    detections = sum(1 for seed in range(200) if _simulate(1.0, 0.0, trials=5, seed=seed))
    assert detections == 200


def test_detection_of_a_partial_vulnerability_improves_with_trials() -> None:
    """An 80%-effective attack is missed more often at n=5 than at n=20.
    This is the trade the budget buys, and it is stated rather than hidden:
    a low trial count means real weaknesses can go unreported."""
    at_five = sum(1 for seed in range(200) if _simulate(0.8, 0.0, trials=5, seed=seed))
    at_twenty = sum(1 for seed in range(200) if _simulate(0.8, 0.0, trials=20, seed=seed))
    assert at_twenty > at_five


# --- asr_delta: comparing a rate across a retest boundary -----------------


def test_asr_delta_is_none_without_both_sides() -> None:
    """No fabricated comparison when either side has no rate — a finding
    whose probe never ran under the trial driver, or a retest that found
    nothing new, has nothing to diff."""
    before = rate_of(5, 5).as_dict()
    assert asr_delta(None, None) is None
    assert asr_delta(before, None) is None
    assert asr_delta(None, before) is None


def test_asr_delta_flags_a_significant_increase() -> None:
    """A clear jump — 0/5 before, 5/5 after — clears the same Wilson-based
    bar `measure()` uses between attack and control, applied here between
    the earlier and later rate instead."""
    before = rate_of(0, 5).as_dict()
    after = rate_of(5, 5).as_dict()
    delta = asr_delta(before, after)
    assert delta is not None
    assert delta["direction"] == "increased"
    assert delta["significant"] is True
    assert delta["before"]["rate"] == 0.0
    assert delta["after"]["rate"] == 1.0


def test_asr_delta_flags_a_significant_decrease() -> None:
    """The mirror image: a weakness that used to always succeed and now
    never does — the useful case for a retest that reproduced the
    fingerprint but at a visibly reduced rate."""
    before = rate_of(5, 5).as_dict()
    after = rate_of(0, 5).as_dict()
    delta = asr_delta(before, after)
    assert delta is not None
    assert delta["direction"] == "decreased"
    assert delta["significant"] is True


def test_asr_delta_is_unchanged_when_within_sampling_noise() -> None:
    """Two rates that are the same effect measured twice, at a trial count
    too small to tell apart from noise, must not be reported as a
    direction — that would be exactly the coin-flip-as-measurement mistake
    §7.1 exists to prevent."""
    before = rate_of(3, 5).as_dict()
    after = rate_of(2, 5).as_dict()
    delta = asr_delta(before, after)
    assert delta is not None
    assert delta["direction"] == "unchanged"
    assert delta["significant"] is False


def test_asr_delta_is_unchanged_for_an_identical_rate() -> None:
    before = rate_of(5, 5).as_dict()
    after = rate_of(5, 5).as_dict()
    delta = asr_delta(before, after)
    assert delta is not None
    assert delta["direction"] == "unchanged"
    assert delta["significant"] is False
