"""Cross-run statistical comparison (`app/core/measure/regression.py`),
the gap `docs/competitive-gap-analysis.md` named as not present:
`RetestResult` is presence/absence by fingerprint, never an ASR delta or
CI-vs-CI comparison.
"""

from app.core.measure.regression import Verdict, compare_runs


def _ai_result(
    *,
    probe_id: str = "ai.jailbreak.instruction_override",
    title: str = "Direct prompt injection",
    fingerprint: str = "sha256:" + "1" * 64,
    endpoint: str = "POST /api/chat",
    successes: int,
    trials: int,
    rate: float,
    ci95: tuple[float, float],
    is_finding: bool,
) -> dict[str, object]:
    return {
        "category": "AI_SECURITY",
        "probe_id": probe_id,
        "title": title,
        "fingerprint": fingerprint,
        "endpoint": endpoint,
        "measurement": {
            "attack_success_rate": {
                "successes": successes,
                "trials": trials,
                "rate": rate,
                "ci95": list(ci95),
            },
            "control_success_rate": {
                "successes": 0,
                "trials": trials,
                "rate": 0.0,
                "ci95": [0.0, 0.3],
            },
            "is_finding": is_finding,
            "stability": "probabilistic",
            "decision_rule": "...",
        },
    }


def _design_review_result(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "category": "AI_SECURITY",
        "probe_id": "ai.agency.permission_inventory",
        "title": "Permission graph inventory",
        "fingerprint": "sha256:" + "9" * 64,
        "endpoint": "design-review",
        "measurement": None,
    }
    base.update(overrides)
    return base


def test_unchanged_rate_is_not_a_regression() -> None:
    baseline = [
        _ai_result(successes=4, trials=5, rate=0.8, ci95=(0.38, 0.96), is_finding=True)
    ]
    current = [
        _ai_result(successes=5, trials=5, rate=1.0, ci95=(0.57, 1.0), is_finding=True)
    ]

    report = compare_runs(baseline, current, baseline_run_id="base", current_run_id="cur")

    assert len(report.comparisons) == 1
    assert report.comparisons[0].verdict is Verdict.UNCHANGED
    assert report.regressions == ()


def test_a_significant_rise_in_attack_success_rate_is_a_regression() -> None:
    baseline = [
        _ai_result(successes=0, trials=5, rate=0.0, ci95=(0.0, 0.43), is_finding=False)
    ]
    current = [
        _ai_result(successes=5, trials=5, rate=1.0, ci95=(0.57, 1.0), is_finding=True)
    ]

    report = compare_runs(baseline, current, baseline_run_id="base", current_run_id="cur")

    assert len(report.regressions) == 1
    assert report.regressions[0].verdict is Verdict.REGRESSED
    assert "95% CI" in report.regressions[0].detail


def test_a_significant_fall_in_attack_success_rate_is_an_improvement() -> None:
    baseline = [
        _ai_result(successes=5, trials=5, rate=1.0, ci95=(0.57, 1.0), is_finding=True)
    ]
    current = [
        _ai_result(successes=0, trials=5, rate=0.0, ci95=(0.0, 0.43), is_finding=False)
    ]

    report = compare_runs(baseline, current, baseline_run_id="base", current_run_id="cur")

    assert len(report.improvements) == 1
    assert report.improvements[0].verdict is Verdict.IMPROVED


def test_a_brand_new_finding_absent_from_the_baseline_is_a_regression() -> None:
    current = [
        _ai_result(successes=5, trials=5, rate=1.0, ci95=(0.57, 1.0), is_finding=True)
    ]

    report = compare_runs([], current, baseline_run_id="base", current_run_id="cur")

    assert len(report.regressions) == 1
    assert "not measured in the baseline run" in report.regressions[0].detail


def test_a_new_probe_that_found_nothing_is_not_a_regression() -> None:
    current = [
        _ai_result(successes=0, trials=5, rate=0.0, ci95=(0.0, 0.43), is_finding=False)
    ]

    report = compare_runs([], current, baseline_run_id="base", current_run_id="cur")

    assert report.comparisons[0].verdict is Verdict.NEW_PROBE
    assert report.regressions == ()


def test_a_finding_resolved_since_the_baseline_is_an_improvement() -> None:
    baseline = [
        _ai_result(successes=5, trials=5, rate=1.0, ci95=(0.57, 1.0), is_finding=True)
    ]

    report = compare_runs(baseline, [], baseline_run_id="base", current_run_id="cur")

    assert report.comparisons[0].verdict is Verdict.IMPROVED
    assert "not reproduced in the current run" in report.comparisons[0].detail


def test_a_probe_dropped_between_runs_that_was_never_a_finding_is_not_reported_as_improved() -> (
    None
):
    baseline = [
        _ai_result(successes=0, trials=5, rate=0.0, ci95=(0.0, 0.43), is_finding=False)
    ]

    report = compare_runs(baseline, [], baseline_run_id="base", current_run_id="cur")

    assert report.comparisons[0].verdict is Verdict.REMOVED_PROBE
    assert report.regressions == () and report.improvements == ()


def test_design_review_results_without_a_measurement_are_excluded() -> None:
    """A permission-graph inventory or a "judge disabled" marker has no
    trial-based rate to compare; treating its absence of `measurement` as a
    zero-trial result would misreport it as either a regression or an
    improvement depending on which run it appeared in."""
    report = compare_runs(
        [_design_review_result()],
        [_design_review_result()],
        baseline_run_id="base",
        current_run_id="cur",
    )

    assert report.comparisons == ()


def test_non_ai_results_are_excluded() -> None:
    api_result = {
        "category": "API_SECURITY",
        "probe_id": "api.bola",
        "title": "BOLA",
        "fingerprint": "sha256:" + "2" * 64,
        "endpoint": "GET /orders/{id}",
        "measurement": None,
    }

    report = compare_runs([api_result], [api_result], baseline_run_id="base", current_run_id="cur")

    assert report.comparisons == ()


def test_results_without_a_fingerprint_match_on_probe_id_and_endpoint() -> None:
    baseline = [
        _ai_result(
            fingerprint="",
            successes=0,
            trials=5,
            rate=0.0,
            ci95=(0.0, 0.43),
            is_finding=False,
        )
    ]
    baseline[0]["fingerprint"] = None
    current = [
        _ai_result(
            fingerprint="",
            successes=5,
            trials=5,
            rate=1.0,
            ci95=(0.57, 1.0),
            is_finding=True,
        )
    ]
    current[0]["fingerprint"] = None

    report = compare_runs(baseline, current, baseline_run_id="base", current_run_id="cur")

    assert len(report.comparisons) == 1
    assert report.comparisons[0].verdict is Verdict.REGRESSED


def test_report_as_dict_round_trips_the_counts() -> None:
    baseline = [
        _ai_result(successes=0, trials=5, rate=0.0, ci95=(0.0, 0.43), is_finding=False)
    ]
    current = [
        _ai_result(successes=5, trials=5, rate=1.0, ci95=(0.57, 1.0), is_finding=True)
    ]

    report = compare_runs(baseline, current, baseline_run_id="base", current_run_id="cur")
    payload = report.as_dict()

    assert payload["baseline_run_id"] == "base"
    assert payload["current_run_id"] == "cur"
    assert payload["regressed"] == 1
    assert payload["improved"] == 0
    assert payload["comparisons"][0]["verdict"] == "regressed"
