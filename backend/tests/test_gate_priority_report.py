"""P0-P4 priority and the packaged quality-gate report (docs/BUILD_SPEC.md §23).

The report is a pure repackaging of a `GateDecision` `evaluate()` already
reached — these tests check that the repackaging never disagrees with the
decision it describes, not that gating logic itself is correct (that is
`test_gate.py`'s job).
"""

from datetime import date, datetime

from app.core.gate.evaluate import evaluate
from app.core.gate.model import GateConfig, GateFinding
from app.core.gate.priority import PRIORITY_ORDER, Priority, priority_for
from app.core.gate.report import build_report
from app.core.probes.models import Confidence, Severity

TODAY = date(2026, 6, 1)


def _finding(
    *,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    stability: str = "deterministic",
    status: str = "new",
    fingerprint: str = "sha256:" + "1" * 64,
    title: str = "Direct prompt injection",
) -> GateFinding:
    return GateFinding(
        fingerprint=fingerprint,
        title=title,
        severity=severity,
        confidence=confidence,
        stability=stability,
        status=status,
    )


# --- priority_for ----------------------------------------------------------


def test_every_severity_maps_to_exactly_one_priority() -> None:
    mapped = {priority_for(severity) for severity in Severity}
    assert mapped == set(Priority)


def test_the_ladder_runs_most_severe_to_least() -> None:
    assert priority_for(Severity.CRITICAL) == Priority.P0
    assert priority_for(Severity.HIGH) == Priority.P1
    assert priority_for(Severity.MEDIUM) == Priority.P2
    assert priority_for(Severity.LOW) == Priority.P3
    assert priority_for(Severity.INFORMATIONAL) == Priority.P4


def test_priority_order_is_most_urgent_first() -> None:
    assert PRIORITY_ORDER == (Priority.P0, Priority.P1, Priority.P2, Priority.P3, Priority.P4)


# --- build_report: counts never disagree with the decision ----------------


def test_priority_counts_sum_to_the_same_total_the_decision_counted() -> None:
    findings = [
        _finding(severity=Severity.CRITICAL, fingerprint="sha256:" + "1" * 64),
        _finding(severity=Severity.HIGH, fingerprint="sha256:" + "2" * 64),
        _finding(severity=Severity.HIGH, fingerprint="sha256:" + "3" * 64),
        _finding(severity=Severity.MEDIUM, fingerprint="sha256:" + "4" * 64),
    ]
    decision = evaluate(findings, GateConfig(), today=TODAY)
    report = build_report(decision, generated_at=datetime(2026, 6, 1, 12, 0))

    assert sum(decision.counts.values()) == sum(report.priority_counts.values())
    assert report.priority_counts[Priority.P0] == 1  # the critical
    assert report.priority_counts[Priority.P1] == 2  # the two highs
    assert report.priority_counts[Priority.P2] == 1  # the medium
    assert report.priority_counts[Priority.P3] == 0
    assert report.priority_counts[Priority.P4] == 0


def test_the_report_never_reaches_a_different_verdict_than_the_decision() -> None:
    decision = evaluate([_finding(severity=Severity.CRITICAL)], GateConfig(), today=TODAY)
    report = build_report(decision)

    assert report.passed is decision.passed
    assert report.exit_code == int(decision.exit_code)
    assert report.reasons == tuple(decision.reasons)


def test_blocking_findings_carry_their_priority() -> None:
    decision = evaluate([_finding(severity=Severity.CRITICAL)], GateConfig(), today=TODAY)
    report = build_report(decision)

    assert len(report.blocking) == 1
    assert report.blocking[0].priority == Priority.P0
    assert report.blocking[0].severity == "CRITICAL"


def test_excluded_findings_carry_their_priority_and_reason() -> None:
    decision = evaluate(
        [_finding(severity=Severity.CRITICAL, stability="single_shot")],
        GateConfig(),
        today=TODAY,
    )
    report = build_report(decision)

    assert len(report.excluded) == 1
    assert report.excluded[0].priority == Priority.P0
    assert "One observation is not a measurement" in report.excluded[0].reason


# --- rendering --------------------------------------------------------------


def test_markdown_names_the_verdict_and_every_priority_band() -> None:
    decision = evaluate([_finding(severity=Severity.CRITICAL)], GateConfig(), today=TODAY)
    report = build_report(decision, generated_at=datetime(2026, 6, 1, 12, 0))
    markdown = report.to_markdown()

    assert "FAIL" in markdown
    for priority in Priority:
        assert priority.value in markdown
    assert "Direct prompt injection" in markdown


def test_markdown_passing_report_names_the_verdict_with_no_blocking_section() -> None:
    decision = evaluate([], GateConfig(), today=TODAY)
    report = build_report(decision, generated_at=datetime(2026, 6, 1, 12, 0))
    markdown = report.to_markdown()

    assert "PASS" in markdown
    assert "## Blocking findings" not in markdown


def test_as_dict_round_trips_every_priority_band_even_when_zero() -> None:
    decision = evaluate([], GateConfig(), today=TODAY)
    report = build_report(decision, generated_at=datetime(2026, 6, 1, 12, 0))
    payload = report.as_dict()

    assert set(payload["priority_counts"]) == {p.value for p in Priority}
    assert payload["passed"] is True
    assert payload["blocking"] == []
    assert payload["excluded"] == []
