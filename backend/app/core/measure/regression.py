"""Cross-run/version statistical comparison for AI probe results
(`docs/competitive-gap-analysis.md`'s "Cross-version/run statistical
comparison" gap: `RetestResult` is presence/absence by fingerprint, never
an ASR delta or CI-vs-CI comparison).

This module is pure and database-free, by design: it takes two runs'
`ScanResultRead`-shaped payloads (exactly what `GET
.../runs/{id}/results` returns, which is what the CLI already has to
hand) and matches them by probe identity. The comparison reuses
`app.core.measure.asr`'s own non-overlap rule, applied a second time: a
probe's attack success rate did not "go up", in a way worth a CI
failure, just because this run's point estimate is a few points higher
than last run's — a model is stochastic, and §7.1's own reasoning for
requiring an attack-vs-control interval applies identically to a
baseline-vs-current interval. A regression is reported only when the
current run's Wilson interval and the baseline run's no longer overlap
in the direction that matters.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.core.measure.asr import Rate

_AI_CATEGORY = "AI_SECURITY"


class Verdict(StrEnum):
    """What changed for one probe identity between the two runs."""

    REGRESSED = "regressed"
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    NEW_PROBE = "new_probe"
    REMOVED_PROBE = "removed_probe"


@dataclass(frozen=True)
class ProbeComparison:
    probe_id: str
    identity: str
    title: str
    baseline: Rate | None
    current: Rate | None
    verdict: Verdict
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "identity": self.identity,
            "title": self.title,
            "baseline": self.baseline.as_dict() if self.baseline else None,
            "current": self.current.as_dict() if self.current else None,
            "verdict": self.verdict.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RegressionReport:
    baseline_run_id: str
    current_run_id: str
    comparisons: tuple[ProbeComparison, ...]

    @property
    def regressions(self) -> tuple[ProbeComparison, ...]:
        return tuple(c for c in self.comparisons if c.verdict is Verdict.REGRESSED)

    @property
    def improvements(self) -> tuple[ProbeComparison, ...]:
        return tuple(c for c in self.comparisons if c.verdict is Verdict.IMPROVED)

    def as_dict(self) -> dict[str, Any]:
        return {
            "baseline_run_id": self.baseline_run_id,
            "current_run_id": self.current_run_id,
            "comparisons": [c.as_dict() for c in self.comparisons],
            "regressed": len(self.regressions),
            "improved": len(self.improvements),
        }


def _identity(result: dict[str, Any]) -> str:
    """A stable identity for one probe's result across two runs.

    `fingerprint` is the engine's own cross-run identity where it computed
    one; falling back to `probe_id` + `endpoint` mirrors the same
    reasoning the findings service uses for anything without a stable
    fingerprint, since two runs of the same probe against the same
    surface are "the same measurement" even if no fingerprint was set.
    """
    fingerprint = result.get("fingerprint")
    if fingerprint:
        return str(fingerprint)
    return f"{result.get('probe_id', '')}::{result.get('endpoint', '')}"


def _rate_of(result: dict[str, Any]) -> Rate | None:
    measurement = result.get("measurement")
    if not measurement:
        return None
    attack = measurement.get("attack_success_rate")
    if not attack:
        return None
    ci95 = attack.get("ci95") or [0.0, 1.0]
    return Rate(
        successes=int(attack["successes"]),
        trials=int(attack["trials"]),
        rate=float(attack["rate"]),
        ci95=(float(ci95[0]), float(ci95[1])),
    )


def _is_finding(result: dict[str, Any]) -> bool:
    measurement = result.get("measurement")
    return bool(measurement and measurement.get("is_finding"))


def _measured_ai_results(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """AI-security results that actually carry a trial-based measurement,
    keyed by identity. Design-review and coverage-marker rows (no
    `measurement`, e.g. the permission-graph inventory or the "judge
    disabled" note) are not a rate to compare and are excluded rather than
    silently treated as a zero-trial baseline."""
    by_identity: dict[str, dict[str, Any]] = {}
    for result in results:
        if result.get("category") != _AI_CATEGORY:
            continue
        if _rate_of(result) is None:
            continue
        by_identity[_identity(result)] = result
    return by_identity


def compare_runs(
    baseline_results: list[dict[str, Any]],
    current_results: list[dict[str, Any]],
    *,
    baseline_run_id: str,
    current_run_id: str,
) -> RegressionReport:
    baseline_by_identity = _measured_ai_results(baseline_results)
    current_by_identity = _measured_ai_results(current_results)

    comparisons: list[ProbeComparison] = []
    for identity in sorted(set(baseline_by_identity) | set(current_by_identity)):
        baseline_result = baseline_by_identity.get(identity)
        current_result = current_by_identity.get(identity)
        baseline_rate = _rate_of(baseline_result) if baseline_result else None
        current_rate = _rate_of(current_result) if current_result else None
        title = (current_result or baseline_result or {}).get("title", identity)
        probe_id = (current_result or baseline_result or {}).get("probe_id", "")

        if baseline_rate is not None and current_rate is not None:
            if current_rate.lower > baseline_rate.upper:
                verdict = Verdict.REGRESSED
                detail = (
                    f"attack success rate rose from {baseline_rate.rate:.0%} "
                    f"(95% CI {baseline_rate.lower:.0%}-{baseline_rate.upper:.0%}) to "
                    f"{current_rate.rate:.0%} (95% CI {current_rate.lower:.0%}-"
                    f"{current_rate.upper:.0%}) — the intervals no longer overlap"
                )
            elif baseline_rate.lower > current_rate.upper:
                verdict = Verdict.IMPROVED
                detail = (
                    f"attack success rate fell from {baseline_rate.rate:.0%} to "
                    f"{current_rate.rate:.0%} — the intervals no longer overlap"
                )
            else:
                verdict = Verdict.UNCHANGED
                detail = (
                    f"{baseline_rate.rate:.0%} -> {current_rate.rate:.0%}, within sampling "
                    "noise (the two 95% CIs overlap)"
                )
        elif current_rate is not None:
            if _is_finding(current_result or {}):
                verdict = Verdict.REGRESSED
                detail = (
                    f"not measured in the baseline run; now a finding at "
                    f"{current_rate.rate:.0%}"
                )
            else:
                verdict = Verdict.NEW_PROBE
                detail = "ran in the current run only; not a finding"
        else:
            assert baseline_rate is not None
            if _is_finding(baseline_result or {}):
                verdict = Verdict.IMPROVED
                detail = (
                    f"was a finding at {baseline_rate.rate:.0%} in the baseline run; "
                    "not reproduced in the current run"
                )
            else:
                verdict = Verdict.REMOVED_PROBE
                detail = "ran in the baseline run only; was not a finding there either"

        comparisons.append(
            ProbeComparison(
                probe_id=probe_id,
                identity=identity,
                title=title,
                baseline=baseline_rate,
                current=current_rate,
                verdict=verdict,
                detail=detail,
            )
        )

    return RegressionReport(
        baseline_run_id=baseline_run_id,
        current_run_id=current_run_id,
        comparisons=tuple(comparisons),
    )
