"""Packaging a `GateDecision` into a shareable artifact (docs/BUILD_SPEC.md §23).

`_print_decision` in `kervy_cli` prints the decision to a CI log, which
answers "why did this build fail?" for the one person watching that job run.
It does not answer it for anyone who opens the PR a day later, or for a
dashboard that wants to show the same verdict without re-running the gate —
that needs a file, not a stream. `QualityGateReport` is that file: the same
decision, the same exclusion reasons, with findings additionally grouped by
P0-P4 (`priority.py`) so the report speaks the ticket-tracker vocabulary a
remediation plan (§14) already promises, not only the risk model's own
severity words.

This is a pure repackaging. It computes nothing `evaluate()` did not already
decide — a report that recomputed the verdict could disagree with the gate
it is supposed to describe.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.core.gate.model import Exclusion, GateDecision, GateFinding
from app.core.gate.priority import PRIORITY_ORDER, Priority, priority_for
from app.core.probes.models import Severity


@dataclass(frozen=True)
class PriorityBlockingFinding:
    fingerprint: str
    title: str
    severity: str
    priority: Priority

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "priority": self.priority.value,
        }


@dataclass(frozen=True)
class ExcludedFinding:
    fingerprint: str
    title: str
    severity: str
    priority: Priority
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "priority": self.priority.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class QualityGateReport:
    generated_at: datetime
    passed: bool
    exit_code: int
    reasons: tuple[str, ...]
    priority_counts: dict[Priority, int]
    blocking: tuple[PriorityBlockingFinding, ...]
    excluded: tuple[ExcludedFinding, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "passed": self.passed,
            "exit_code": self.exit_code,
            "reasons": list(self.reasons),
            "priority_counts": {
                priority.value: self.priority_counts.get(priority, 0)
                for priority in PRIORITY_ORDER
            },
            "blocking": [item.as_dict() for item in self.blocking],
            "excluded": [item.as_dict() for item in self.excluded],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Quality gate report",
            "",
            f"Generated: {self.generated_at.isoformat()}",
            f"Result: **{'PASS' if self.passed else 'FAIL'}** (exit code {self.exit_code})",
            "",
            "## Priority breakdown",
            "",
            "| Priority | Count |",
            "| --- | --- |",
        ]
        for priority in PRIORITY_ORDER:
            lines.append(f"| {priority.value} | {self.priority_counts.get(priority, 0)} |")

        if self.reasons:
            lines += ["", "## Why it failed", ""]
            lines += [f"- {reason}" for reason in self.reasons]

        if self.blocking:
            lines += [
                "",
                "## Blocking findings",
                "",
                "| Priority | Severity | Title | Fingerprint |",
                "| --- | --- | --- | --- |",
            ]
            for finding in self.blocking:
                lines.append(
                    f"| {finding.priority.value} | {finding.severity} | {finding.title} "
                    f"| `{finding.fingerprint}` |"
                )

        if self.excluded:
            lines += ["", "## Excluded (not counted toward the verdict)", ""]
            for item in self.excluded:
                lines.append(
                    f"- `{item.fingerprint}` [{item.priority.value}/{item.severity}] "
                    f"{item.title} — {item.reason}"
                )

        return "\n".join(lines) + "\n"


def build_report(
    decision: GateDecision, *, generated_at: datetime | None = None
) -> QualityGateReport:
    """Repackage a decision the gate already reached — never a second verdict."""
    moment = generated_at or datetime.now(UTC)

    priority_counts: dict[Priority, int] = dict.fromkeys(PRIORITY_ORDER, 0)
    for severity_name, count in decision.counts.items():
        try:
            severity = Severity(severity_name)
        except ValueError:
            continue
        priority_counts[priority_for(severity)] += count

    return QualityGateReport(
        generated_at=moment,
        passed=decision.passed,
        exit_code=int(decision.exit_code),
        reasons=tuple(decision.reasons),
        priority_counts=priority_counts,
        blocking=tuple(_blocking(item) for item in decision.blocking),
        excluded=tuple(_excluded(item) for item in decision.excluded),
    )


def _blocking(finding: GateFinding) -> PriorityBlockingFinding:
    return PriorityBlockingFinding(
        fingerprint=finding.fingerprint,
        title=finding.title,
        severity=finding.severity.value,
        priority=priority_for(finding.severity),
    )


def _excluded(exclusion: Exclusion) -> ExcludedFinding:
    return ExcludedFinding(
        fingerprint=exclusion.finding.fingerprint,
        title=exclusion.finding.title,
        severity=exclusion.finding.severity.value,
        priority=priority_for(exclusion.finding.severity),
        reason=exclusion.reason,
    )

