"""Turning findings into a check run a reviewer can act on.

Three decisions shape this module, and all three are about not wasting a
reviewer's attention.

**Annotations only where they will render.** GitHub accepts an annotation only
on a line the pull request's diff touches, and *silently discards* the rest. A
finding in untouched code would therefore vanish. So the diff's changed lines
are read first, findings are filtered against them, and everything that cannot
be anchored is listed in the check run's body instead — visible, just not
inline. The counts of both are reported, so "we posted 12 of 30" is a fact the
caller has rather than a thing they have to infer.

**Pre-existing findings are separated from new ones.** A pull request that
touches one file should not be presented as though it introduced eighty issues
the repository already had. Findings first seen in this run are the ones that
lead; the rest are counted and summarised below.

**The payload carries no evidence.** Title, severity, rationale and remediation
only. A pull request is the most public place this platform writes — an
evidence bundle, a response body or a matched secret has no business there, and
`scrub` runs over everything on the way out regardless.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from app.core.gate.model import GateDecision
from app.core.integrations.dispatch import scrub
from app.core.vcs.contract import (
    MAX_ANNOTATIONS_PER_REQUEST,
    MAX_OUTPUT_TEXT_CHARS,
    Annotation,
    CheckConclusion,
    CheckRunRequest,
    DiffFile,
)

CHECK_RUN_NAME = "Kervy Security"

#: Finding severity -> GitHub annotation level. GitHub has three; this platform
#: has five, so medium and below share `notice` rather than inventing urgency.
_LEVELS: Mapping[str, str] = {
    "CRITICAL": "failure",
    "HIGH": "failure",
    "MEDIUM": "warning",
    "LOW": "notice",
    "INFORMATIONAL": "notice",
}

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


@dataclass(frozen=True)
class PublishableFinding:
    """A finding in the shape this layer needs.

    A separate type from the ORM model for the same reason `GateFinding` is:
    the renderer must be testable without a database, and it must be usable
    against whatever the API returned to a CI job.
    """

    fingerprint: str
    title: str
    severity: str
    surface: str
    probe_id: str
    severity_rationale: str = ""
    remediation: str = ""
    is_new: bool = True

    @property
    def location(self) -> tuple[str | None, int | None]:
        """`(path, line)` when the surface names a file, else `(None, None)`.

        A surface is a file path for a static finding and an HTTP route for a
        dynamic one — `GET /orders/{id}` is not a file, and treating it as one
        would anchor an annotation to a path that does not exist.
        """
        surface = self.surface.strip()
        if not surface or " " in surface:
            return None, None
        path, _, tail = surface.rpartition(":")
        if path and tail.isdigit():
            return path, int(tail)
        return surface, None


def _sort_key(finding: PublishableFinding) -> tuple[int, int, str]:
    order = (
        _SEVERITY_ORDER.index(finding.severity.upper())
        if finding.severity.upper() in _SEVERITY_ORDER
        else len(_SEVERITY_ORDER)
    )
    # New findings first, then by severity: a reviewer reads from the top, and
    # what this change introduced is what they can still do something about.
    return (0 if finding.is_new else 1, order, finding.fingerprint)


def annotations_for(
    findings: Sequence[PublishableFinding], diff: Mapping[str, DiffFile]
) -> tuple[list[Annotation], list[PublishableFinding]]:
    """`(annotations, findings that could not be anchored)`.

    The second element is the point: a finding that GitHub would have discarded
    is handed back so the caller can put it somewhere a human will see it.
    """
    paired: list[tuple[Annotation, PublishableFinding]] = []
    unanchored: list[PublishableFinding] = []

    for finding in sorted(findings, key=_sort_key):
        path, line = finding.location
        file = diff.get(path) if path else None
        if file is None or not file.covers(line):
            unanchored.append(finding)
            continue
        assert line is not None  # `covers` is False for None
        message = scrub(
            "\n\n".join(
                part
                for part in (
                    finding.severity_rationale,
                    f"Remediation: {finding.remediation}" if finding.remediation else "",
                    f"Probe: {finding.probe_id} · fingerprint {finding.fingerprint}",
                )
                if part
            )
        )
        paired.append(
            (
                Annotation(
                    path=file.path,
                    start_line=line,
                    end_line=line,
                    level=_LEVELS.get(finding.severity.upper(), "notice"),
                    title=scrub(f"{finding.severity.upper()}: {finding.title}"),
                    message=message,
                ),
                finding,
            )
        )

    # Over GitHub's cap the extras are not dropped: they move into the body
    # with the rest of the unanchored findings, where a reviewer still sees
    # them. Kept paired with their finding so the overflow is exact, rather
    # than matched back by title — two findings can share one.
    unanchored.extend(finding for _, finding in paired[MAX_ANNOTATIONS_PER_REQUEST:])
    anchored = [annotation for annotation, _ in paired[:MAX_ANNOTATIONS_PER_REQUEST]]

    return anchored, unanchored


def _counts(findings: Sequence[PublishableFinding]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        key = finding.severity.upper()
        if key in counts:
            counts[key] += 1
    return {key: value for key, value in counts.items() if value}


def summary_for(
    findings: Sequence[PublishableFinding],
    decision: GateDecision,
    *,
    anchored: int,
    unanchored: int,
) -> str:
    new = [finding for finding in findings if finding.is_new]
    pre_existing = [finding for finding in findings if not finding.is_new]

    lines: list[str] = []
    if decision.passed:
        lines.append("**Gate passed.**")
    else:
        lines.append("**Gate failed.**")
        lines.extend(f"- {reason}" for reason in decision.reasons)

    if new:
        counted = ", ".join(f"{count} {key.lower()}" for key, count in _counts(new).items())
        lines.append(f"\n{len(new)} finding(s) first seen in this run: {counted}.")
    else:
        lines.append("\nNo findings were first seen in this run.")

    if pre_existing:
        # Stated separately so a change that touched one file is not presented
        # as having introduced what the repository already had.
        counted = ", ".join(
            f"{count} {key.lower()}" for key, count in _counts(pre_existing).items()
        )
        lines.append(f"{len(pre_existing)} pre-existing finding(s) also present: {counted}.")

    if unanchored:
        lines.append(
            f"\n{anchored} finding(s) are annotated inline. {unanchored} could not be: "
            "GitHub only renders an annotation on a line this pull request changed, "
            "so those are listed below instead."
        )
    return scrub("\n".join(lines))


def body_for(findings: Sequence[PublishableFinding]) -> str:
    """The check run's long text: everything that has no inline annotation."""
    if not findings:
        return ""
    rows = ["| Severity | Finding | Where | Probe |", "| --- | --- | --- | --- |"]
    for finding in sorted(findings, key=_sort_key):
        marker = "" if finding.is_new else " _(pre-existing)_"
        rows.append(
            f"| {finding.severity.upper()} "
            f"| {finding.title}{marker} "
            f"| `{finding.surface}` "
            f"| `{finding.probe_id}` |"
        )
    text = scrub("\n".join(rows))
    if len(text) > MAX_OUTPUT_TEXT_CHARS:
        # Truncation is announced. A silently cut table would read as a
        # complete list of what was found.
        keep = MAX_OUTPUT_TEXT_CHARS - 200
        text = (
            text[:keep] + "\n\n_Truncated: too many findings to list here. "
            "The full set is in the Kervy report._"
        )
    return text


def conclusion_for(decision: GateDecision, *, findings: int) -> CheckConclusion:
    """Failure when the gate failed, neutral when there was nothing to judge.

    `neutral` rather than `success` for a run with no findings *and* no gate
    configuration is deliberate: "we checked and found nothing" and "nothing
    was checked" must not look the same on a pull request.
    """
    if not decision.passed:
        return CheckConclusion.FAILURE
    if findings == 0 and not decision.counts:
        return CheckConclusion.NEUTRAL
    return CheckConclusion.SUCCESS


def check_run_for(
    findings: Sequence[PublishableFinding],
    decision: GateDecision,
    *,
    head_sha: str,
    diff: Mapping[str, DiffFile],
    details_url: str | None = None,
) -> tuple[CheckRunRequest, int, int]:
    """Build the check run. Returns it with the anchored/unanchored counts."""
    anchored, unanchored = annotations_for(findings, diff)
    conclusion = conclusion_for(decision, findings=len(findings))
    title = (f"{len(findings)} finding(s)" if findings else "No findings") + (
        " — gate failed" if not decision.passed else ""
    )
    request = CheckRunRequest(
        name=CHECK_RUN_NAME,
        head_sha=head_sha,
        conclusion=conclusion,
        title=title,
        summary=summary_for(findings, decision, anchored=len(anchored), unanchored=len(unanchored)),
        text=body_for(unanchored),
        annotations=anchored,
        details_url=details_url,
    )
    return request, len(anchored), len(unanchored)
