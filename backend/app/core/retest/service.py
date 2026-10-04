"""Retest planning and verdicts (docs/BUILD_SPEC.md §26 Phase 9).

A retest answers one question an ordinary scan cannot: *is it gone?* A scan
that no longer reports a weakness looks identical to a scan whose probe never
got to try — both are silence — so a retest states up front which findings it
is checking, and afterwards gives each one a verdict it can defend.

Three verdicts, and the third is the important one:

* **reproduced** — this run found it again. The finding reopens.
* **not reproduced** — the probe that found it ran, and this time found
  nothing. That is evidence of a fix.
* **not tested** — the probe did not run, or the run halted. This is *not* a
  fix, and conflating it with one is how a platform tells an organization a
  weakness is closed when nobody looked.

The comparison is made on the §11 fingerprint, which is what makes it
possible at all: identity that survives varying response text, drifting line
numbers and changed request ids.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import record_event
from app.models.assessment_run import AssessmentRun
from app.models.finding import Finding, FindingStatus
from app.models.retest import RetestResult, RetestVerdict


@dataclass(frozen=True)
class BaselineEntry:
    """One finding as it stood when the retest was requested."""

    finding_id: str
    fingerprint: str
    probe_id: str
    evidence_ref: str | None
    severity: str
    status: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "probe_id": self.probe_id,
            "evidence_ref": self.evidence_ref,
            "severity": self.severity,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BaselineEntry":
        return cls(
            finding_id=str(raw.get("finding_id", "")),
            fingerprint=str(raw.get("fingerprint", "")),
            probe_id=str(raw.get("probe_id", "")),
            evidence_ref=raw.get("evidence_ref"),
            severity=str(raw.get("severity", "")),
            status=str(raw.get("status", "")),
        )


def baseline_of(findings: list[Finding]) -> list[dict[str, Any]]:
    """The snapshot a retest run stores before it starts.

    Taken before the run rather than read back afterwards, because the run
    overwrites the very fields a comparison needs: promotion updates a
    reproduced finding's `evidence_ref`, so "the digest from before" only
    exists if it was written down first.
    """
    return [
        BaselineEntry(
            finding_id=str(finding.id),
            fingerprint=finding.fingerprint,
            probe_id=finding.probe_id,
            evidence_ref=finding.evidence_ref,
            severity=finding.severity.value,
            status=finding.status.value,
        ).as_dict()
        for finding in findings
    ]


def mark_awaiting_retest(findings: list[Finding], user_id: uuid.UUID | None) -> list[Finding]:
    """Move findings whose remediation is claimed into `retest_required`.

    §11's lifecycle says a remediation is a claim until something checks it,
    and `remediated` leads nowhere except here. Requesting the retest is the
    moment that transition belongs to: after this, the finding's own state
    says a check is outstanding, which is true even if the run then fails.

    Findings in any other state are left alone. Something still
    `in_remediation` has not been claimed fixed, and a retest is welcome to
    look at it without the platform asserting progress nobody reported.
    """
    moved: list[Finding] = []
    for finding in findings:
        if finding.status is FindingStatus.REMEDIATED:
            finding.status = FindingStatus.RETEST_REQUIRED
            finding.status_changed_by_user_id = user_id
            moved.append(finding)
    return moved


async def record_retest(db: AsyncSession, *, run: AssessmentRun) -> list[RetestResult]:
    """Compare this retest run against its baseline and record the verdicts.

    Runs after promotion, so a finding this run saw again already carries
    `last_run_id == run.id`. That is the whole test for "reproduced": it uses
    the same promotion path every scan uses, rather than a second, parallel
    idea of what counts as the same weakness.
    """
    baseline = [BaselineEntry.from_dict(item) for item in (run.retest_baseline or []) if item]
    if not baseline:
        return []

    findings = {
        str(finding.id): finding
        for finding in (
            await db.execute(
                select(Finding)
                .where(
                    Finding.organization_id == run.organization_id,
                    Finding.id.in_([uuid.UUID(entry.finding_id) for entry in baseline]),
                )
                # The task is loaded with the finding because a verdict that
                # closes one closes the other, and a lazy load would raise on
                # an async session.
                .options(selectinload(Finding.remediation_task))
            )
        )
        .scalars()
        .all()
    }

    # Which probes actually executed, from the run's own record rather than
    # from what they reported. This distinction is the whole reason
    # `probes_executed` exists: a probe that ran and found nothing and a probe
    # that never ran are indistinguishable in the results table, and reading
    # the second as a fix is the worst mistake this workflow could make.
    #
    # An empty list means the run predates that record, and the comparison
    # fails closed: `not_tested` rather than an unearned `not_reproduced`.
    probes_that_ran = {str(item) for item in (run.probes_executed or [])}

    results: list[RetestResult] = []
    for entry in baseline:
        finding = findings.get(entry.finding_id)
        if finding is None:
            # Deleted between request and run. Recorded rather than skipped:
            # a retest that silently drops a row is a retest whose totals lie.
            results.append(
                _result(
                    run,
                    finding_id=uuid.UUID(entry.finding_id),
                    entry=entry,
                    verdict=RetestVerdict.NOT_TESTED,
                    after_evidence_ref=None,
                    detail="The finding no longer exists, so nothing was compared.",
                )
            )
            continue

        verdict, detail, after_ref = _verdict_for(entry, finding, run, probes_that_ran)
        await _apply(db, finding, verdict, run)
        results.append(
            _result(
                run,
                finding_id=finding.id,
                entry=entry,
                verdict=verdict,
                after_evidence_ref=after_ref,
                detail=detail,
            )
        )

    for result in results:
        db.add(result)
    return results


def _verdict_for(
    entry: BaselineEntry,
    finding: Finding,
    run: AssessmentRun,
    probes_that_ran: set[str],
) -> tuple[RetestVerdict, str, str | None]:
    if finding.last_run_id == run.id:
        return (
            RetestVerdict.REPRODUCED,
            (
                f"This run reported the same fingerprint again ({finding.fingerprint}). "
                f"Seen {finding.times_seen} time(s) in total."
            ),
            finding.evidence_ref,
        )

    if run.halted_reason:
        return (
            RetestVerdict.NOT_TESTED,
            (
                f"The run stopped early ({run.halted_reason}), so the absence of this "
                "finding says nothing about whether it was fixed."
            ),
            None,
        )

    if entry.probe_id not in probes_that_ran:
        return (
            RetestVerdict.NOT_TESTED,
            (
                f"{entry.probe_id} produced no result in this run — it did not apply to "
                "the target as configured, was refused by scope, or was held back by "
                "safe mode. Not looking is not a fix."
            ),
            None,
        )

    return (
        RetestVerdict.NOT_REPRODUCED,
        (
            f"{entry.probe_id} ran and did not report this fingerprint "
            f"({entry.fingerprint}). The weakness was not reproducible under the same "
            "conditions."
        ),
        None,
    )


async def _apply(
    db: AsyncSession, finding: Finding, verdict: RetestVerdict, run: AssessmentRun
) -> None:
    """Record the verdict on the finding, and close only what may be closed.

    `not_tested` never moves a status — that is the point of having it. And a
    `not_reproduced` closes only a finding that was explicitly awaiting a
    retest: a weakness someone is still working on has not been declared
    fixed by anybody, and the platform will not declare it for them.
    """
    finding.retest_result = verdict.value
    finding.last_retest_run_id = run.id

    if verdict is RetestVerdict.NOT_TESTED:
        return

    if verdict is RetestVerdict.NOT_REPRODUCED:
        if finding.status is FindingStatus.RETEST_REQUIRED:
            previous_status = finding.status
            finding.status = FindingStatus.CLOSED
            finding.status_note = f"Closed by retest {run.id}: not reproduced."
            if finding.remediation_task is not None:
                finding.remediation_task.closed_at = datetime.now(UTC)
            await _audit_auto_status_change(
                db, finding=finding, run=run, from_status=previous_status
            )
        return

    # Reproduced. Promotion has already reopened a remediated or closed
    # finding as confirmed; this covers the one it cannot, because
    # `retest_required` is not a state promotion treats as resolved.
    if finding.status is FindingStatus.RETEST_REQUIRED:
        previous_status = finding.status
        finding.status = FindingStatus.CONFIRMED
        finding.status_note = f"Reopened by retest {run.id}: still reproducible."
        await _audit_auto_status_change(db, finding=finding, run=run, from_status=previous_status)
    # The work is not done, so its task stays open even if something closed it
    # optimistically earlier.
    if finding.remediation_task is not None:
        finding.remediation_task.closed_at = None


async def _audit_auto_status_change(
    db: AsyncSession, *, finding: Finding, run: AssessmentRun, from_status: FindingStatus
) -> None:
    """The retest's own automatic status transitions, audited the same way
    `promote_run_results`'s auto-reopen now is: the platform made this
    call, not a person, so `user_id=None` says so rather than attributing
    it to whoever happened to request the retest."""
    await record_event(
        db,
        action="finding.status.auto_retest_verdict",
        resource_type="finding",
        resource_id=str(finding.id),
        result="allow",
        organization_id=run.organization_id,
        user_id=None,
        metadata={
            "from_status": from_status.value,
            "to_status": finding.status.value,
            "fingerprint": finding.fingerprint,
            "retest_run_id": str(run.id),
            "verdict": finding.retest_result,
        },
    )


def _result(
    run: AssessmentRun,
    *,
    finding_id: uuid.UUID,
    entry: BaselineEntry,
    verdict: RetestVerdict,
    after_evidence_ref: str | None,
    detail: str,
) -> RetestResult:
    return RetestResult(
        organization_id=run.organization_id,
        run_id=run.id,
        finding_id=finding_id,
        fingerprint=entry.fingerprint,
        verdict=verdict,
        before_evidence_ref=entry.evidence_ref,
        after_evidence_ref=after_evidence_ref,
        detail=detail,
    )
