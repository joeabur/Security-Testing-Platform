"""Running a workflow and recording every stage.

The thin, database-aware half. The decisions live in `plan.py` (pure) and
`result.py` (the gate); this module reads the target's configuration, drives the
stages in order, and writes what happened.

A workflow **does not gain capabilities**. It queues the same assessment run the
API queues, under the same authorization check and the same scope engine. If
that check refuses, the workflow is refused — recorded as `REFUSED` with the
reason, rather than failed, because "we were not authorized to do this" and "we
tried and it broke" are different facts about the same run.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.core.gate.evaluate import load_config
from app.core.gate.model import GateConfig, GateConfigError
from app.core.runs.service import queue_run
from app.core.workflow.contract import (
    UNATTENDED_APPROVAL_ACTIONS,
    ActionKind,
    Plan,
    PlannedAction,
    Stage,
    StageRecord,
    Trigger,
    TriggerKind,
    WorkflowOutcome,
    WorkflowStatus,
)
from app.core.workflow.plan import TargetCapabilities, build_plan
from app.core.workflow.result import DEFAULT_GATE, decide
from app.models.api_spec import ApiSpec
from app.models.assessment_run import AssessmentRun
from app.models.finding import Finding
from app.models.integration import NotificationChannel
from app.models.synthetic_account import SyntheticAccount
from app.models.target import Target
from app.models.vcs import VcsConnection
from app.models.workflow import Workflow, WorkflowRun

#: A workflow's scan profile/mode when automation queues one on its behalf.
#: Matches `RunCreate`'s own defaults (`app/schemas/run.py`) — automation
#: gains no capability a human triggering the same workflow would not
#: already have.
_AUTOMATED_SCAN_PROFILE = "connectivity"
_AUTOMATED_SAFE_MODE = True


async def capabilities_for(
    db: AsyncSession, target: Target, *, trigger: Trigger
) -> TargetCapabilities:
    """Read what this target is actually configured for.

    Queried rather than inferred: a plan that guessed would produce a digest
    that did not describe what ran.
    """
    has_openapi = (
        await db.execute(select(ApiSpec.id).where(ApiSpec.target_id == target.id).limit(1))
    ).scalar_one_or_none() is not None
    has_accounts = (
        await db.execute(
            select(SyntheticAccount.id).where(SyntheticAccount.target_id == target.id).limit(1)
        )
    ).scalar_one_or_none() is not None
    has_channel = (
        await db.execute(
            select(NotificationChannel.id)
            .where(
                NotificationChannel.organization_id == target.organization_id,
                NotificationChannel.enabled.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none() is not None
    has_vcs = (
        await db.execute(
            select(VcsConnection.id)
            .where(
                VcsConnection.organization_id == target.organization_id,
                VcsConnection.enabled.is_(True),
            )
            .limit(1)
        )
    ).scalar_one_or_none() is not None

    return TargetCapabilities(
        kind=str(getattr(target.kind, "value", target.kind)),
        has_code_repo=bool(target.code_repo_ref),
        has_openapi=has_openapi,
        has_adapter=bool(target.adapter_kind),
        has_synthetic_accounts=has_accounts,
        can_publish_pr=has_vcs and trigger.pull_number is not None,
        has_notification_channel=has_channel,
    )


def gate_config_for(workflow: Workflow) -> GateConfig:
    """The workflow's gate, or the documented default.

    A malformed stored configuration is **not** silently replaced by the
    default: the gate's own rule is that a misconfigured gate must never report
    a pass, so it raises and the workflow is refused.
    """
    if not workflow.gate_config:
        return DEFAULT_GATE
    import json

    return load_config(json.dumps(workflow.gate_config))


async def findings_for(
    db: AsyncSession, organization_id: uuid.UUID, target_id: uuid.UUID
) -> Sequence[Finding]:
    result = await db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id, Finding.target_id == target_id
        )
    )
    return list(result.scalars().all())


async def plan_for(db: AsyncSession, workflow: Workflow, trigger: Trigger) -> Plan:
    target = await db.get(Target, workflow.target_id)
    if target is None:
        raise ValueError("workflow target no longer exists")
    return build_plan(trigger, await capabilities_for(db, target, trigger=trigger))


async def start(
    db: AsyncSession,
    workflow: Workflow,
    trigger: Trigger,
) -> tuple[WorkflowRun, WorkflowOutcome]:
    """Record the trigger and the plan, and evaluate the result.

    Scan actions are *planned* here but executed by the assessment worker; this
    function records the plan, runs the stages it owns, and decides. Wiring the
    scan execution itself is done by the caller queueing an assessment run —
    which keeps one code path for "run an assessment" rather than two.
    """
    plan = await plan_for(db, workflow, trigger)
    outcome = WorkflowOutcome(status=WorkflowStatus.RUNNING, plan=plan)
    outcome.record(
        Stage.TRIGGER,
        ok=True,
        detail=f"{trigger.kind.value} by {trigger.actor}",
        **trigger.as_record(),
    )
    outcome.record(
        Stage.PLAN,
        ok=True,
        detail=f"{len(plan.will_run)} action(s) will run, "
        f"{len(plan.actions) - len(plan.will_run)} skipped",
        digest=plan.digest,
    )

    run = WorkflowRun(
        organization_id=workflow.organization_id,
        workflow_id=workflow.id,
        status=WorkflowStatus.RUNNING.value,
        trigger=trigger.as_record(),
        plan=plan.as_record(),
        plan_digest=plan.digest,
        stages=[item.as_record() for item in outcome.stages],
        evidence_refs=[],
        gate_reasons=[],
        gate_counts={},
        started_at=datetime.now(UTC),
    )
    db.add(run)
    await db.flush()
    return run, outcome


async def finish(
    db: AsyncSession,
    run: WorkflowRun,
    workflow: Workflow,
    outcome: WorkflowOutcome,
    *,
    evidence_refs: Sequence[str] = (),
    actions_detail: str = "",
) -> WorkflowOutcome:
    """Run the evidence and result stages, then persist everything."""
    outcome.record(
        Stage.ACTIONS,
        ok=True,
        detail=actions_detail or "actions completed",
    )
    outcome.evidence_refs = list(evidence_refs)
    outcome.record(
        Stage.EVIDENCE,
        ok=True,
        detail=f"{len(outcome.evidence_refs)} evidence bundle(s) sealed",
    )

    try:
        config = gate_config_for(workflow)
    except GateConfigError as exc:
        # A misconfigured gate must never report a pass.
        outcome.status = WorkflowStatus.REFUSED
        outcome.record(Stage.RESULT, ok=False, detail=f"gate configuration is invalid: {exc}")
        run.detail = f"gate configuration is invalid: {exc}"[:500]
        await _persist(db, run, outcome)
        return outcome

    findings = await findings_for(db, workflow.organization_id, workflow.target_id)
    decision = decide(findings, config)

    outcome.gate_passed = decision.passed
    outcome.gate_exit_code = int(decision.exit_code)
    outcome.gate_reasons = list(decision.reasons)
    outcome.gate_counts = dict(decision.counts)
    outcome.status = WorkflowStatus.COMPLETED
    outcome.record(
        Stage.RESULT,
        ok=decision.passed,
        detail="gate passed" if decision.passed else "; ".join(decision.reasons),
        blocking=len(decision.blocking),
        excluded=len(decision.excluded),
    )

    await _persist(db, run, outcome)
    await record_event(
        db,
        action="workflow.completed" if decision.passed else "workflow.gate_failed",
        resource_type="workflow_run",
        resource_id=str(run.id),
        result="allow" if decision.passed else "deny",
        organization_id=workflow.organization_id,
        metadata={
            "workflow": workflow.name,
            "trigger": run.trigger.get("kind"),
            "plan_digest": run.plan_digest,
            "gate_passed": decision.passed,
            "counts": dict(decision.counts),
        },
    )
    return outcome


async def _persist(db: AsyncSession, run: WorkflowRun, outcome: WorkflowOutcome) -> None:
    run.status = outcome.status.value
    run.stages = [item.as_record() for item in outcome.stages]
    run.evidence_refs = list(outcome.evidence_refs)
    run.gate_passed = outcome.gate_passed
    run.gate_exit_code = outcome.gate_exit_code
    run.gate_reasons = list(outcome.gate_reasons)
    run.gate_counts = dict(outcome.gate_counts)
    run.finished_at = datetime.now(UTC)
    await db.flush()


def trigger_from(
    workflow: Workflow,
    *,
    ref: str | None = None,
    commit: str | None = None,
    pull_number: int | None = None,
    actor: str = "system",
    kind: TriggerKind | None = None,
    unattended: bool = False,
) -> Trigger:
    """`kind` defaults to the workflow's own configured trigger kind — the
    manual-API and agent-tool call sites that always pass `unattended=False`
    (its own default) rely on this. The inbound webhook endpoint is the one
    caller that overrides `kind` explicitly, since an accepted delivery
    names its own event kind rather than reading the workflow's static
    configuration."""
    return Trigger(
        kind=kind or TriggerKind(workflow.trigger_kind),
        organization_id=workflow.organization_id,
        target_id=workflow.target_id,
        ref=ref,
        commit=commit,
        pull_number=pull_number,
        actor=actor,
        unattended=unattended,
    )


async def queue_scan_for_workflow_run(
    db: AsyncSession, run: WorkflowRun, workflow: Workflow, plan: Plan, *, user_id: uuid.UUID
) -> AssessmentRun | None:
    """Queue the scan a plan calls for, through the exact same path
    `POST /runs` and the agent's `start_scan` tool already use — never a
    second, parallel way to start one. Returns `None`, queuing nothing,
    when the plan has no scan-touching action at all (a workflow that only
    correlates or notifies over findings that already exist)."""
    if not (set(plan.will_run) & UNATTENDED_APPROVAL_ACTIONS):
        return None
    target = await db.get(Target, workflow.target_id)
    if target is None:
        raise ValueError("workflow target no longer exists")
    assessment_run = await queue_run(
        db,
        organization_id=workflow.organization_id,
        target=target,
        user_id=user_id,
        profile=_AUTOMATED_SCAN_PROFILE,
        safe_mode=_AUTOMATED_SAFE_MODE,
        confirmed_at=datetime.now(UTC),
    )
    run.assessment_run_id = assessment_run.id
    await db.flush()
    return assessment_run


async def start_and_maybe_pause(
    db: AsyncSession,
    workflow: Workflow,
    trigger: Trigger,
) -> tuple[WorkflowRun, WorkflowOutcome]:
    """`start()`'s own contract, plus the approval gate: an *unattended*
    trigger (Celery Beat, the inbound webhook — never a human calling the
    API) whose plan would queue a scan-touching action pauses here rather
    than proceeding. A human calling `POST /workflows/{id}/runs` (or the
    `RUN_WORKFLOW` agent tool) never pauses — their own authenticated,
    role-checked call *is* the approval, exactly as today.

    An attended trigger, or an unattended one whose plan has nothing to
    approve, behaves exactly like `start()` always has: this function does
    not queue a scan or gate anything itself either way — that split stays
    with `queue_scan_for_workflow_run`/`finish`, called separately once a
    run is not (or no longer) paused.
    """
    run, outcome = await start(db, workflow, trigger)
    if trigger.unattended and (set(outcome.plan.will_run) & UNATTENDED_APPROVAL_ACTIONS):
        run.status = WorkflowStatus.AWAITING_APPROVAL.value
        run.detail = (
            "awaiting human approval before queuing a scan-touching action "
            f"triggered by {trigger.actor}"
        )[:500]
        await db.flush()
    return run, outcome


def _plan_from_record(record: dict[str, object]) -> Plan:
    """The inverse of `Plan.as_record()` — reloads a stored run's plan so a
    resumed/gated run can check `plan.will_run` without recomputing it (the
    stored plan is the one the operator actually saw and approved; deriving
    a fresh one here could theoretically disagree with it if the target's
    configuration changed in between)."""
    actions_data = record.get("actions", [])
    assert isinstance(actions_data, list)
    actions = tuple(
        PlannedAction(
            kind=ActionKind(action["kind"]),
            reason=action["reason"],
            skipped=action["skipped"],
        )
        for action in actions_data
    )
    return Plan(actions=actions)


def _outcome_from_run(run: WorkflowRun) -> WorkflowOutcome:
    """Reconstruct the in-memory `WorkflowOutcome` a freshly-loaded run's
    stored `plan`/`stages` describe, so `finish()` can append its own
    ACTIONS/EVIDENCE/RESULT stages onto the TRIGGER/PLAN ones `start()`
    already persisted rather than overwriting them — `_persist()` replaces
    `run.stages` wholesale with whatever `outcome.stages` holds at that
    point."""
    stages = [
        StageRecord(
            stage=Stage(record["stage"]),
            ok=record["ok"],
            detail=record["detail"],
            data=record.get("data", {}),
        )
        for record in run.stages
    ]
    return WorkflowOutcome(
        status=WorkflowStatus.RUNNING, plan=_plan_from_record(run.plan), stages=stages
    )


async def gate_run_once_scan_finished(
    db: AsyncSession, run: WorkflowRun, workflow: Workflow
) -> WorkflowOutcome:
    """Called once the assessment run `queue_scan_for_workflow_run` queued
    reaches a terminal state (`app/workers/tasks.py::gate_workflow_run_if_linked`)
    — the exact same `finish()` a manual trigger's synchronous call already
    uses, over the findings that scan just produced."""
    outcome = _outcome_from_run(run)
    return await finish(db, run, workflow, outcome, actions_detail="scan completed")


async def approve(
    db: AsyncSession, run: WorkflowRun, workflow: Workflow, *, approved_by_user_id: uuid.UUID
) -> WorkflowRun:
    """Resume a paused run: queue the scan the plan called for, attributed
    to the human who approved it — `queue_run`'s own `user_id` requirement
    is what makes this approval meaningful rather than a formality; see the
    module-level note in `queue_scan_for_workflow_run`. Gating happens
    later, asynchronously, once that scan reaches a terminal state
    (`app/workers/tasks.py::gate_workflow_run_if_linked`) — this function
    does not gate anything itself.
    """
    if run.status != WorkflowStatus.AWAITING_APPROVAL.value:
        raise ValueError(f"run is not awaiting approval (status: {run.status})")
    plan = _plan_from_record(run.plan)
    await queue_scan_for_workflow_run(db, run, workflow, plan, user_id=approved_by_user_id)
    run.status = WorkflowStatus.RUNNING.value
    run.approved_by_user_id = approved_by_user_id
    run.approved_at = datetime.now(UTC)
    await db.flush()
    await record_event(
        db,
        action="workflow_run.approved",
        resource_type="workflow_run",
        resource_id=str(run.id),
        result="allow",
        organization_id=workflow.organization_id,
        user_id=approved_by_user_id,
        metadata={"workflow": workflow.name, "plan_digest": run.plan_digest},
    )
    return run


async def reject(
    db: AsyncSession,
    run: WorkflowRun,
    workflow: Workflow,
    *,
    rejected_by_user_id: uuid.UUID,
    reason: str,
) -> WorkflowRun:
    if run.status != WorkflowStatus.AWAITING_APPROVAL.value:
        raise ValueError(f"run is not awaiting approval (status: {run.status})")
    run.status = WorkflowStatus.REFUSED.value
    run.detail = reason[:500]
    run.finished_at = datetime.now(UTC)
    await db.flush()
    await record_event(
        db,
        action="workflow_run.rejected",
        resource_type="workflow_run",
        resource_id=str(run.id),
        result="deny",
        organization_id=workflow.organization_id,
        user_id=rejected_by_user_id,
        metadata={"workflow": workflow.name, "plan_digest": run.plan_digest, "reason": reason},
    )
    return run
