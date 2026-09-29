"""The five stages, and what each is allowed to depend on.

A workflow is the shape this platform already had, made explicit and stored:
something happens, a plan is derived from it, actions run, evidence is sealed,
and a result is decided. Writing it down as five stages buys two things.

**A plan you can read before it runs.** The plan is derived from the trigger and
the target's configuration and nothing else, so the same trigger against the
same configuration produces the same plan. That is what makes "why did this
run the AppSec engines but not the AI probes?" answerable from a stored record
rather than from logs.

**A result that cannot be argued with.** The result comes from `gate.evaluate`
over findings — the same function the CI gate uses, so a workflow and a pipeline
cannot disagree about the same findings. Crucially, `evaluate` reads
`GateFinding`s built from a finding's **real fields**. AI drafts live in a
separate table and are never read here. That is not a policy the code asks
nicely about: there is no code path from `ai_drafts` into the result stage, and
`tests/test_workflow.py` asserts that a draft proposing a different severity
changes nothing about the decision.

The stages are deliberately not a general workflow engine. There is no
branching, no user-defined steps, no expression language. A plan is a list of
actions this platform already knows how to run, and that limitation is what
keeps the result deterministic.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum


class Stage(StrEnum):
    TRIGGER = "trigger"
    PLAN = "plan"
    ACTIONS = "actions"
    EVIDENCE = "evidence"
    RESULT = "result"


class TriggerKind(StrEnum):
    """What can start a workflow.

    `REPOSITORY_CHANGE` is the one §26 Phase 17 names explicitly. `MANUAL` is
    how a human re-runs one. `SCHEDULE` is fired by Celery Beat
    (pentest-module Phase 8; `app/workers/tasks.py::dispatch_scheduled_workflows`).
    There is no separate `WEBHOOK` kind: an inbound webhook produces a
    `REPOSITORY_CHANGE` or `PULL_REQUEST` trigger, the same as always — what
    Phase 8 added is the authenticated, replay-protected acceptance endpoint
    (`app/api/v1/routers/webhooks.py`), not a new trigger vocabulary. See
    `Trigger.unattended` for how a trigger with no human present at the call
    is distinguished from one where a human is.
    """

    REPOSITORY_CHANGE = "repository_change"
    PULL_REQUEST = "pull_request"
    SCHEDULE = "schedule"
    MANUAL = "manual"


class ActionKind(StrEnum):
    """Actions a plan may contain.

    A closed set, on purpose. A workflow cannot introduce a new capability —
    it composes what the platform already does, under the same scope engine and
    the same authorization.
    """

    APPSEC_SCAN = "appsec_scan"
    API_SCAN = "api_scan"
    AI_SCAN = "ai_scan"
    DAST_SCAN = "dast_scan"
    NORMALIZE = "normalize"
    CORRELATE = "correlate"
    GATE = "gate"
    NOTIFY = "notify"
    PUBLISH_PR = "publish_pr"


# The actions an *unattended* trigger (Celery Beat, the inbound webhook) may
# never queue without a human's explicit approval first — they touch a
# target or write externally. `NOTIFY`/`CORRELATE`/`GATE`/`NORMALIZE` never
# gate, even when unattended: they act only on findings that already exist.
# Mirrors `app.core.assistant.autonomy.TARGET_TOUCHING`'s idiom: a closed set
# checked independently of any configuration, so no setting can grant it.
UNATTENDED_APPROVAL_ACTIONS = frozenset(
    {
        ActionKind.APPSEC_SCAN,
        ActionKind.API_SCAN,
        ActionKind.AI_SCAN,
        ActionKind.DAST_SCAN,
        ActionKind.PUBLISH_PR,
    }
)


class WorkflowStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUSED = "refused"
    #: An unattended trigger (Celery Beat or the inbound webhook) whose plan
    #: would queue a scan-touching action. Never reached by a trigger a human
    #: made themselves — see `Trigger.unattended` and `UNATTENDED_APPROVAL_ACTIONS`.
    AWAITING_APPROVAL = "awaiting_approval"


@dataclass(frozen=True)
class Trigger:
    """What happened. Scalar fields only — a trigger is a fact, not a payload.

    `ref` and `commit` are what a repository change carries; both optional
    because a scheduled or manual trigger has neither.
    """

    kind: TriggerKind
    organization_id: uuid.UUID
    target_id: uuid.UUID
    ref: str | None = None
    commit: str | None = None
    pull_number: int | None = None
    actor: str = "system"
    #: True when no human was present at the moment of this specific call —
    #: Celery Beat or the inbound webhook, never a manual API/CLI/agent-tool
    #: call (even one that re-runs a `SCHEDULE`-kind workflow: a human
    #: calling the API *is* present for that call). This, not `kind`, is
    #: what `start_and_maybe_pause` checks before queuing a scan.
    unattended: bool = False

    def as_record(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "target_id": str(self.target_id),
            "ref": self.ref,
            "commit": self.commit,
            "pull_number": self.pull_number,
            "actor": self.actor,
            "unattended": self.unattended,
        }


@dataclass(frozen=True)
class PlannedAction:
    kind: ActionKind
    reason: str
    #: Why an action is *absent* matters as much as why one is present, so a
    #: skipped action is recorded with its reason rather than omitted.
    skipped: bool = False

    def as_record(self) -> dict[str, object]:
        return {"kind": self.kind.value, "reason": self.reason, "skipped": self.skipped}


@dataclass(frozen=True)
class Plan:
    """What will run, and why each thing will or will not.

    `digest` is over the ordered action list, so two plans are equal exactly
    when they would do the same things. It is stored on the run, which is what
    makes "did the plan change between these two commits?" a comparison rather
    than an investigation.
    """

    actions: tuple[PlannedAction, ...]

    @property
    def will_run(self) -> tuple[ActionKind, ...]:
        return tuple(action.kind for action in self.actions if not action.skipped)

    @property
    def digest(self) -> str:
        body = json.dumps([action.as_record() for action in self.actions], sort_keys=True)
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()

    def as_record(self) -> dict[str, object]:
        return {
            "actions": [action.as_record() for action in self.actions],
            "digest": self.digest,
        }


@dataclass
class StageRecord:
    """One stage's outcome, in the order the stages ran."""

    stage: Stage
    ok: bool
    detail: str
    data: Mapping[str, object] = field(default_factory=dict)

    def as_record(self) -> dict[str, object]:
        return {
            "stage": self.stage.value,
            "ok": self.ok,
            "detail": self.detail,
            "data": dict(self.data),
        }


@dataclass
class WorkflowOutcome:
    """Everything the run decided, ready to persist."""

    status: WorkflowStatus
    plan: Plan
    stages: list[StageRecord] = field(default_factory=list)
    #: Evidence bundle references sealed during this workflow, so the result is
    #: traceable to what was observed.
    evidence_refs: list[str] = field(default_factory=list)
    #: The gate's own decision, verbatim. Never edited by a later stage.
    gate_passed: bool | None = None
    gate_exit_code: int | None = None
    gate_reasons: list[str] = field(default_factory=list)
    gate_counts: Mapping[str, int] = field(default_factory=dict)

    def record(self, stage: Stage, *, ok: bool, detail: str, **data: object) -> None:
        self.stages.append(StageRecord(stage=stage, ok=ok, detail=detail, data=data))

    def stage(self, stage: Stage) -> StageRecord | None:
        for item in self.stages:
            if item.stage is stage:
                return item
        return None

    def as_record(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "plan": self.plan.as_record(),
            "stages": [item.as_record() for item in self.stages],
            "evidence_refs": list(self.evidence_refs),
            "gate": {
                "passed": self.gate_passed,
                "exit_code": self.gate_exit_code,
                "reasons": list(self.gate_reasons),
                "counts": dict(self.gate_counts),
            },
        }


def ordered_stages() -> Sequence[Stage]:
    """The fixed order. There is no branching — see the module docstring."""
    return (Stage.TRIGGER, Stage.PLAN, Stage.ACTIONS, Stage.EVIDENCE, Stage.RESULT)
