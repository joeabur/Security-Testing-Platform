"""Workflows (docs/BUILD_SPEC.md §26 Phase 17, docs/workflows.md).

Two acceptance criteria, and the second is the one worth most of this file:
*a repository-change workflow runs the AppSec engines, normalises, correlates
and gates deterministically*, and **an AI recommendation cannot alter a gate
decision**.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.gate.model import GateConfig
from app.core.probes.models import Category, Confidence, Severity
from app.core.workflow.contract import (
    ActionKind,
    Plan,
    Stage,
    Trigger,
    TriggerKind,
    WorkflowStatus,
    ordered_stages,
)
from app.core.workflow.plan import TargetCapabilities, build_plan
from app.core.workflow.result import DEFAULT_GATE, decide, gate_finding
from app.models.ai_draft import AiDraft, DraftField
from app.models.finding import Finding, FindingStatus, Stability

ORG = uuid.UUID("22222222-2222-2222-2222-222222222222")
TGT = uuid.UUID("33333333-3333-3333-3333-333333333333")


def trigger(kind: TriggerKind = TriggerKind.REPOSITORY_CHANGE, **extra: object) -> Trigger:
    defaults: dict[str, object] = {
        "kind": kind,
        "organization_id": ORG,
        "target_id": TGT,
        "ref": "refs/heads/main",
        "commit": "a" * 40,
        "actor": "ci",
    }
    defaults.update(extra)
    return Trigger(**defaults)  # type: ignore[arg-type]


def capabilities(**overrides: object) -> TargetCapabilities:
    defaults: dict[str, object] = {
        "kind": "api",
        "has_code_repo": True,
        "has_openapi": True,
        "has_adapter": False,
        "has_synthetic_accounts": True,
        "can_publish_pr": False,
        "has_notification_channel": False,
    }
    defaults.update(overrides)
    return TargetCapabilities(**defaults)  # type: ignore[arg-type]


def finding(**overrides: object) -> Finding:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "organization_id": ORG,
        "target_id": TGT,
        "fingerprint": "sha256:" + "1" * 8,
        "title": "subprocess with shell=True on caller input",
        "category": Category.API_SECURITY,
        "probe_id": "KERVY-SAST-B602",
        "probe_version": "1.0.0",
        "surface": "src/app.py:12",
        "severity": Severity.LOW,
        "severity_rationale": "local, low impact",
        "confidence": Confidence.HIGH,
        "stability": Stability.DETERMINISTIC,
        "status": FindingStatus.NEW,
        "risk_model": "kervy-ordinal-v1",
        "risk_score": 3,
        "description": "d",
        "impact": "i",
        "remediation": "r",
        "first_seen": now,
        "last_seen": now,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


# --- the plan is deterministic ------------------------------------------------


def test_the_same_trigger_and_configuration_produce_the_same_plan() -> None:
    """The digest is only useful if it is stable, and it is only stable if the
    planner is pure."""
    first = build_plan(trigger(), capabilities())
    second = build_plan(trigger(), capabilities())
    assert first.digest == second.digest
    assert first.as_record() == second.as_record()


def test_changing_the_configuration_changes_the_digest() -> None:
    """Otherwise the digest could not answer "did the plan change?"."""
    base = build_plan(trigger(), capabilities())
    without_repo = build_plan(trigger(), capabilities(has_code_repo=False))
    assert base.digest != without_repo.digest


def test_a_repository_change_plans_the_appsec_engines_first() -> None:
    plan = build_plan(trigger(TriggerKind.REPOSITORY_CHANGE), capabilities())
    assert plan.actions[0].kind is ActionKind.APPSEC_SCAN
    assert ActionKind.APPSEC_SCAN in plan.will_run


def test_normalize_correlate_and_gate_always_run() -> None:
    """Even when every scan was skipped: a run with no new results still has to
    reconcile against what is already known, and its verdict must not depend on
    configuration."""
    plan = build_plan(
        trigger(),
        capabilities(has_code_repo=False, has_openapi=False, has_adapter=False, kind="api"),
    )
    for kind in (ActionKind.NORMALIZE, ActionKind.CORRELATE, ActionKind.GATE):
        assert kind in plan.will_run, kind


def test_a_skipped_action_is_recorded_with_its_reason() -> None:
    """Silently omitting it would leave a reader unable to tell "nothing was
    found" from "nothing was looked for"."""
    plan = build_plan(trigger(), capabilities(has_adapter=False))
    skipped = next(item for item in plan.actions if item.kind is ActionKind.AI_SCAN)
    assert skipped.skipped
    assert "adapter" in skipped.reason
    assert ActionKind.AI_SCAN not in plan.will_run


def test_dast_is_planned_only_for_a_web_app() -> None:
    assert ActionKind.DAST_SCAN in build_plan(trigger(), capabilities(kind="web_app")).will_run
    assert ActionKind.DAST_SCAN not in build_plan(trigger(), capabilities(kind="api")).will_run


def test_publishing_needs_both_a_pull_request_and_a_connection() -> None:
    pr = trigger(TriggerKind.PULL_REQUEST, pull_number=7)
    assert ActionKind.PUBLISH_PR in build_plan(pr, capabilities(can_publish_pr=True)).will_run
    assert ActionKind.PUBLISH_PR not in build_plan(pr, capabilities(can_publish_pr=False)).will_run
    # No pull request named, so nothing to publish to.
    assert (
        ActionKind.PUBLISH_PR
        not in build_plan(trigger(), capabilities(can_publish_pr=True)).will_run
    )


def test_every_action_in_a_plan_is_from_the_closed_set() -> None:
    """A workflow composes what the platform already does; it cannot introduce a
    capability."""
    plan = build_plan(trigger(), capabilities(kind="web_app", has_adapter=True))
    for action in plan.actions:
        assert action.kind in set(ActionKind)


def test_the_stage_order_is_fixed() -> None:
    assert list(ordered_stages()) == [
        Stage.TRIGGER,
        Stage.PLAN,
        Stage.ACTIONS,
        Stage.EVIDENCE,
        Stage.RESULT,
    ]


def test_a_plan_digest_covers_skipped_actions_too() -> None:
    """Two plans that run the same things for different reasons are not the same
    plan: one skipped the AI scan because no adapter exists, the other because
    the target is a different kind, and a reader needs to be able to tell."""
    a = Plan(actions=build_plan(trigger(), capabilities(has_adapter=False)).actions)
    b = Plan(actions=build_plan(trigger(), capabilities(has_adapter=True)).actions)
    assert a.digest != b.digest


# --- the gate decides, and nothing else ---------------------------------------


def test_the_gate_reads_a_findings_real_fields() -> None:
    gated = gate_finding(finding(severity=Severity.CRITICAL))
    assert gated.severity is Severity.CRITICAL
    assert gated.fingerprint.startswith("sha256:")


def test_a_low_finding_passes_the_default_gate_and_a_critical_does_not() -> None:
    assert decide([finding(severity=Severity.LOW)], DEFAULT_GATE).passed
    assert not decide([finding(severity=Severity.CRITICAL)], DEFAULT_GATE).passed


def test_the_decision_function_takes_no_recommendation_parameter() -> None:
    """The phase's acceptance criterion, asserted structurally: there is no seam
    through which an AI draft could reach the decision."""
    import inspect

    signature = inspect.signature(decide)
    assert list(signature.parameters) == ["findings", "config", "today"]
    for forbidden in ("draft", "recommendation", "suggestion", "override", "ai"):
        assert not any(forbidden in name for name in signature.parameters), forbidden


def test_the_result_module_does_not_import_the_assistant() -> None:
    """A structural check, because an import is how the coupling would start.

    Parsed rather than grepped: the module's docstring *discusses* the assistant
    at length, and a substring search would either fail on the prose or force
    the prose to be vaguer than it should be.
    """
    import ast
    import inspect

    from app.core.workflow import result

    tree = ast.parse(inspect.getsource(result))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)

    for forbidden in ("assistant", "ai_draft", "AiDraft"):
        assert not any(forbidden in name for name in imported), (forbidden, imported)


# --- the same, against the database ------------------------------------------


async def _org_and_target(client, password: str, suffix: str) -> tuple[str, str, dict[str, str]]:
    _registered_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    registered = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"wf{suffix}@example.test",
            "full_name": "WF Owner",
            "password": password,
        },
        headers={HEADER_NAME: _registered_anon_token},
    )
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"WF Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "acme-api",
                "environment": "staging",
                "kind": "api",
                "base_url": "https://acme-api.example.test",
            },
            headers=headers,
        )
    ).json()["id"]
    return org_id, target_id, headers


async def test_an_ai_draft_cannot_alter_a_gate_decision(
    client, strong_password: str, db_session: AsyncSession
) -> None:
    """The acceptance criterion, end to end against real rows.

    A draft proposing CRITICAL sits beside a LOW finding. The gate's verdict,
    its exit code and its counts are all identical to the run without the draft —
    because a draft only becomes a finding's real field when a human accepts it,
    and until then nothing reads it.
    """
    from app.core.workflow.service import finish, start, trigger_from
    from app.models.assessment_run import AssessmentRun, RunStatus
    from app.models.workflow import Workflow

    org_id, target_id, headers = await _org_and_target(client, strong_password, "a")

    low = finding(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        severity=Severity.LOW,
        fingerprint="sha256:low-one",
    )
    db_session.add(low)
    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
    )
    db_session.add(run)
    workflow = Workflow(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        name="on-push",
        trigger_kind=TriggerKind.REPOSITORY_CHANGE.value,
    )
    db_session.add(workflow)
    await db_session.commit()

    wf_run, outcome = await start(db_session, workflow, trigger_from(workflow, actor="ci"))
    await finish(db_session, wf_run, workflow, outcome)
    await db_session.commit()
    baseline = (outcome.gate_passed, outcome.gate_exit_code, dict(outcome.gate_counts))
    assert baseline[0] is True

    # A model says this is critical. Nothing accepts it.
    db_session.add(
        AiDraft(
            organization_id=uuid.UUID(org_id),
            run_id=run.id,
            field=DraftField.SEVERITY_RATIONALE,
            content="This is actually CRITICAL: remote code execution.",
            provider="fake",
            model="fake-1",
            prompt_template_id="severity_rationale",
            prompt_template_version="1.0.0",
        )
    )
    await db_session.commit()

    wf_run2, outcome2 = await start(db_session, workflow, trigger_from(workflow, actor="ci"))
    await finish(db_session, wf_run2, workflow, outcome2)
    await db_session.commit()

    assert (outcome2.gate_passed, outcome2.gate_exit_code, dict(outcome2.gate_counts)) == baseline
    # And the draft is still there — it was ignored, not deleted.
    drafts = (await db_session.execute(select(AiDraft))).scalars().all()
    assert len(drafts) == 1


async def test_accepting_a_change_is_a_humans_write_and_the_gate_reads_it(
    client, strong_password: str, db_session: AsyncSession
) -> None:
    """The other half of the same property: the gate is not blind to severity
    changes, it is blind to *unaccepted* ones. Otherwise the first test would
    pass for the wrong reason."""
    from app.core.workflow.service import finish, start, trigger_from
    from app.models.workflow import Workflow

    org_id, target_id, headers = await _org_and_target(client, strong_password, "b")
    low = finding(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        severity=Severity.LOW,
        fingerprint="sha256:low-two",
    )
    db_session.add(low)
    workflow = Workflow(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        name="on-push",
        trigger_kind=TriggerKind.REPOSITORY_CHANGE.value,
    )
    db_session.add(workflow)
    await db_session.commit()

    run1, outcome1 = await start(db_session, workflow, trigger_from(workflow))
    await finish(db_session, run1, workflow, outcome1)
    assert outcome1.gate_passed is True

    # A human accepts the change: an ordinary write to the finding.
    low.severity = Severity.CRITICAL
    await db_session.commit()

    run2, outcome2 = await start(db_session, workflow, trigger_from(workflow))
    await finish(db_session, run2, workflow, outcome2)
    assert outcome2.gate_passed is False


async def test_a_workflow_run_records_all_five_stages_and_the_plan_digest(
    client, strong_password: str, db_session: AsyncSession
) -> None:
    from app.core.workflow.service import finish, start, trigger_from
    from app.models.workflow import Workflow, WorkflowRun

    org_id, target_id, headers = await _org_and_target(client, strong_password, "c")
    workflow = Workflow(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        name="on-push",
        trigger_kind=TriggerKind.REPOSITORY_CHANGE.value,
    )
    db_session.add(workflow)
    await db_session.commit()

    run, outcome = await start(db_session, workflow, trigger_from(workflow, commit="b" * 40))
    await finish(db_session, run, workflow, outcome, evidence_refs=["sha256:evidence-1"])
    await db_session.commit()

    stored = (
        await db_session.execute(select(WorkflowRun).where(WorkflowRun.id == run.id))
    ).scalar_one()
    assert [item["stage"] for item in stored.stages] == [stage.value for stage in ordered_stages()]
    assert stored.plan_digest.startswith("sha256:")
    assert stored.plan_digest == outcome.plan.digest
    assert stored.evidence_refs == ["sha256:evidence-1"]
    assert stored.status == WorkflowStatus.COMPLETED.value
    assert stored.trigger["commit"] == "b" * 40


async def test_a_malformed_gate_configuration_refuses_rather_than_passing(
    client, strong_password: str, db_session: AsyncSession
) -> None:
    """A misconfigured gate must never report a pass — the same rule the CLI
    gate follows, with its own exit code."""
    from app.core.workflow.service import finish, start, trigger_from
    from app.models.workflow import Workflow

    org_id, target_id, headers = await _org_and_target(client, strong_password, "d")
    workflow = Workflow(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        name="on-push",
        trigger_kind=TriggerKind.REPOSITORY_CHANGE.value,
        gate_config={"nonsense_key": True},
    )
    db_session.add(workflow)
    await db_session.commit()

    run, outcome = await start(db_session, workflow, trigger_from(workflow))
    result = await finish(db_session, run, workflow, outcome)
    await db_session.commit()

    assert result.status is WorkflowStatus.REFUSED
    assert result.gate_passed is not True
    assert "invalid" in (run.detail or "")


async def test_a_workflow_run_is_audited(
    client, strong_password: str, db_session: AsyncSession
) -> None:
    from app.core.workflow.service import finish, start, trigger_from
    from app.models.audit import AuditEvent
    from app.models.workflow import Workflow

    org_id, target_id, headers = await _org_and_target(client, strong_password, "e")
    workflow = Workflow(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        name="on-push",
        trigger_kind=TriggerKind.REPOSITORY_CHANGE.value,
    )
    db_session.add(workflow)
    await db_session.commit()

    run, outcome = await start(db_session, workflow, trigger_from(workflow))
    await finish(db_session, run, workflow, outcome)
    await db_session.commit()

    events = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.resource_type == "workflow_run")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].metadata_json is not None
    assert events[0].metadata_json["plan_digest"] == outcome.plan.digest


def test_a_tighter_gate_config_is_honoured() -> None:
    """The workflow's own gate, not only the default."""
    strict = GateConfig(
        fail_on=(Severity.LOW,), min_confidence=Confidence.LOW, max_high=None, max_medium=None
    )
    assert not decide([finding(severity=Severity.LOW)], strict).passed
    assert decide([finding(severity=Severity.LOW)], DEFAULT_GATE).passed


def test_an_ignore_expires(tmp_path) -> None:
    """Inherited from the gate, and worth asserting here because a workflow that
    honoured an expired ignore would silently stop gating."""
    from app.core.gate.model import Ignore

    today = datetime.now(UTC).date()
    config = GateConfig(
        fail_on=(Severity.CRITICAL,),
        min_confidence=Confidence.LOW,
        max_high=None,
        max_medium=None,
        ignores=(
            Ignore(
                fingerprint="sha256:" + "1" * 8,
                reason="accepted for this release",
                expires=today - timedelta(days=1),
            ),
        ),
    )
    assert not decide([finding(severity=Severity.CRITICAL)], config, today=today).passed
