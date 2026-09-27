"""Celery tasks. Thin wrappers over `core/` — the lifecycle logic lives in
`app/core/orchestrator/runner.py` and is unit-tested without Celery or a
broker; `execute_assessment_run` below is the async implementation the task
delegates to, and tests call it directly.
"""

import asyncio
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.appsec.checkout import (
    CheckoutError,
    check_host_allowed,
    clone_repository,
    discard_checkout,
    make_checkout_dir,
    parse_repo_ref,
)
from app.core.appsec.registry import appsec_engines
from app.core.appsec.workspace import CodeScopeError
from app.core.config import get_settings
from app.core.dast.contract import DastTarget
from app.core.evidence.store import EvidenceError, EvidenceStore
from app.core.findings.service import promote_run_results
from app.core.orchestrator.ai_check import AiSecurityCheck
from app.core.orchestrator.checks import Check, Endpoint, ReachabilityCheck
from app.core.orchestrator.code_check import CodeScanCheck
from app.core.orchestrator.context_builder import (
    build_ai_probe_target,
    build_conversational_adapter,
    build_probe_target,
    build_run_context,
    build_workspace,
)
from app.core.orchestrator.dast_check import DastCheck
from app.core.orchestrator.plugin_check import PluginCheck
from app.core.orchestrator.probe_check import ProbeCheck
from app.core.orchestrator.runner import RunEventPayload, execute_run
from app.core.probes.api.registry import build_api_registry
from app.core.probes.models import ScanResult, Severity
from app.core.rasp.contract import RuntimeProtectionProfile, untested_marker
from app.core.retest.service import record_retest
from app.core.scope.errors import AuthorizationRequiredError, RoEValidationError
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.transport import GatedTransport
from app.db.session import dispose_engine, get_session_factory
from app.db.tenant_context import set_current_organization
from app.models.assessment_run import (
    AssessmentRun,
    RunEvent,
    RunEventKind,
    RunKind,
    RunStatus,
)
from app.models.retest import RetestVerdict
from app.models.scan_result import ScanResultRecord
from app.models.surface_endpoint import SurfaceEndpoint
from app.models.synthetic_account import SyntheticAccount
from app.models.target import Target, TargetKind
from app.plugins.allowlist import policy_from_settings
from app.plugins.contract import PluginKind
from app.plugins.registry import discover
from app.workers.cancellation import is_cancellation_requested
from app.workers.celery_app import celery_app

logger = structlog.get_logger()


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _record_event(
    db: AsyncSession, run_id: uuid.UUID, kind: RunEventKind, message: str, payload: dict[str, Any]
) -> None:
    db.add(RunEvent(run_id=run_id, kind=kind, message=message[:1000], payload=payload or None))
    await db.commit()


async def _load_run(db: AsyncSession, run_id: uuid.UUID) -> AssessmentRun | None:
    result = await db.execute(
        select(AssessmentRun)
        .where(AssessmentRun.id == run_id)
        .options(
            selectinload(AssessmentRun.target).selectinload(Target.authorization),
            selectinload(AssessmentRun.target).selectinload(Target.rules_of_engagement),
            # Loaded eagerly because the findings service reads it to judge
            # exposure, and a lazy load in the async worker raises rather
            # than quietly fetching.
            selectinload(AssessmentRun.target).selectinload(Target.surface_endpoints),
        )
    )
    return result.scalar_one_or_none()


async def _enabled_endpoint_rows(db: AsyncSession, target_id: uuid.UUID) -> list[SurfaceEndpoint]:
    result = await db.execute(
        select(SurfaceEndpoint)
        .where(SurfaceEndpoint.target_id == target_id, SurfaceEndpoint.enabled.is_(True))
        .order_by(SurfaceEndpoint.path, SurfaceEndpoint.method)
    )
    return list(result.scalars().all())


async def _synthetic_accounts(db: AsyncSession, target_id: uuid.UUID) -> list[SyntheticAccount]:
    result = await db.execute(
        select(SyntheticAccount)
        .where(SyntheticAccount.target_id == target_id)
        .order_by(SyntheticAccount.label)
    )
    return list(result.scalars().all())


def _store_evidence(run_id: uuid.UUID, result: ScanResult) -> str | None:
    """Write this result's exchange to the evidence store, if it has one.

    A failure here must not lose the result. The finding is still true
    without its bundle, and a run that threw away nine good findings because
    the evidence directory was read-only would be a worse outcome than one
    whose findings say "no evidence stored". The failure is logged rather
    than swallowed silently.
    """
    if result.evidence_bundle is None:
        return None
    settings = get_settings()
    store = EvidenceStore(Path(settings.evidence_root), key=settings.evidence_encryption_key_bytes)
    try:
        return store.write(str(run_id), result.evidence_bundle)
    except (EvidenceError, OSError) as exc:
        logger.warning(
            "evidence.write_failed", run_id=str(run_id), probe_id=result.probe_id, error=str(exc)
        )
        return None


async def _persist_scan_results(
    db: AsyncSession,
    run_id: uuid.UUID,
    organization_id: uuid.UUID,
    results: list[ScanResult],
) -> None:
    for result in results:
        evidence_ref = await asyncio.to_thread(_store_evidence, run_id, result)
        db.add(
            ScanResultRecord(
                run_id=run_id,
                organization_id=organization_id,
                result_code=result.id,
                title=result.title[:300],
                category=result.category,
                severity=result.severity,
                confidence=result.confidence,
                endpoint=result.endpoint[:2048],
                description=result.description,
                evidence=result.evidence,
                impact=result.impact,
                remediation=result.remediation,
                probe_id=result.probe_id,
                probe_version=result.probe_version,
                frameworks=list(result.frameworks),
                reproduction=list(result.reproduction),
                fingerprint=result.fingerprint,
                measurement=result.measurement,
                stability=result.stability,
                evidence_ref=evidence_ref,
            )
        )
    await db.commit()


async def execute_assessment_run(
    run_id: uuid.UUID, transport: GatedTransport | None = None
) -> RunStatus:
    """Run one assessment to a terminal state, persisting progress as it goes.

    `transport` exists so tests can inject a resolver-and-network double; in
    production it is always the default `GatedTransport`, which is still the
    only path to the network either way.
    """
    session_factory = get_session_factory()

    async with session_factory() as db:
        run = await _load_run(db, run_id)
        if run is None:
            logger.warning("run_not_found", run_id=str(run_id))
            return RunStatus.FAILED
        if run.status not in {RunStatus.QUEUED, RunStatus.DRAFT}:
            # Already started, finished, or cancelled before the worker picked
            # it up — never restart a run that has left the queue.
            return run.status

        # Row-Level Security (app/db/tenant_context.py): every query this
        # task makes from here on, including the ones already issued above
        # to load `run` itself, needs the organization set for the *next*
        # transaction this session opens — set as soon as the run's
        # organization is known.
        set_current_organization(run.organization_id)

        target = run.target

        try:
            ctx = build_run_context(target)
        except (AuthorizationRequiredError, RoEValidationError) as exc:
            run.status = RunStatus.FAILED
            run.error_message = str(exc)
            run.finished_at = datetime.now(UTC)
            await db.commit()
            await _record_event(db, run.id, RunEventKind.FAILED, str(exc), {})
            return RunStatus.FAILED

        # The switch latches, so a cancellation requested at any point stops
        # the run at the next scope check rather than at the next check boundary.
        ctx.kill_switch = KillSwitch(probe=lambda: is_cancellation_requested(str(run_id)))

        endpoint_rows = await _enabled_endpoint_rows(db, target.id)
        accounts = await _synthetic_accounts(db, target.id)
        probe_target = build_probe_target(target, endpoint_rows, accounts, safe_mode=run.safe_mode)
        probe_check = ProbeCheck(build_api_registry(), probe_target)
        checks: list[Check] = [
            ReachabilityCheck(
                target.base_url,
                [Endpoint(method=row.method, path=row.path) for row in endpoint_rows],
            ),
            probe_check,
        ]

        # The AI engine only runs where the operator configured a chat
        # adapter. Without one there is no conversational surface to test,
        # and guessing an endpoint and a wire format would mean sending
        # adversarial prompts somewhere nobody authorized in that shape.
        checkout_dir: Path | None = None
        ai_check: AiSecurityCheck | None = None
        adapter = build_conversational_adapter(target, transport or GatedTransport())
        if adapter is not None:
            ai_check = AiSecurityCheck(
                adapter=adapter,
                probe_target=build_ai_probe_target(target, safe_mode=run.safe_mode),
            )
            checks.append(ai_check)

        # DAST runs only for `kind: web_app`. Not for every HTTP target: a
        # crawler follows links the *application* chooses, and turning that on
        # for an API or an LLM app whose owner authorized a bounded, spec-driven
        # assessment would widen the scan beyond what they agreed to. Declaring
        # the kind is how the operator says "this is a site, crawl it".
        dast_check: DastCheck | None = None
        if target.kind is TargetKind.WEB_APP:
            dast_check = DastCheck(
                target=DastTarget(
                    seed_url=target.base_url,
                    # Read from the rules of engagement, never from the run
                    # request: whether state may change is an authorization
                    # decision, not a per-run option.
                    allow_state_mutation=ctx.roe.allow_state_mutation,
                )
            )
            checks.append(dast_check)

        # The code engines need a checkout. It is created here and removed in
        # the `finally` below whatever happens: a working copy of a client's
        # repository is precisely what must not be left on a worker, since it
        # is the material a secret scan just found credentials in.
        code_check: CodeScanCheck | None = None
        if target.code_repo_ref:
            checkout_dir = make_checkout_dir()
            try:
                code_check = await _prepare_code_check(target, checkout_dir)
                checks.append(code_check)
            except (CheckoutError, CodeScopeError) as exc:
                # Discard here rather than clearing the variable: a clone that
                # failed part-way has still written files, and leaving them
                # behind is the leak this whole path exists to avoid.
                discard_checkout(checkout_dir)
                checkout_dir = None
                await _record_event(
                    db,
                    run.id,
                    RunEventKind.CHECK_COMPLETED,
                    f"Code scanning skipped: {exc}",
                    {"reason": str(exc)},
                )

        # Third-party probe plugins, if an operator allowlisted any. The banner
        # goes into the run's own event log as well as the worker log, so the
        # report's provenance is reconstructable from the run rather than from
        # whichever worker happened to pick it up.
        plugin_check: PluginCheck | None = None
        discovery = discover(policy_from_settings())
        logger.info("plugins.discovered", banner=discovery.banner())
        probe_plugins = discovery.of_kind(PluginKind.PROBE)
        # Only when something was actually found: a deployment that runs no
        # plugins must not file an event on every run saying so.
        if discovery.loaded or discovery.refused:
            await _record_event(
                db,
                run.id,
                RunEventKind.CHECK_COMPLETED,
                discovery.banner().replace("\n", " | ")[:1000],
                {
                    "loaded": [record.describe() for record in discovery.loaded],
                    "refused": list(discovery.refused),
                },
            )
        if probe_plugins:
            plugin_check = PluginCheck(plugins=probe_plugins, probe_target=probe_target)
            checks.append(plugin_check)

        run.status = RunStatus.RUNNING
        run.started_at = datetime.now(UTC)
        run.checks_total = len(checks)
        run.authorization_digest = _digest(
            {
                "valid_from": ctx.authorization.valid_from,
                "valid_until": ctx.authorization.valid_until,
            }
        )
        run.roe_digest = _digest(
            {
                "allowed_domains": list(ctx.roe.allowed_domains),
                "excluded_domains": list(ctx.roe.excluded_domains),
                "allowed_ip_ranges": list(ctx.roe.allowed_ip_ranges),
                "allowed_paths": list(ctx.roe.allowed_paths),
                "excluded_paths": list(ctx.roe.excluded_paths),
                "allowed_methods": list(ctx.roe.allowed_methods),
                "safe_mode": ctx.roe.safe_mode,
            }
        )
        await db.commit()

        async def emit(event: RunEventPayload) -> None:
            await _record_event(
                db, run.id, RunEventKind(event.kind.value), event.message, dict(event.data)
            )

        try:
            outcome = await execute_run(ctx, checks, transport or GatedTransport(), emit)
        finally:
            if checkout_dir is not None:
                discard_checkout(checkout_dir)

        all_results = list(probe_check.scan_results)
        if ai_check is not None:
            all_results.extend(ai_check.scan_results)
        if code_check is not None:
            all_results.extend(code_check.scan_results)
        if dast_check is not None:
            all_results.extend(dast_check.scan_results)
        if plugin_check is not None:
            all_results.extend(plugin_check.scan_results)

        # A target that declares runtime protection gets an explicit "not
        # tested" line, because no engine on this platform measures it
        # (docs/BUILD_SPEC.md §4.5 row 6). §14 requires a report to state what
        # it did not cover, and a claimed WAF that nothing exercised is exactly
        # the kind of gap that otherwise reads as a control that held.
        rasp_marker = untested_marker(
            RuntimeProtectionProfile.from_records(target.runtime_protection or [])
        )
        if rasp_marker is not None:
            all_results.append(rasp_marker)

        await _persist_scan_results(db, run.id, run.organization_id, all_results)

        # Promote this run's results into persistent findings. Done after
        # the results are stored so a promotion can be re-run and corrected
        # later without re-scanning the target.
        await promote_run_results(
            db, organization_id=run.organization_id, run_id=run.id, target=target
        )

        run.status = RunStatus(outcome.status.value)
        run.findings_reported = sum(
            1 for result in all_results if result.severity is not Severity.INFORMATIONAL
        )
        run.checks_completed = outcome.checks_completed
        run.requests_blocked = outcome.requests_blocked
        run.requests_used = len(outcome.results)
        # The record a retest needs: every probe or engine that actually got
        # to run, whether or not it reported anything.
        run.probes_executed = sorted({item.surface for item in outcome.results if item.ok})
        run.halted_reason = outcome.halted_reason
        run.error_message = outcome.error_message
        run.finished_at = datetime.now(UTC)

        # A retest's verdicts come last, after promotion has decided which
        # findings this run saw again. `halted_reason` is already set above,
        # which is what lets the comparison say "not tested" rather than
        # reading a cut-short run as a fix.
        if run.kind is RunKind.RETEST:
            verdicts = await record_retest(db, run=run)
            logger.info(
                "retest_recorded",
                run_id=str(run_id),
                reproduced=sum(1 for v in verdicts if v.verdict is RetestVerdict.REPRODUCED),
                not_reproduced=sum(
                    1 for v in verdicts if v.verdict is RetestVerdict.NOT_REPRODUCED
                ),
                not_tested=sum(1 for v in verdicts if v.verdict is RetestVerdict.NOT_TESTED),
            )

        await db.commit()

        logger.info(
            "run_finished",
            run_id=str(run_id),
            status=run.status.value,
            checks=f"{outcome.checks_completed}/{outcome.checks_total}",
        )
        return run.status


@celery_app.task(name="aegis.run_assessment")
def run_assessment(run_id: str) -> str:
    """Celery's synchronous entry point.

    Each task gets its own event loop, and asyncpg connections belong to the
    loop that opened them, so the engine is disposed before the loop closes
    rather than left holding connections the next task cannot use.
    """

    async def _run() -> RunStatus:
        try:
            return await execute_assessment_run(uuid.UUID(run_id))
        finally:
            await dispose_engine()

    status = asyncio.run(_run())
    # Queued after the run's own transaction has committed and its engine is
    # disposed, so a channel that hangs cannot hold an assessment open and a
    # notification failure is never recorded as an assessment failure.
    from app.workers.notifications import notify_run_finished

    notify_run_finished.delay(run_id)
    return status.value


async def _prepare_code_check(target: Target, checkout_dir: "Path") -> CodeScanCheck:
    """Clone the target's repository and build the code check for it.

    Every control the gated transport would have applied to an outbound
    request is applied before `git` starts: the host must be allowlisted,
    its address must not be one the scope engine blocks, and the scheme must
    be one that cannot execute commands.
    """
    roe = target.rules_of_engagement
    raw_scope = dict(roe.code_scope or {}) if roe is not None else {}
    ref = parse_repo_ref(str(target.code_repo_ref))

    check_host_allowed(
        ref,
        tuple(str(item) for item in raw_scope.get("allowed_repo_hosts", [])),
        allowed_ip_ranges=tuple(str(item) for item in (roe.allowed_ip_ranges if roe else [])),
    )
    await clone_repository(ref, checkout_dir / "repo")
    workspace = build_workspace(target, checkout_dir / "repo")
    return CodeScanCheck(engines=appsec_engines(), workspace=workspace)
