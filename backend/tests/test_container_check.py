"""The orchestrator's container check, and persisting its tool invocations.

Mirrors `test_domain_engine.py`'s check-level tests: one engine failure
must not lose the run, and a successful run's outcome summarizes what it
found. The service test mirrors `test_promote_discovered_subdomains_upserts
_on_rerun` for the DB-backed half.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.container.contract import ContainerTarget, ToolInvocationRecord
from app.core.container.service import record_tool_invocations
from app.core.orchestrator.container_check import ContainerCheck
from app.models.assessment_run import AssessmentRun, RunKind, RunStatus
from app.models.organization import Organization
from app.models.target import Target, TargetEnvironment, TargetKind
from app.models.tool_invocation import RunToolInvocation
from tests.security.conftest import make_context

TARGET = ContainerTarget(
    image_ref="ghcr.io/org/app:tag", allowed_registries=("ghcr.io",), allow_live_pull=True
)


async def test_container_check_reports_an_engine_failure_without_losing_the_run() -> None:
    class _ExplodingEngine:
        async def run(self, target: object) -> tuple[list[object], list[object]]:
            raise RuntimeError("boom")

    check = ContainerCheck(target=TARGET, engine=_ExplodingEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert len(results) == 1
    assert results[0].ok is False
    assert check.scan_results[0].id == "AEGIS-CONTAINER-199"


async def test_container_check_summarizes_findings_and_invocations() -> None:
    invocation = ToolInvocationRecord(
        tool_name="docker",
        tool_version=None,
        network_use="declared_service",
        command_summary="docker pull ghcr.io/org/app:tag",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        exit_status=0,
    )

    class _StubEngine:
        async def run(self, target: object) -> tuple[list[object], list[object]]:
            return [], [invocation]

    check = ContainerCheck(target=TARGET, engine=_StubEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert results[0].ok is True
    assert "nothing reportable found" in results[0].detail
    assert check.tool_invocations == [invocation]


async def test_container_check_declares_it_does_not_need_the_request_budget() -> None:
    check = ContainerCheck(target=TARGET)
    assert check.requires_network is False


# --- service.record_tool_invocations (DB-backed) -----------------------------


async def test_record_tool_invocations_persists_the_fixed_shape(db_session: AsyncSession) -> None:
    org = Organization(name="Container Test Org", slug=f"container-test-org-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    target = Target(
        organization_id=org.id,
        name="app image",
        environment=TargetEnvironment.STAGING,
        kind=TargetKind.CONTAINER,
        base_url="ghcr.io/org/app",
    )
    db_session.add(target)
    await db_session.flush()
    run = AssessmentRun(
        organization_id=org.id,
        target_id=target.id,
        status=RunStatus.RUNNING,
        kind=RunKind.ASSESSMENT,
        profile="full",
        safe_mode=True,
    )
    db_session.add(run)
    await db_session.flush()

    started = datetime.now(UTC)
    record = ToolInvocationRecord(
        tool_name="trivy",
        tool_version=None,
        network_use="offline",
        command_summary="trivy image ghcr.io/org/app:tag",
        started_at=started,
        finished_at=started,
        exit_status=0,
    )

    rows = await record_tool_invocations(
        db_session,
        organization_id=org.id,
        run_id=run.id,
        invocations=[record],
    )
    await db_session.commit()

    assert len(rows) == 1
    stored = (
        await db_session.execute(
            select(RunToolInvocation).where(RunToolInvocation.id == rows[0].id)
        )
    ).scalar_one()
    assert stored.tool_name == "trivy"
    assert stored.network_use == "offline"
    assert stored.exit_status == 0
