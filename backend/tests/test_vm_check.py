"""The orchestrator's VM check, and persisting its tool invocations and
discovered open services.

Mirrors `test_container_check.py`'s check-level tests (one engine failure
must not lose the run) and `test_cloud_check.py`'s DB-backed
upsert-on-rerun test, since `VmCheck` is the first check to need both
halves at once.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.orchestrator.vm_check import VmCheck
from app.core.vm.contract import OpenPort, ToolInvocationRecord, VmTarget
from app.core.vm.service import promote_discovered_open_services, record_tool_invocations
from app.models.assessment_run import AssessmentRun, RunKind, RunStatus
from app.models.discovered_asset import AssetKind, DiscoveredAsset
from app.models.organization import Organization
from app.models.target import Target, TargetEnvironment, TargetKind
from app.models.tool_invocation import RunToolInvocation
from tests.security.conftest import make_context

TARGET = VmTarget(host="8.8.8.8", allowed_ports=(22, 80))


async def test_vm_check_reports_an_engine_failure_without_losing_the_run() -> None:
    class _ExplodingEngine:
        async def run(self, target: object) -> tuple[list[object], list[object], list[object]]:
            raise RuntimeError("boom")

    check = VmCheck(target=TARGET, engine=_ExplodingEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert len(results) == 1
    assert results[0].ok is False
    assert check.scan_results[0].id == "KERVY-VM-199"


async def test_vm_check_summarizes_a_clean_run() -> None:
    class _StubEngine:
        async def run(self, target: object) -> tuple[list[object], list[object], list[object]]:
            return [], [], []

    check = VmCheck(target=TARGET, engine=_StubEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert results[0].ok is True
    assert "nothing reportable found" in results[0].detail
    assert check.discovered == []


async def test_vm_check_summarizes_open_port_counts_and_carries_invocations() -> None:
    invocation = ToolInvocationRecord(
        tool_name="nmap",
        tool_version=None,
        network_use="declared_service",
        command_summary="nmap -sV -p 22,80 8.8.8.8",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        exit_status=0,
    )
    open_ports = [OpenPort(port=22, protocol="tcp", service="ssh", product="", version="")]

    class _StubEngine:
        async def run(self, target: object) -> tuple[list[object], list[object], list[object]]:
            return [], open_ports, [invocation]

    check = VmCheck(target=TARGET, engine=_StubEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert results[0].ok is True
    assert "1 open port(s) found" in results[0].detail
    assert check.discovered == open_ports
    assert check.tool_invocations == [invocation]


async def test_vm_check_declares_it_does_not_need_the_request_budget() -> None:
    check = VmCheck(target=TARGET)
    assert check.requires_network is False


# --- service.record_tool_invocations / promote_discovered_open_services -------


async def test_record_tool_invocations_persists_the_fixed_shape(db_session: AsyncSession) -> None:
    org = Organization(name="VM Test Org", slug=f"vm-test-org-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    target = Target(
        organization_id=org.id,
        name="jump host",
        environment=TargetEnvironment.STAGING,
        kind=TargetKind.VIRTUAL_MACHINE,
        base_url="8.8.8.8",
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
        tool_name="nmap",
        tool_version=None,
        network_use="declared_service",
        command_summary="nmap -sV -p 22,80 8.8.8.8",
        started_at=started,
        finished_at=started,
        exit_status=0,
    )

    rows = await record_tool_invocations(
        db_session, organization_id=org.id, run_id=run.id, invocations=[record]
    )
    await db_session.commit()

    assert len(rows) == 1
    stored = (
        await db_session.execute(
            select(RunToolInvocation).where(RunToolInvocation.id == rows[0].id)
        )
    ).scalar_one()
    assert stored.tool_name == "nmap"
    assert stored.network_use == "declared_service"
    assert stored.exit_status == 0


async def test_promote_discovered_open_services_upserts_on_rerun(db_session: AsyncSession) -> None:
    org = Organization(name="VM Test Org 2", slug=f"vm-test-org2-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    target = Target(
        organization_id=org.id,
        name="jump host",
        environment=TargetEnvironment.STAGING,
        kind=TargetKind.VIRTUAL_MACHINE,
        base_url="8.8.8.8",
    )
    db_session.add(target)
    await db_session.flush()

    open_port = OpenPort(port=22, protocol="tcp", service="ssh", product="OpenSSH", version="8.9")

    first = await promote_discovered_open_services(
        db_session,
        organization_id=org.id,
        parent_target_id=target.id,
        target=TARGET,
        open_ports=[open_port],
    )
    await db_session.commit()
    assert len(first) == 1
    assert first[0].identifier == "8.8.8.8:22"
    assert first[0].asset_kind is AssetKind.OPEN_SERVICE
    assert first[0].asset_metadata["service"] == "ssh"
    assert first[0].asset_metadata["product"] == "OpenSSH"

    second = await promote_discovered_open_services(
        db_session,
        organization_id=org.id,
        parent_target_id=target.id,
        target=TARGET,
        open_ports=[open_port],
    )
    await db_session.commit()
    assert second[0].id == first[0].id

    rows = (
        (
            await db_session.execute(
                select(DiscoveredAsset).where(DiscoveredAsset.parent_target_id == target.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
