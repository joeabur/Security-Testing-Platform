"""The orchestrator's cloud check, and persisting its discovered buckets.

Mirrors `test_container_check.py`'s shape: one engine failure must not lose
the run, and a successful run's outcome summarizes what it found. The
service test mirrors `test_promote_discovered_subdomains_upserts_on_rerun`
for the DB-backed half.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cloud.contract import BucketExposure, CloudTarget
from app.core.cloud.service import promote_discovered_buckets
from app.core.orchestrator.cloud_check import CloudCheck
from app.models.discovered_asset import AssetKind, DiscoveredAsset
from app.models.organization import Organization
from app.models.target import Target, TargetEnvironment, TargetKind
from tests.security.conftest import make_context

TARGET = CloudTarget(provider="aws", account_ref="123456789012", credential_env_var="AWS_CRED")


async def test_cloud_check_reports_an_engine_failure_without_losing_the_run() -> None:
    class _ExplodingEngine:
        async def run(self, target: object) -> tuple[list[object], list[object]]:
            raise RuntimeError("boom")

    check = CloudCheck(target=TARGET, engine=_ExplodingEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert len(results) == 1
    assert results[0].ok is False
    assert check.scan_results[0].id == "AEGIS-CLOUD-199"


async def test_cloud_check_summarizes_a_clean_run() -> None:
    class _StubEngine:
        async def run(self, target: object) -> tuple[list[object], list[object]]:
            return [], []

    check = CloudCheck(target=TARGET, engine=_StubEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert results[0].ok is True
    assert "nothing reportable found" in results[0].detail
    assert check.discovered == []


async def test_cloud_check_summarizes_public_bucket_counts() -> None:
    exposures = [
        BucketExposure(name="a", region="us-east-1", is_public=True, public_reason="r"),
        BucketExposure(name="b", region="us-east-1", is_public=False, public_reason="r"),
    ]

    class _StubEngine:
        async def run(self, target: object) -> tuple[list[object], list[object]]:
            return [], exposures

    check = CloudCheck(target=TARGET, engine=_StubEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert results[0].ok is True
    assert "1 public bucket(s) of 2" in results[0].detail
    assert check.discovered == exposures


async def test_cloud_check_declares_it_does_not_need_the_request_budget() -> None:
    check = CloudCheck(target=TARGET)
    assert check.requires_network is False


# --- service.promote_discovered_buckets (DB-backed) ---------------------------


async def test_promote_discovered_buckets_upserts_on_rerun(db_session: AsyncSession) -> None:
    org = Organization(name="Cloud Test Org", slug=f"cloud-test-org-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    target = Target(
        organization_id=org.id,
        name="AWS account",
        environment=TargetEnvironment.STAGING,
        kind=TargetKind.CLOUD_ACCOUNT,
        base_url="aws:123456789012",
    )
    db_session.add(target)
    await db_session.flush()

    exposure = BucketExposure(
        name="my-bucket", region="us-east-1", is_public=True, public_reason="public ACL grant"
    )

    first = await promote_discovered_buckets(
        db_session,
        organization_id=org.id,
        parent_target_id=target.id,
        target=TARGET,
        exposures=[exposure],
    )
    await db_session.commit()
    assert len(first) == 1
    assert first[0].identifier == "aws:123456789012:my-bucket"
    assert first[0].asset_kind is AssetKind.CLOUD_RESOURCE
    assert first[0].asset_metadata["provider"] == "aws"
    assert first[0].asset_metadata["resource_type"] == "object_storage_bucket"
    assert first[0].risk_summary["is_public"] is True

    second = await promote_discovered_buckets(
        db_session,
        organization_id=org.id,
        parent_target_id=target.id,
        target=TARGET,
        exposures=[exposure],
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


async def test_promote_discovered_buckets_records_a_no_longer_public_change(
    db_session: AsyncSession,
) -> None:
    org = Organization(name="Cloud Test Org 2", slug=f"cloud-test-org2-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    target = Target(
        organization_id=org.id,
        name="AWS account",
        environment=TargetEnvironment.STAGING,
        kind=TargetKind.CLOUD_ACCOUNT,
        base_url="aws:123456789012",
    )
    db_session.add(target)
    await db_session.flush()

    public = BucketExposure(
        name="my-bucket", region="us-east-1", is_public=True, public_reason="public ACL grant"
    )
    await promote_discovered_buckets(
        db_session,
        organization_id=org.id,
        parent_target_id=target.id,
        target=TARGET,
        exposures=[public],
    )
    await db_session.commit()

    now_private = BucketExposure(
        name="my-bucket", region="us-east-1", is_public=False, public_reason="no public grant"
    )
    rows = await promote_discovered_buckets(
        db_session,
        organization_id=org.id,
        parent_target_id=target.id,
        target=TARGET,
        exposures=[now_private],
    )
    await db_session.commit()

    assert rows[0].risk_summary["is_public"] is False
