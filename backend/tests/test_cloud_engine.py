"""The cloud engine's control flow: credential gating, provider dispatch,
region filtering, and finding shape — exercised with an injected `providers`
map rather than real `boto3`/AWS credentials, the same reason
`ContainerEngine`'s tests inject `pull`/`scan`/`remove` instead of reaching
for a real Docker daemon.
"""

from __future__ import annotations

from app.core.cloud.contract import BucketExposure, CloudProviderError, CloudTarget
from app.core.cloud.engine import CloudEngine

TARGET = CloudTarget(provider="aws", account_ref="123456789012", credential_env_var="AWS_CRED")


async def test_a_missing_credential_is_a_visible_gap_and_never_calls_the_provider() -> None:
    calls = []

    async def list_exposed_storage(target: CloudTarget, credential: str) -> list[BucketExposure]:
        calls.append((target, credential))
        return []

    engine = CloudEngine(providers={"aws": list_exposed_storage})

    findings, exposures = await engine.run(TARGET, environ={})

    assert calls == []
    assert exposures == []
    assert len(findings) == 1
    assert findings[0].id == "AEGIS-CLOUD-109"
    assert "AWS_CRED" in findings[0].evidence


async def test_an_unimplemented_provider_is_a_visible_gap() -> None:
    engine = CloudEngine(providers={"aws": _unused})
    target = CloudTarget(provider="azure", account_ref="sub-1", credential_env_var="AZURE_CRED")

    findings, exposures = await engine.run(target, environ={"AZURE_CRED": "some-credential"})

    assert exposures == []
    assert findings[0].id == "AEGIS-CLOUD-109"
    assert "azure" in findings[0].evidence
    assert "not implemented yet" in findings[0].evidence


async def test_a_provider_error_is_a_visible_gap_not_a_crash() -> None:
    async def list_exposed_storage(target: CloudTarget, credential: str) -> list[BucketExposure]:
        raise CloudProviderError("AWS S3 ListBuckets failed: access denied")

    engine = CloudEngine(providers={"aws": list_exposed_storage})

    findings, exposures = await engine.run(TARGET, environ={"AWS_CRED": "creds"})

    assert exposures == []
    assert findings[0].id == "AEGIS-CLOUD-109"
    assert "access denied" in findings[0].evidence


async def test_a_clean_run_still_emits_an_inventory_finding() -> None:
    """The same "coverage must show tested, not silently absent" rule
    `DomainEngine`'s subdomain-discovery finding applies — a clean account
    with no buckets must not vanish from the report's coverage section."""

    async def list_exposed_storage(target: CloudTarget, credential: str) -> list[BucketExposure]:
        return []

    engine = CloudEngine(providers={"aws": list_exposed_storage})

    findings, exposures = await engine.run(TARGET, environ={"AWS_CRED": "creds"})

    assert exposures == []
    assert len(findings) == 1
    assert findings[0].id == "AEGIS-CLOUD-001"
    assert "No storage buckets were found" in findings[0].description


async def test_public_buckets_produce_high_severity_findings_alongside_the_inventory() -> None:
    exposures_in = [
        BucketExposure(
            name="public-bucket", region="us-east-1", is_public=True, public_reason="reason a"
        ),
        BucketExposure(
            name="private-bucket", region="us-east-1", is_public=False, public_reason="reason b"
        ),
    ]

    async def list_exposed_storage(target: CloudTarget, credential: str) -> list[BucketExposure]:
        return exposures_in

    engine = CloudEngine(providers={"aws": list_exposed_storage})

    findings, exposures = await engine.run(TARGET, environ={"AWS_CRED": "creds"})

    assert exposures == exposures_in
    assert {item.id for item in findings} == {"AEGIS-CLOUD-001", "AEGIS-CLOUD-101"}
    public_finding = next(item for item in findings if item.id == "AEGIS-CLOUD-101")
    assert "public-bucket" in public_finding.title
    assert public_finding.severity.value == "HIGH"
    assert public_finding.fingerprint is not None

    inventory = next(item for item in findings if item.id == "AEGIS-CLOUD-001")
    assert "1 of 2" in inventory.description


async def test_environ_is_read_from_os_environ_by_default(monkeypatch) -> None:
    monkeypatch.setenv("AWS_CRED", "the-real-credential")
    seen_credential = None

    async def list_exposed_storage(target: CloudTarget, credential: str) -> list[BucketExposure]:
        nonlocal seen_credential
        seen_credential = credential
        return []

    engine = CloudEngine(providers={"aws": list_exposed_storage})
    await engine.run(TARGET)

    assert seen_credential == "the-real-credential"


async def _unused(target: CloudTarget, credential: str) -> list[BucketExposure]:
    raise AssertionError("should not be called for an unimplemented provider")
