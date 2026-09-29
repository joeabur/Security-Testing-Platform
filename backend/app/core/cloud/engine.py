"""The cloud engine: read-only object-storage exposure inventory.

AWS (`providers/aws.py`) is the one provider fully implemented in this
phase — real, correct `boto3` usage, tested via an injected provider
function so no live AWS account is needed to prove the engine's own logic
(gating, scope filtering, finding shape) correct, the same reason
`ContainerEngine` injects `pull`/`scan`/`remove` rather than reaching for
real `docker`/`trivy` at call time.

Azure and GCP route correctly — `resolve_cloud_scope` already validates
`provider` against exactly `{"aws", "azure", "gcp"}`, and this engine's
dispatch handles all three — but calling either today produces an explicit
"not implemented yet" gap finding rather than a fabricated result. See
`docs/roadmap.md` for why: each needs its own multi-package SDK
integration (`azure-identity` + `azure-mgmt-storage` + `azure-storage-
blob`; `google-cloud-storage` + service-account credential handling), and
shipping either untested against a real account would be exactly the kind
of unverified claim this codebase's own discipline refuses to make.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from app.core.cloud.contract import BucketExposure, CloudProviderError, CloudTarget
from app.core.cloud.providers.aws import list_exposed_storage as _aws_list_exposed_storage
from app.core.probes.models import Category, Confidence, ScanResult, Severity

ENGINE_ID = "cloud.engine"
ENGINE_VERSION = "1.0.0"

ListExposedStorageFn = Callable[[CloudTarget, str], Awaitable[list[BucketExposure]]]

_PROVIDERS: dict[str, ListExposedStorageFn] = {
    "aws": _aws_list_exposed_storage,
}


@dataclass
class CloudEngine:
    """Injectable `providers` map so tests exercise the engine's own control
    flow — credential resolution, scope filtering, finding shape — without
    a real cloud account or the `boto3` package installed."""

    providers: dict[str, ListExposedStorageFn] = field(default_factory=lambda: dict(_PROVIDERS))

    async def run(
        self, target: CloudTarget, *, environ: dict[str, str] | None = None
    ) -> tuple[list[ScanResult], list[BucketExposure]]:
        source = os.environ if environ is None else environ
        credential = source.get(target.credential_env_var)
        if not credential:
            return (
                [
                    _coverage_marker(
                        target.account_ref,
                        f"no credential resolved for {target.credential_env_var!r}; the "
                        "cloud engine did not run",
                    )
                ],
                [],
            )

        list_exposed_storage = self.providers.get(target.provider)
        if list_exposed_storage is None:
            return (
                [
                    _coverage_marker(
                        target.account_ref,
                        f"the {target.provider!r} provider is not implemented yet — only "
                        "'aws' ships in this phase",
                    )
                ],
                [],
            )

        try:
            exposures = await list_exposed_storage(target, credential)
        except CloudProviderError as exc:
            return [_coverage_marker(target.account_ref, str(exc))], []

        return _findings(target, exposures), exposures


def _findings(target: CloudTarget, exposures: list[BucketExposure]) -> list[ScanResult]:
    results: list[ScanResult] = [_inventory_finding(target, exposures)]
    for exposure in exposures:
        if not exposure.is_public:
            continue
        results.append(
            ScanResult(
                id="KERVY-CLOUD-101",
                title=f"Publicly accessible storage bucket: {exposure.name}",
                category=Category.INFRASTRUCTURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                endpoint=f"{target.provider}:{target.account_ref}:{exposure.name}",
                description=(
                    f"{exposure.name} ({target.provider}, {exposure.region or 'unknown region'}) "
                    f"is publicly accessible: {exposure.public_reason}"
                ),
                evidence=exposure.public_reason,
                impact=(
                    "Anyone on the internet can read — and, depending on the grant, write — "
                    "objects in this bucket without authenticating to this account."
                ),
                remediation=(
                    "Remove the public grant from the bucket policy or ACL, and enable the "
                    "account-level Block Public Access setting unless a public bucket is a "
                    "deliberate, reviewed exception."
                ),
                probe_id=ENGINE_ID,
                probe_version=ENGINE_VERSION,
                reproduction=(
                    f"aws s3api get-bucket-policy-status --bucket {exposure.name}",
                    f"aws s3api get-bucket-acl --bucket {exposure.name}",
                ),
                fingerprint="sha256:"
                + hashlib.sha256(
                    f"{target.provider}|{target.account_ref}|{exposure.name}".encode()
                ).hexdigest(),
            )
        )
    return results


def _inventory_finding(target: CloudTarget, exposures: list[BucketExposure]) -> ScanResult:
    """Unconditional, informational — the same reason `DomainEngine` always
    emits its subdomain-discovery finding: a clean run that found nothing
    public must still show up as *tested*, not silently absent from the
    report's coverage section (`_PILLAR_PREFIXES["Cloud"] = ("cloud.",)`)."""
    public_count = sum(1 for item in exposures if item.is_public)
    listed = "\n".join(
        f"{item.name} ({item.region or 'unknown region'})" for item in exposures[:50]
    )
    return ScanResult(
        id="KERVY-CLOUD-001",
        title=f"{len(exposures)} storage bucket(s) inventoried for {target.account_ref}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        endpoint=f"{target.provider}:{target.account_ref}",
        description=(
            f"{public_count} of {len(exposures)} bucket(s) are publicly accessible."
            if exposures
            else "No storage buckets were found in this account (or its declared regions)."
        ),
        evidence=listed,
        impact="None from this inventory — it makes no mutating call.",
        remediation="Review the list for anything unexpected.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )


def _coverage_marker(surface: str, reason: str) -> ScanResult:
    return ScanResult(
        id="KERVY-CLOUD-109",
        title=f"Not tested: {surface}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=f"cloud/{surface}",
        description=f"{reason}. This assessment says nothing about {surface}.",
        evidence=reason,
        impact="Unknown — not tested.",
        remediation="Resolve the credential/provider gap, or confirm the gap is expected.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )
