"""The orchestrator's cloud check.

Mirrors `container_check.py`'s shape and its "one engine failure must not
lose the run" contract. Also carries the engine's inventoried buckets
separately from `scan_results`, since persisting them into
`DiscoveredAsset` rows is a DB write `execute_assessment_run` does after
the check finishes, not something a pure, DB-free check does itself — the
same reason `DomainCheck` carries `discovered` separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.cloud.contract import BucketExposure, CloudTarget
from app.core.cloud.engine import CloudEngine
from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass
class CloudCheck:
    target: CloudTarget
    id: str = "core.cloud"
    name: str = "Cloud (read-only account inventory and exposure checks)"
    # A provider SDK call, not a `GatedTransport` request — the same
    # reasoning `ContainerCheck` gives: an exhausted *request* budget is not
    # a reason to skip a check that never spends one.
    requires_network: bool = False
    scan_results: list[ScanResult] = field(default_factory=list)
    discovered: list[BucketExposure] = field(default_factory=list)
    engine: CloudEngine | None = None

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        # `ctx`/`transport` are accepted to satisfy the `Check` protocol
        # every other check implements, but unused: a cloud provider SDK
        # call is not a `GatedTransport` request. See `engine.py`'s
        # docstring, and `ContainerCheck` for the same shape.
        del ctx, transport
        engine = self.engine or CloudEngine()
        try:
            findings, exposures = await engine.run(self.target)
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the run
            self.scan_results.append(
                ScanResult(
                    id="KERVY-CLOUD-199",
                    title="Cloud engine failed to complete",
                    category=Category.INFRASTRUCTURE,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="cloud/engine",
                    description=(
                        "The cloud engine raised an exception, so this assessment says "
                        "nothing about what it would have found."
                    ),
                    evidence=f"{type(exc).__name__}: {exc}",
                    impact="Unknown — the scan did not complete.",
                    remediation="Re-run; if it recurs, the engine needs fixing.",
                    probe_id="cloud.engine",
                    probe_version="1.0.0",
                )
            )
            return [
                CheckResult(
                    check_id=self.id,
                    surface=self.target.account_ref,
                    ok=False,
                    detail=f"engine raised: {exc}",
                )
            ]

        self.scan_results.extend(findings)
        self.discovered.extend(exposures)
        public_count = sum(1 for item in exposures if item.is_public)
        return [
            CheckResult(
                check_id=self.id,
                surface=self.target.account_ref,
                ok=True,
                detail=(
                    f"Cloud: {public_count} public bucket(s) of {len(exposures)} inventoried"
                    if exposures
                    else "Cloud: nothing reportable found"
                ),
            )
        ]
