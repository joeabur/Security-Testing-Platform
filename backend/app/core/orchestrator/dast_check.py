"""The orchestrator's DAST check.

Thin on purpose: the crawl and the tool policy are the engine's business, and
this module exists only to run it inside a run's lifecycle and report progress
in the same `CheckResult` shape as every other check.

`requires_network = True`, unlike the AppSec check — a crawl is nothing but
requests, so an exhausted request budget genuinely means there is no work left
to do.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.dast.contract import DastTarget
from app.core.dast.engine import DastEngine
from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass
class DastCheck:
    target: DastTarget
    id: str = "core.dast"
    name: str = "DAST (crawl and web scanners)"
    requires_network: bool = True
    scan_results: list[ScanResult] = field(default_factory=list)
    engine: DastEngine | None = None

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        # Built here rather than in `__init__` so the check carries the run's own
        # transport — the same one every other check uses, and the same one the
        # static egress test guards.
        engine = self.engine or DastEngine(transport=transport)
        try:
            found = await engine.run(ctx, self.target)
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the run
            self.scan_results.append(
                ScanResult(
                    id="KERVY-DAST-099",
                    title="DAST engine failed to complete",
                    category=Category.INFRASTRUCTURE,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="dast/engine",
                    description=(
                        "The DAST engine raised an exception, so this assessment says "
                        "nothing about what it would have found."
                    ),
                    evidence=f"{type(exc).__name__}: {exc}",
                    impact="Unknown — the scan did not complete.",
                    remediation="Re-run; if it recurs, the engine needs fixing.",
                    probe_id="dast.engine",
                    probe_version="1.0.0",
                )
            )
            return [
                CheckResult(
                    check_id=self.id,
                    surface=self.target.seed_url,
                    ok=False,
                    detail=f"engine raised: {exc}",
                )
            ]

        self.scan_results.extend(found)
        reportable = [item for item in found if item.severity is not Severity.INFORMATIONAL]
        return [
            CheckResult(
                check_id=self.id,
                surface=self.target.seed_url,
                ok=True,
                detail=(
                    f"DAST: {len(reportable)} finding(s)"
                    if reportable
                    else "DAST: nothing reportable found"
                ),
            )
        ]
