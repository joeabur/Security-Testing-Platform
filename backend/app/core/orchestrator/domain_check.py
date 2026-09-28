"""The orchestrator's domain check.

Mirrors `dast_check.py`'s shape and its "one engine failure must not lose
the run" contract. Also carries the discovered subdomains separately from
`scan_results`, since promoting them into `DiscoveredAsset` rows is a DB
write `execute_assessment_run` does after the check finishes, not something
a pure, DB-free check does itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.domain.contract import DiscoveredSubdomain, DomainTarget
from app.core.domain.engine import DomainEngine
from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass
class DomainCheck:
    target: DomainTarget
    id: str = "core.domain"
    name: str = "Domain/DNS (subdomain discovery, TLS and header checks)"
    requires_network: bool = True
    scan_results: list[ScanResult] = field(default_factory=list)
    discovered: list[DiscoveredSubdomain] = field(default_factory=list)
    engine: DomainEngine | None = None

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        # Built here rather than in `__init__` so the check carries the run's own
        # transport — the same one every other check uses, and the same one the
        # static egress test guards.
        engine = self.engine or DomainEngine(transport=transport)
        try:
            findings, discovered = await engine.run(ctx, self.target)
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the run
            self.scan_results.append(
                ScanResult(
                    id="AEGIS-DOMAIN-099",
                    title="Domain engine failed to complete",
                    category=Category.INFRASTRUCTURE,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="domain/engine",
                    description=(
                        "The domain engine raised an exception, so this assessment says "
                        "nothing about what it would have found."
                    ),
                    evidence=f"{type(exc).__name__}: {exc}",
                    impact="Unknown — the scan did not complete.",
                    remediation="Re-run; if it recurs, the engine needs fixing.",
                    probe_id="domain.engine",
                    probe_version="1.0.0",
                )
            )
            return [
                CheckResult(
                    check_id=self.id,
                    surface=self.target.root_domain,
                    ok=False,
                    detail=f"engine raised: {exc}",
                )
            ]

        self.scan_results.extend(findings)
        self.discovered.extend(discovered)
        reportable = [item for item in findings if item.severity is not Severity.INFORMATIONAL]
        return [
            CheckResult(
                check_id=self.id,
                surface=self.target.root_domain,
                ok=True,
                detail=(
                    f"Domain: {len(reportable)} finding(s), {len(discovered)} host(s) discovered"
                    if reportable
                    else f"Domain: nothing reportable found, {len(discovered)} host(s) discovered"
                ),
            )
        ]
