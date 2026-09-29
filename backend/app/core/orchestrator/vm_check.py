"""The orchestrator's VM check, and persisting its discovered open services.

Mirrors `container_check.py`'s "one engine failure must not lose the run"
contract, and carries both `tool_invocations` (like `ContainerCheck`) and
`discovered` (like `CloudCheck`) separately from `scan_results` — the VM
engine is the first to need both halves at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport
from app.core.vm.contract import OpenPort, ToolInvocationRecord, VmTarget
from app.core.vm.engine import VmEngine


@dataclass
class VmCheck:
    target: VmTarget
    id: str = "core.vm"
    name: str = "VM (authorized port/service discovery)"
    # A subprocess (nmap), not a `GatedTransport` request — the same
    # reasoning `ContainerCheck` gives: an exhausted *request* budget is not
    # a reason to skip a check that never spends one.
    requires_network: bool = False
    scan_results: list[ScanResult] = field(default_factory=list)
    tool_invocations: list[ToolInvocationRecord] = field(default_factory=list)
    discovered: list[OpenPort] = field(default_factory=list)
    engine: VmEngine | None = None

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        del ctx, transport
        engine = self.engine or VmEngine()
        try:
            findings, open_ports, invocations = await engine.run(self.target)
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the run
            self.scan_results.append(
                ScanResult(
                    id="KERVY-VM-199",
                    title="VM engine failed to complete",
                    category=Category.INFRASTRUCTURE,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="vm/engine",
                    description=(
                        "The VM engine raised an exception, so this assessment says "
                        "nothing about what it would have found."
                    ),
                    evidence=f"{type(exc).__name__}: {exc}",
                    impact="Unknown — the scan did not complete.",
                    remediation="Re-run; if it recurs, the engine needs fixing.",
                    probe_id="vm.engine",
                    probe_version="1.0.0",
                )
            )
            return [
                CheckResult(
                    check_id=self.id,
                    surface=self.target.host,
                    ok=False,
                    detail=f"engine raised: {exc}",
                )
            ]

        self.scan_results.extend(findings)
        self.tool_invocations.extend(invocations)
        self.discovered.extend(open_ports)
        return [
            CheckResult(
                check_id=self.id,
                surface=self.target.host,
                ok=True,
                detail=(
                    f"VM: {len(open_ports)} open port(s) found"
                    if open_ports
                    else "VM: nothing reportable found"
                ),
            )
        ]
