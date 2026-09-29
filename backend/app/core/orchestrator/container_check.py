"""The orchestrator's container check.

Mirrors `domain_check.py`'s shape and its "one engine failure must not lose
the run" contract. Also carries the engine's tool invocations separately
from `scan_results`, since persisting them into `RunToolInvocation` rows is
a DB write `execute_assessment_run` does after the check finishes, not
something a pure, DB-free check does itself — the same reason `DomainCheck`
carries `discovered` separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.container.contract import ContainerTarget, ToolInvocationRecord
from app.core.container.engine import ContainerEngine
from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass
class ContainerCheck:
    target: ContainerTarget
    id: str = "core.container"
    name: str = "Container (live registry pull, offline vulnerability scan)"
    # A subprocess (docker/trivy), not a `GatedTransport` request — the same
    # reasoning `CodeScanCheck` gives: an exhausted *request* budget is not a
    # reason to skip a check that never spends one.
    requires_network: bool = False
    scan_results: list[ScanResult] = field(default_factory=list)
    tool_invocations: list[ToolInvocationRecord] = field(default_factory=list)
    engine: ContainerEngine | None = None

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        # `ctx`/`transport` are accepted to satisfy the `Check` protocol every
        # other check implements, but unused: a container pull is a
        # subprocess, not a `GatedTransport` request, so there is nothing
        # here for the scope engine's `RunContext` to gate — the
        # allowlist/IP-block checks happen inside `pull.check_registry_allowed`
        # instead. See `pull.py`'s docstring, and `CodeScanCheck` for the same
        # "network-capable protocol, file/subprocess-only check" shape.
        del ctx, transport
        engine = self.engine or ContainerEngine()
        try:
            findings, invocations = await engine.run(self.target)
        except Exception as exc:  # noqa: BLE001 - one engine must not lose the run
            self.scan_results.append(
                ScanResult(
                    id="KERVY-CONTAINER-199",
                    title="Container engine failed to complete",
                    category=Category.INFRASTRUCTURE,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="container/engine",
                    description=(
                        "The container engine raised an exception, so this assessment "
                        "says nothing about what it would have found."
                    ),
                    evidence=f"{type(exc).__name__}: {exc}",
                    impact="Unknown — the scan did not complete.",
                    remediation="Re-run; if it recurs, the engine needs fixing.",
                    probe_id="container.engine",
                    probe_version="1.0.0",
                )
            )
            return [
                CheckResult(
                    check_id=self.id,
                    surface=self.target.image_ref,
                    ok=False,
                    detail=f"engine raised: {exc}",
                )
            ]

        self.scan_results.extend(findings)
        self.tool_invocations.extend(invocations)
        reportable = [item for item in findings if item.severity is not Severity.INFORMATIONAL]
        return [
            CheckResult(
                check_id=self.id,
                surface=self.target.image_ref,
                ok=True,
                detail=(
                    f"Container: {len(reportable)} finding(s)"
                    if reportable
                    else "Container: nothing reportable found"
                ),
            )
        ]
