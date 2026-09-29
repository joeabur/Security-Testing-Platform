"""The check that runs the AppSec engines over a resolved workspace
(docs/BUILD_SPEC.md §26 Phase 14).

Mirrors `ProbeCheck` and `AiSecurityCheck`: one engine failing is recorded
as a visible gap and the run continues, because a run that loses four good
engines to one bad one is worse for the operator than a run with a hole it
can see.

Unlike the other two checks, nothing here goes through `GatedTransport` —
these engines read files. Where an engine's tool would reach the network, it
is launched with an explicit offline configuration (see
`app/core/appsec/tooling.py`), which is how §6.3's rule applies to a
subprocess.
"""

from dataclasses import dataclass, field

from app.core.appsec.contract import AppSecEngine
from app.core.appsec.workspace import Workspace
from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass
class CodeScanCheck:
    engines: list[AppSecEngine]
    workspace: Workspace
    id: str = "core.appsec"
    name: str = "AppSec engines"
    # These engines read files. An exhausted request budget is not a reason
    # to skip them, though an operator cancellation still is.
    requires_network: bool = False
    scan_results: list[ScanResult] = field(default_factory=list)

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        results: list[CheckResult] = []

        for engine in self.engines:
            if ctx.kill_switch.tripped:
                break
            if not engine.applies_to(self.workspace):
                continue

            try:
                found = await engine.run(self.workspace)
            except Exception as exc:  # noqa: BLE001 - one engine must not lose the run
                self.scan_results.append(_engine_error(engine, exc))
                results.append(
                    CheckResult(
                        check_id=self.id,
                        surface=engine.meta.id,
                        ok=False,
                        detail=f"engine raised: {exc}",
                    )
                )
                continue

            self.scan_results.extend(found)
            reportable = [r for r in found if r.severity is not Severity.INFORMATIONAL]
            results.append(
                CheckResult(
                    check_id=self.id,
                    surface=engine.meta.id,
                    ok=True,
                    detail=(
                        f"{engine.meta.name}: {len(reportable)} finding(s)"
                        if reportable
                        else f"{engine.meta.name}: nothing found"
                    ),
                )
            )
        return results


def _engine_error(engine: AppSecEngine, exc: Exception) -> ScanResult:
    return ScanResult(
        id="KERVY-APPSEC-099",
        title=f"Engine {engine.meta.id} failed to complete",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=engine.meta.pillar.value,
        description=(
            f"The {engine.meta.id} engine raised an error and did not finish, so this "
            "run says nothing about what it covers."
        ),
        evidence=f"{type(exc).__name__}: {exc}",
        impact="Unknown — the scan did not complete, which is not the same as passing.",
        remediation="Re-run this engine; if it keeps failing, report it as a platform bug.",
        probe_id=engine.meta.id,
        probe_version=engine.meta.version,
    )
