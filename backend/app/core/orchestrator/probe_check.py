"""The check that runs a probe registry against a target
(docs/BUILD_SPEC.md §26 Phase 5).

One probe failing is not one run failing. A probe that raises is recorded as
an error against that probe and the run carries on, because a run that loses
fifteen good probes to one bad one is worse for the operator than a run with
a gap it can see.
"""

from dataclasses import dataclass, field

from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeRegistry, ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport


@dataclass
class ProbeCheck:
    """Runs every applicable probe in a registry and collects its results."""

    registry: ProbeRegistry
    probe_target: ProbeTarget
    id: str = "core.api_security"
    name: str = "API security probes"
    # Filled as the check runs; the caller persists these after `run()`.
    scan_results: list[ScanResult] = field(default_factory=list)

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        results: list[CheckResult] = []

        for probe in self.registry.applicable(self.probe_target):
            if ctx.halted or ctx.kill_switch.tripped:
                break

            try:
                found = await probe.run(self.probe_target, ctx, transport)
            except Exception as exc:  # noqa: BLE001 - one probe must not lose the run
                results.append(
                    CheckResult(
                        check_id=self.id,
                        surface=probe.id,
                        ok=False,
                        detail=f"probe raised: {exc}",
                    )
                )
                self.scan_results.append(_probe_error(probe.id, probe.version, exc))
                continue

            self.scan_results.extend(found)
            reportable = [
                result for result in found if result.severity is not Severity.INFORMATIONAL
            ]
            results.append(
                CheckResult(
                    check_id=self.id,
                    surface=probe.id,
                    ok=True,
                    detail=(
                        f"{probe.name}: {len(reportable)} finding(s)"
                        if reportable
                        else f"{probe.name}: nothing found"
                    ),
                )
            )
        return results


def _probe_error(probe_id: str, probe_version: str, exc: Exception) -> ScanResult:
    """A probe that crashed produces a visible gap, never a silent pass.

    Without this, a probe that raised on every endpoint would look exactly
    like a probe that found nothing, which is the most dangerous kind of
    false negative a scanner can have.
    """
    return ScanResult(
        id="KERVY-API-099",
        title=f"Probe {probe_id} failed to complete",
        category=Category.API_SECURITY,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=probe_id,
        description=(
            f"The probe {probe_id} raised an error and did not finish, so this run "
            "says nothing about what it checks."
        ),
        evidence=f"{type(exc).__name__}: {exc}",
        impact="Unknown — the check did not complete, which is not the same as passing.",
        remediation="Re-run this probe; if it keeps failing, report it as a platform bug.",
        probe_id=probe_id,
        probe_version=probe_version,
    )
