"""The check that runs third-party probe plugins (docs/BUILD_SPEC.md §16, §26
Phase 11).

Plugins go through the same shape as every other check: they get the run
context and the gated transport, one failure is recorded rather than losing
the run, and everything they return is a `ScanResult` the findings service
promotes exactly as it promotes a native probe's.

The one thing this check adds is attribution. A plugin's results are stamped
with the plugin's own id and version, and a result that arrives claiming to be
from somewhere else is rewritten — a third-party package must not be able to
file a finding under a native probe's name, because an operator reading the
report would draw conclusions about a probe that never ran.
"""

from dataclasses import dataclass, field, replace

from app.core.orchestrator.checks import CheckResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport
from app.plugins.contract import PluginContext, PluginRecord


@dataclass
class PluginCheck:
    """Runs the loaded probe plugins against the target."""

    plugins: list[PluginRecord]
    probe_target: ProbeTarget
    id: str = "core.plugins"
    name: str = "Third-party probe plugins"
    scan_results: list[ScanResult] = field(default_factory=list)

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        results: list[CheckResult] = []
        if not self.plugins:
            return results

        # Recorded on every run that loaded any, so a reader of the report can
        # see that non-native code contributed to it. §14's coverage honesty
        # cuts both ways: silence about a plugin is as misleading as silence
        # about an untested area.
        self.scan_results.append(self._provenance_note())

        context = PluginContext(ctx=ctx, transport=transport, safe_mode=self.probe_target.safe_mode)
        for record in self.plugins:
            if ctx.halted or ctx.kill_switch.tripped:
                break
            results.append(await self._run_one(record, context))
        return results

    async def _run_one(self, record: PluginRecord, context: PluginContext) -> CheckResult:
        try:
            found = list(await record.obj.run(self.probe_target, context))
        except Exception as exc:  # noqa: BLE001 - untrusted code must not lose the run
            self.scan_results.append(self._plugin_error(record, exc))
            return CheckResult(
                check_id=self.id,
                surface=record.name,
                ok=False,
                detail=f"plugin raised: {type(exc).__name__}: {exc}",
            )

        self.scan_results.extend(self._attributed(record, found))
        return CheckResult(
            check_id=self.id,
            surface=record.name,
            ok=True,
            detail=f"{record.describe()}: {len(found)} result(s)",
        )

    def _attributed(self, record: PluginRecord, found: list[ScanResult]) -> list[ScanResult]:
        """Stamp each result with the plugin that produced it.

        Overwritten, not merely defaulted. A plugin that set `probe_id` to
        `ai.injection.direct.instruction_override` would otherwise file its
        findings under a native probe, and a reader would attribute them to
        code that never ran.
        """
        return [
            replace(
                result,
                probe_id=record.name,
                probe_version=record.version,
                # Also cleared: a plugin cannot hand us an evidence bundle. It
                # has no way to produce one through the contract, so anything
                # here came from somewhere the platform cannot vouch for.
                evidence_bundle=None,
            )
            for result in found
        ]

    def _provenance_note(self) -> ScanResult:
        listed = ", ".join(sorted(record.describe() for record in self.plugins))
        return ScanResult(
            id="KERVY-PLUGIN-900",
            title="Third-party plugins contributed to this run",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=self.probe_target.base_url,
            description=(
                "Findings in this run may come from plugins outside this platform's "
                "own test suite. They are attributed to the plugin that produced "
                "them, and they were reviewed by whoever added the package — not "
                "by this project."
            ),
            evidence=f"Loaded plugins: {listed}",
            impact="Not a weakness — provenance, recorded for the report.",
            remediation="None required.",
            probe_id=self.id,
            probe_version="1.0.0",
        )

    def _plugin_error(self, record: PluginRecord, exc: Exception) -> ScanResult:
        return ScanResult(
            id="KERVY-PLUGIN-099",
            title=f"Not tested: plugin {record.name} failed to complete",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=record.name,
            description=(
                f"The plugin {record.describe()} raised an error and did not finish, "
                "so this run says nothing about what it checks."
            ),
            evidence=f"{type(exc).__name__}: {exc}",
            impact="Unknown — the check did not complete, which is not the same as passing.",
            remediation=(
                "Report this to the plugin's maintainer. Remove it from "
                "plugins.allowlist if it keeps failing."
            ),
            probe_id=self.id,
            probe_version="1.0.0",
        )
