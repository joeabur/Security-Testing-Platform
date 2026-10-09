"""The check that runs the AI security engine against a conversational
target (docs/BUILD_SPEC.md §26 Phase 6).

Mirrors `probe_check.ProbeCheck`: one probe failing is recorded as a gap
and the run carries on, because a run that loses ten good probes to one bad
one is worse for the operator than a run with a visible hole.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial

from app.core.orchestrator.checks import CheckResult
from app.core.probes.ai.contract import AiProbeTarget, Ask, new_canary
from app.core.probes.ai.cross_identity.runner import run_cross_identity_probe
from app.core.probes.ai.driver import run_ai_probe
from app.core.probes.ai.judge import DISABLED_JUDGE, JudgeConfig
from app.core.probes.ai.multiturn.runner import run_multi_turn_probe
from app.core.probes.ai.registry import (
    agency_probe,
    consumption_probe,
    cross_identity_probes,
    multi_turn_probes,
    trial_probes,
)
from app.core.probes.credentials import SyntheticAccount
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport
from app.core.targets.models import TargetResponse, Turn
from app.core.targets.protocol import ConversationalAdapter


@dataclass
class AiSecurityCheck:
    adapter: ConversationalAdapter
    probe_target: AiProbeTarget
    judge: JudgeConfig = field(default_factory=lambda: DISABLED_JUDGE)
    id: str = "core.ai_security"
    name: str = "AI security probes"
    scan_results: list[ScanResult] = field(default_factory=list)

    async def run(self, ctx: RunContext, transport: GatedTransport) -> list[CheckResult]:
        results: list[CheckResult] = []

        async def ask(prompt: str) -> TargetResponse:
            return await self.adapter.send(Turn(content=prompt), ctx)

        # One `Ask` per operator-declared synthetic account, each closing
        # over that account's own headers (resolved fresh here, never
        # stored — the same rule `app/core/probes/credentials.py` already
        # enforces for the REST authorization probes). This is what lets
        # `cross_identity` probes below drive the target as two or more
        # distinct identities.
        ask_as: dict[str, Ask] = {
            account.label: self._ask_as(account, ctx)
            for account in self.probe_target.authorization.usable()
        }

        # One canary for the whole check, so a marker that leaks from one
        # probe into another's context is still this run's marker and not a
        # stale one from a previous assessment.
        canary = new_canary()

        # What was and was not used to detect, recorded whichever way it
        # goes (§7.3, §14).
        self.scan_results.append(self._judging_note())

        for probe in trial_probes():
            if ctx.halted or ctx.kill_switch.tripped:
                break
            results.append(
                await self._guard(
                    probe.meta.id,
                    probe.meta.name,
                    partial(run_ai_probe, probe, self.probe_target, ctx, ask, canary=canary),
                )
            )

        for conversation_probe in multi_turn_probes():
            if ctx.halted or ctx.kill_switch.tripped:
                break
            results.append(
                await self._guard(
                    conversation_probe.meta.id,
                    conversation_probe.meta.name,
                    partial(
                        run_multi_turn_probe,
                        conversation_probe,
                        self.probe_target,
                        ctx,
                        ask,
                        canary=canary,
                    ),
                )
            )

        for identity_probe in cross_identity_probes():
            if ctx.halted or ctx.kill_switch.tripped:
                break
            results.append(
                await self._guard(
                    identity_probe.meta.id,
                    identity_probe.meta.name,
                    partial(
                        run_cross_identity_probe,
                        identity_probe,
                        self.probe_target,
                        ctx,
                        ask_as,
                        canary=canary,
                    ),
                )
            )

        consumption = consumption_probe()
        if not (ctx.halted or ctx.kill_switch.tripped):
            results.append(
                await self._guard(
                    consumption.meta.id,
                    consumption.meta.name,
                    partial(consumption.run, self.probe_target, ctx, ask),
                )
            )

        # Architectural analysis last, and unconditionally: it sends nothing,
        # so a halted or budget-exhausted run still gets it.
        agency = agency_probe()
        found = agency.analyze(self.probe_target)
        self.scan_results.extend(found)
        results.append(
            CheckResult(
                check_id=self.id,
                surface=agency.meta.id,
                ok=True,
                detail=f"{agency.meta.name}: {len(found)} result(s)",
            )
        )
        return results

    def _ask_as(self, account: SyntheticAccount, ctx: RunContext) -> Ask:
        """An `Ask` closure bound to one synthetic account's resolved
        headers, computed once per run rather than resolved again on every
        call — the credential itself still never leaves this closure."""
        headers = self.probe_target.authorization.credentials.headers_for(account)

        async def ask(prompt: str) -> TargetResponse:
            return await self.adapter.send(Turn(content=prompt), ctx, extra_headers=headers)

        return ask

    async def _guard(
        self,
        probe_id: str,
        probe_name: str,
        run: Callable[[], Awaitable[list[ScanResult]]],
    ) -> CheckResult:
        try:
            found = await run()
        except Exception as exc:  # noqa: BLE001 - one probe must not lose the run
            self.scan_results.append(self._probe_error(probe_id, exc))
            return CheckResult(
                check_id=self.id, surface=probe_id, ok=False, detail=f"probe raised: {exc}"
            )

        self.scan_results.extend(found)
        reportable = [item for item in found if item.severity is not Severity.INFORMATIONAL]
        return CheckResult(
            check_id=self.id,
            surface=probe_id,
            ok=True,
            detail=(
                f"{probe_name}: {len(reportable)} finding(s)"
                if reportable
                else f"{probe_name}: nothing found"
            ),
        )

    def _judging_note(self) -> ScanResult:
        return ScanResult(
            id="KERVY-AI-900",
            title="Detection methodology",
            category=Category.AI_SECURITY,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=self.probe_target.surface,
            description=(
                "How the AI findings in this run were detected. Recorded on every run so "
                "a reader never has to assume."
            ),
            evidence=(
                self.judge.describe()
                + "\n\nAll AI detections in this run are marker-based or structural: a "
                "probe succeeds when this run's random canary appears, or when a "
                "response is structurally what was being tested for. No probe succeeds "
                "by eliciting harmful content (docs/BUILD_SPEC.md §2.2)."
            ),
            impact="Not a weakness — methodology, recorded for the report.",
            remediation="None required.",
            probe_id="core.ai_security",
            probe_version="1.0.0",
        )

    def _probe_error(self, probe_id: str, exc: Exception) -> ScanResult:
        return ScanResult(
            id="KERVY-AI-099",
            title=f"Probe {probe_id} failed to complete",
            category=Category.AI_SECURITY,
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
            probe_version="unknown",
        )
