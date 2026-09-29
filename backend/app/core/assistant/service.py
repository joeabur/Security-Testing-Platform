"""The AI intelligence layer (Implementation Specification §8, §10, §11).

What it is: a co-pilot that explains, correlates, prioritises and drafts.

What it is not, and cannot be made into by configuration: a thing that
decides. §10 is the rule this module exists to enforce — deterministic
evidence stays authoritative, and AI output is analysis *of* it:

    Tool / Engine -> Observation -> Detection -> Finding -> AI interpretation

So every method here returns a **draft**. Nothing in this module writes a
finding's real fields, changes a status, touches an authorization, or sends
anything to a target — `refuse_target_touching` makes the last of those an
error rather than an omission.

The service is optional end to end. With no provider configured, every
method raises `ProviderNotConfiguredError` and the rest of the platform is
unaffected, which is a tested property rather than an intention.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.assistant.autonomy import AutonomyMode, Capability, require
from app.core.assistant.prompts import (
    ANSWER_EVIDENCE_QUESTION,
    CORRELATE_FINDINGS,
    DRAFT_REMEDIATION,
    DRAFT_SEVERITY_RATIONALE,
    EXPLAIN_FINDING,
    PRIORITISE_FINDINGS,
    SUMMARISE_RUN,
    PromptTemplate,
    quote_evidence,
)
from app.core.assistant.provider import (
    AIProvider,
    Completion,
    ProviderNotConfiguredError,
)

MAX_EVIDENCE_CHARS = 4000
MAX_TITLES = 50
MAX_FINDINGS = 25


@dataclass(frozen=True)
class Draft:
    """AI output, labelled as such and not yet part of anything.

    It becomes report text only when a human accepts it. Until then it sits
    beside the real fields, never over them.
    """

    capability: Capability
    content: str
    model: str
    provider: str
    prompt_template_id: str
    prompt_template_version: str
    tokens_sent: int = 0
    tokens_received: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def audit_metadata(self) -> dict[str, object]:
        """What the audit trail records for this interaction.

        §6.3 item 4: "the model, prompt template, and version used for every
        assistant interaction are logged", so that "the AI drafted this
        remediation text" is always traceable and reproducible.
        """
        return {
            "capability": self.capability.value,
            "provider": self.provider,
            "model": self.model,
            "prompt_template": self.prompt_template_id,
            "prompt_template_version": self.prompt_template_version,
            "tokens_sent": self.tokens_sent,
            "tokens_received": self.tokens_received,
        }


@dataclass(frozen=True)
class FindingView:
    """The read-only slice of a scan result the assistant is given.

    A deliberate projection rather than the row itself: the assistant cannot
    write what it was never handed, and a reviewer can see exactly what the
    model was shown.
    """

    probe_id: str
    title: str
    endpoint: str
    severity: str
    description: str
    evidence: str
    remediation: str


def _render_findings_list(findings: list[FindingView]) -> str:
    """One evidence-fenced block per finding, capped the same way
    `summarise_run`'s title list is capped: a co-pilot reasoning over a
    hundred findings at once produces noise, not a correlation."""
    lines = [
        f"- [{finding.probe_id}] {finding.title} (severity: {finding.severity}, "
        f"surface: {finding.endpoint}): {finding.description[:MAX_EVIDENCE_CHARS]}"
        for finding in findings[:MAX_FINDINGS]
    ]
    return quote_evidence("\n".join(lines))


class AIService:
    """Drafting and analysis over findings. No writes, no target access."""

    def __init__(
        self,
        provider: AIProvider | None = None,
        *,
        mode: AutonomyMode = AutonomyMode.ASSIST,
    ) -> None:
        self._provider = provider
        self._mode = mode

    @property
    def configured(self) -> bool:
        return self._provider is not None and self._mode is not AutonomyMode.OFF

    @property
    def mode(self) -> AutonomyMode:
        return self._mode

    def _require_provider(self) -> AIProvider:
        if self._provider is None:
            raise ProviderNotConfiguredError(
                "no AI provider is configured. Every other part of the platform — "
                "scanning, scoring, reporting, the CI gate — works without one."
            )
        return self._provider

    async def explain_finding(self, finding: FindingView) -> Draft:
        return await self._draft(
            Capability.EXPLAIN_FINDING,
            EXPLAIN_FINDING,
            probe_id=finding.probe_id,
            endpoint=finding.endpoint,
            severity=finding.severity,
            title=finding.title,
            description=quote_evidence(finding.description[:MAX_EVIDENCE_CHARS]),
            evidence=quote_evidence(finding.evidence[:MAX_EVIDENCE_CHARS]),
        )

    async def draft_remediation(self, finding: FindingView) -> Draft:
        return await self._draft(
            Capability.DRAFT_REMEDIATION,
            DRAFT_REMEDIATION,
            probe_id=finding.probe_id,
            endpoint=finding.endpoint,
            title=finding.title,
            remediation=quote_evidence(finding.remediation[:MAX_EVIDENCE_CHARS]),
            evidence=quote_evidence(finding.evidence[:MAX_EVIDENCE_CHARS]),
        )

    async def draft_severity_rationale(self, finding: FindingView) -> Draft:
        return await self._draft(
            Capability.DRAFT_SEVERITY_RATIONALE,
            DRAFT_SEVERITY_RATIONALE,
            probe_id=finding.probe_id,
            endpoint=finding.endpoint,
            severity=finding.severity,
            title=finding.title,
            evidence=quote_evidence(finding.evidence[:MAX_EVIDENCE_CHARS]),
        )

    async def summarise_run(
        self,
        *,
        target: str,
        checks: str,
        severity_counts: Mapping[str, int],
        titles: list[str],
        not_tested: list[str],
    ) -> Draft:
        """An executive summary drafted from counts the platform computed.

        The counts are passed in rather than described, because §14 requires
        the methodology, scope and appendix sections to be generated
        deterministically from data. A model asked to count would sometimes
        get it wrong, and a wrong number in an executive summary is the kind
        of error that destroys trust in the whole report.
        """
        return await self._draft(
            Capability.SUMMARISE_RUN,
            SUMMARISE_RUN,
            target=target,
            checks=checks,
            severity_counts=", ".join(
                f"{name}: {count}" for name, count in sorted(severity_counts.items())
            )
            or "none",
            not_tested=", ".join(not_tested) or "nothing recorded as untested",
            titles=quote_evidence("\n".join(f"- {title}" for title in titles[:MAX_TITLES])),
        )

    async def correlate_findings(self, findings: list[FindingView]) -> Draft:
        """Look for relationships across findings from the same assessment.

        Findings are a human's read-only slice, the same as `FindingView`
        elsewhere in this class — the draft returned is a recommendation to
        weigh, not a change to any finding's own fields or relationships.
        """
        return await self._draft(
            Capability.CORRELATE_FINDINGS,
            CORRELATE_FINDINGS,
            findings=_render_findings_list(findings),
        )

    async def prioritise_findings(self, findings: list[FindingView]) -> Draft:
        """Propose a remediation order. The platform's own severity/status
        fields are unaffected — see `PRIORITISE_FINDINGS`'s own template."""
        return await self._draft(
            Capability.PRIORITISE_FINDINGS,
            PRIORITISE_FINDINGS,
            findings=_render_findings_list(findings),
        )

    async def answer_evidence_question(self, finding: FindingView, question: str) -> Draft:
        """Answer a free-text question about one finding, grounded only in
        what was captured — never in anything the question itself asserts."""
        return await self._draft(
            Capability.ANSWER_EVIDENCE_QUESTION,
            ANSWER_EVIDENCE_QUESTION,
            probe_id=finding.probe_id,
            endpoint=finding.endpoint,
            severity=finding.severity,
            title=finding.title,
            evidence=quote_evidence(finding.evidence[:MAX_EVIDENCE_CHARS]),
            question=quote_evidence(question[:MAX_EVIDENCE_CHARS]),
        )

    async def propose_scan(self, request: str, available_commands: list[str]) -> Draft:
        """Compose a command for the operator to run. It is never run here.

        The assistant is a command *composer*, not a command *executor*: a
        composed command still goes through every scope check when a human
        chooses to run it, and there is no path from this method to a target.

        There is no guard call here because there is nothing to guard — this
        method returns text. `refuse_target_touching` belongs at the point
        where something tries to *act*, which is why `execute()` does not
        exist on this class at all.
        """
        return await self._draft(
            Capability.PROPOSE_SCAN,
            PromptTemplate(
                id="assistant.propose_scan",
                version="1.0.0",
                system=EXPLAIN_FINDING.system,
                template=(
                    "Compose the command an operator should run for this request. "
                    "Output the command only. Use exclusively these commands: "
                    "{commands}.\n\nRequest:\n{request}"
                ),
            ),
            commands=", ".join(available_commands),
            request=quote_evidence(request[:MAX_EVIDENCE_CHARS]),
        )

    async def _draft(
        self, capability: Capability, template: PromptTemplate, **values: str
    ) -> Draft:
        require(self._mode, capability)
        provider = self._require_provider()

        completion: Completion = await provider.generate(
            template.render(**values), system=template.system
        )
        return Draft(
            capability=capability,
            content=completion.text,
            model=completion.model,
            provider=provider.name,
            prompt_template_id=template.id,
            prompt_template_version=template.version,
            tokens_sent=completion.tokens_sent,
            tokens_received=completion.tokens_received,
        )
