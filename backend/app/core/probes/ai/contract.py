"""AI probe contract (docs/BUILD_SPEC.md §9).

§9 specifies `plan` / `run` / `detect`, and that split is kept here because
it is what makes the trials machinery possible: `plan` says what to send,
the driver sends it N times plus a control, and `detect` judges each
response in isolation. A probe that ran its own requests could not be given
trials, a baseline, or a budget without every probe reimplementing them.

Two rules from §2.2 are enforced by the shape of this module rather than by
convention:

* **Marker-based detection only.** `Attempt` carries the canary the driver
  generated for this run, and detection asks whether that marker came back.
  A probe cannot "succeed" by eliciting genuinely harmful output, because
  success is defined as the appearance of a random token.
* **Declared provenance.** `ProbeMeta.payload_source` is required, so every
  payload in the repository says where it came from.
"""

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from app.core.measure.asr import Measurement
from app.core.probes.models import ScanResult
from app.core.targets.models import Capabilities, TargetResponse

CANARY_PREFIX = "KERVY-CANARY-"


def new_canary() -> str:
    """A per-run random marker (§9: `KERVY-CANARY-<random>`).

    Random per run so that a target which has seen a previous assessment —
    or which has the string in its training data or its logs — cannot
    produce a stale marker and be reported as vulnerable.
    """
    return f"{CANARY_PREFIX}{secrets.token_hex(8).upper()}"


class ProbeCategory(StrEnum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    DISCLOSURE = "disclosure"
    HIDDEN_CONTEXT = "hidden_context"
    OUTPUT_HANDLING = "output_handling"
    EXCESSIVE_AGENCY = "excessive_agency"
    CONSUMPTION = "consumption"
    JAILBREAK = "jailbreak"
    AGENT = "agent"


@dataclass(frozen=True)
class Mappings:
    owasp_llm_2026: tuple[str, ...] = ()
    owasp_asi_2026: tuple[str, ...] = ()
    mitre_atlas: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    nist_ai_rmf: tuple[str, ...] = ()

    def as_frameworks(self) -> tuple[str, ...]:
        """Flatten to the `ScanResult.frameworks` wire form.

        MITRE ATLAS entries are only emitted where a probe declares one it
        has verified against the pinned release (§3): an unverified
        technique id looks authoritative and is worse than no mapping.
        """
        return (
            *(f"OWASP-LLM-2026:{item}" for item in self.owasp_llm_2026),
            *(f"OWASP-ASI-2026:{item}" for item in self.owasp_asi_2026),
            *(f"MITRE-ATLAS:{item}" for item in self.mitre_atlas),
            *(f"CWE-{item}" if not item.startswith("CWE") else item for item in self.cwe),
            *(f"NIST-AI-RMF:{item}" for item in self.nist_ai_rmf),
        )


@dataclass(frozen=True)
class ProbeMeta:
    id: str
    version: str
    name: str
    category: ProbeCategory
    description: str
    mappings: Mappings
    # `payload_source` is required by §2.2: every payload declares whether it
    # is original, adapted from a cited source, or generated.
    payload_source: str
    safe_mode: bool = True
    mutates_state: bool = False
    requires: Capabilities = field(default_factory=Capabilities)
    default_trials: int = 5
    cost_class: str = "low"


@dataclass(frozen=True)
class Attempt:
    """One thing to send. `is_control` marks the baseline: the same request
    with the adversarial component removed (§7.1)."""

    id: str
    prompt: str
    canary: str
    is_control: bool = False
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Detection:
    """Whether one response counts as a success, and why."""

    succeeded: bool
    reason: str
    evidence: str = ""


@dataclass(frozen=True)
class ProbePlan:
    """What a probe wants sent: adversarial attempts and their controls."""

    attempts: tuple[Attempt, ...]
    controls: tuple[Attempt, ...] = ()


@dataclass(frozen=True)
class TrialRecord:
    """One attempt's outcome, kept for evidence and reproduction (§7.2).

    `response_text` is **already redacted** when this record is built: the
    driver runs every response through `redact()` before storing it, so a
    secret a target discloses cannot reach a record, a finding, or a report
    by way of any probe — not only the one looking for secrets
    (docs/BUILD_SPEC.md §9 LLM02, §13).

    `detection_evidence` is what the probe's own detector chose to keep,
    which for a secret is a digest and a masked preview rather than a value.
    """

    attempt_id: str
    prompt: str
    is_control: bool
    succeeded: bool
    reason: str
    response_text: str
    detection_evidence: str = ""


@dataclass(frozen=True)
class ProbeOutcome:
    """Everything a probe needs to write its report."""

    measurement: Measurement
    records: tuple[TrialRecord, ...]
    canary: str
    # Which attempt the measurement is of: probes offer several framings of
    # one idea, and the measurement belongs to the strongest of them rather
    # than to their average.
    best_attempt_id: str | None = None

    def first_success(self) -> TrialRecord | None:
        """A successful trial of the measured attempt, preferred over any
        other, so the evidence shown matches the numbers reported."""
        measured = [
            record
            for record in self.records
            if record.succeeded
            and not record.is_control
            and (self.best_attempt_id is None or record.attempt_id == self.best_attempt_id)
        ]
        if measured:
            return measured[0]
        return next(
            (record for record in self.records if record.succeeded and not record.is_control), None
        )


@dataclass(frozen=True)
class AiProbeTarget:
    """What an AI probe is allowed to know about the target."""

    name: str
    surface: str
    capabilities: Capabilities = field(default_factory=Capabilities)
    safe_mode: bool = True
    # Tools the operator *declared*. §9 is explicit that a tool surface is
    # never guessed, so an empty tuple means "not declared", never "none".
    declared_tools: tuple["DeclaredTool", ...] = ()
    trials: int | None = None


@dataclass(frozen=True)
class DeclaredTool:
    """A tool the agent can call, as declared by the operator or a manifest."""

    name: str
    description: str = ""
    writes: bool = False
    irreversible: bool = False
    external: bool = False
    requires_confirmation: bool = False


@runtime_checkable
class AiProbe(Protocol):
    meta: ProbeMeta

    def applies_to(self, target: AiProbeTarget) -> bool: ...

    def plan(self, target: AiProbeTarget, canary: str) -> ProbePlan: ...

    def detect(self, attempt: Attempt, response: TargetResponse) -> Detection: ...

    def report(self, target: AiProbeTarget, outcome: ProbeOutcome) -> list[ScanResult]: ...


# How the driver reaches the target. A callable rather than the adapter type
# itself so a probe suite can be driven by anything that can answer a
# prompt — and so tests can substitute a target with known behaviour.
Ask = Callable[[str], Awaitable[TargetResponse]]
