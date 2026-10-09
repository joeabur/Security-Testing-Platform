"""Cross-identity AI probe contract.

`app/core/probes/ai/multiturn/contract.py`'s own module docstring names
this gap plainly: "a target that relies on a session/conversation id the
adapter does not carry is a different, not-yet-covered case, and this
module does not claim otherwise." This module is that case.

**Why a separate protocol from both `AiProbe` and `MultiTurnProbe`.** Both
of those drive the target through exactly one `Ask` closure — one fixed
identity for the whole probe. What this protocol needs to express is the
opposite: a sequence of turns where *who* sends each turn is itself part
of the attack. `IdentityTurn.account_label` names the `SyntheticAccount`
(app/core/probes/credentials.py) that must send that turn, and the runner
(`runner.py`) resolves it against a map of per-account `Ask` closures the
orchestrator builds from `AiProbeTarget.authorization` — the same
operator-declared test accounts the REST BOLA probe already uses.

**No transcript replay, and this is a safety property, not a style
choice.** `multiturn/runner.py` reconstructs the conversation as text and
resends it inside each prompt, because that engine has only one identity
and is testing whether behaviour shifts as more context is shown. Doing
the same thing here would hand the second identity's turn the first
identity's secret directly in its own prompt text, so a "success" would
only prove the target echoes what it was told — not that the target's own
backend correlated state across two independently-authenticated requests,
which is the entire point of a cross-identity probe. Each `IdentityTurn`
is therefore sent standalone: only the turn that is meant to *plant* the
canary ever references `{canary}` in its template.
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.core.probes.ai.contract import AiProbeTarget, Detection, ProbeMeta, ProbeOutcome
from app.core.probes.ai.multiturn.contract import ConversationTurn
from app.core.probes.models import ScanResult

__all__ = [
    "CrossIdentityPlan",
    "CrossIdentityProbe",
    "CrossIdentityScript",
    "IdentityTurn",
]


@dataclass(frozen=True)
class IdentityTurn:
    """One turn template, and which operator-declared account must send it.

    `account_label` must match a `SyntheticAccount.label` the target's
    `AuthorizationTestPlan` declares (app/core/probes/credentials.py); the
    runner resolves it against the per-account `Ask` map and aborts that
    trial, rather than guessing, if no credential is resolvable for it.
    """

    account_label: str
    prompt_template: str


@dataclass(frozen=True)
class CrossIdentityScript:
    """A fixed sequence of identity turns: one technique, or its control."""

    id: str
    turns: tuple[IdentityTurn, ...]
    is_control: bool = False
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class CrossIdentityPlan:
    """What a probe wants run: adversarial cross-identity scripts and their
    controls — the cross-identity analogue of `ProbePlan`/`MultiTurnPlan`."""

    scripts: tuple[CrossIdentityScript, ...]
    controls: tuple[CrossIdentityScript, ...] = ()


@runtime_checkable
class CrossIdentityProbe(Protocol):
    meta: ProbeMeta

    def applies_to(self, target: AiProbeTarget) -> bool: ...

    def plan(self, target: AiProbeTarget, canary: str) -> CrossIdentityPlan: ...

    def detect(
        self, script: CrossIdentityScript, transcript: tuple[ConversationTurn, ...], canary: str
    ) -> Detection: ...

    def report(self, target: AiProbeTarget, outcome: ProbeOutcome) -> list[ScanResult]: ...
