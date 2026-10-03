"""Multi-turn AI probe contract.

`docs/ai-security-testing.md` names the gap plainly: "every probe here is
single-turn; `driver.py` calls `ask(prompt)` once per trial with no
conversation-state object." This module is the conversation-state object.

**Why a separate protocol rather than a variant of `AiProbe`.** `AiProbe.plan`
decides every prompt up front and hands the whole set to the driver, which
is exactly right for a technique that does not depend on how the target
replies. A multi-turn attack is the opposite by definition: whether turn 2
is sent, and what it says, can depend on turn 1's response. Forcing that
into `plan()`'s shape would mean either picking turn 2 blind (not actually
multi-turn) or smuggling an adaptive decision into `detect()` (not what
`detect()` is for). So this protocol keeps the parts of `AiProbe` that
still fit unchanged — `ProbeMeta`, `Detection`, `AiProbeTarget`, `Ask`, and
the final `report()` step — and replaces only `plan`/`detect` with a shape
that can look at the transcript so far before deciding what comes next.

**How a conversation is actually carried, honestly.** `Ask` is, and stays,
`Callable[[str], Awaitable[TargetResponse]]` — one string in, one response
out, exactly what every existing adapter already implements. No adapter
here is given a message array or a session id to thread through; extending
the wire protocol of every `ConversationalAdapter` to carry one is a larger,
separate change (`docs/ai-security-testing.md` tracks it as such). Instead
the runner (`runner.py`) builds the transcript itself and replays it as text
inside each prompt it sends — the same technique a human tester uses
against a chat UI with no API access to its session. That means what this
engine measures is whether a target's behaviour shifts as it is shown an
escalating conversation, not whether a target's own *server-side* session
memory can be subverted across independent requests — a target that relies
on a session/conversation id the adapter does not carry is a different,
not-yet-covered case, and this module does not claim otherwise.
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from app.core.probes.ai.contract import AiProbeTarget, Detection, ProbeMeta, ProbeOutcome
from app.core.probes.models import ScanResult

__all__ = [
    "ConversationScript",
    "ConversationTurn",
    "MultiTurnPlan",
    "MultiTurnProbe",
]


@dataclass(frozen=True)
class ConversationTurn:
    """One turn actually sent and answered.

    `response_text` is already redacted by the runner before this object is
    built — the same "redact once, centrally" rule `TrialRecord` documents
    applies here for the identical reason: a probe that has to remember to
    redact is a probe that eventually forgets.
    """

    turn_index: int
    prompt: str
    response_text: str


@dataclass(frozen=True)
class ConversationScript:
    """A fixed sequence of turn templates: one technique, or its control.

    `{canary}` in a turn template is substituted by the runner, the same
    convention `Attempt.prompt` templates use today. Turns run in order;
    each later template may itself reference nothing about earlier turns —
    the runner supplies that context by replaying the transcript, so a
    script only has to say what *it* adds at each step.
    """

    id: str
    turns: tuple[str, ...]
    is_control: bool = False
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class MultiTurnPlan:
    """What a probe wants run: adversarial conversation scripts and their
    controls — the multi-turn analogue of `ProbePlan`."""

    scripts: tuple[ConversationScript, ...]
    controls: tuple[ConversationScript, ...] = ()


@runtime_checkable
class MultiTurnProbe(Protocol):
    meta: ProbeMeta

    def applies_to(self, target: AiProbeTarget) -> bool: ...

    def plan(self, target: AiProbeTarget, canary: str) -> MultiTurnPlan: ...

    def detect(
        self, script: ConversationScript, transcript: tuple[ConversationTurn, ...], canary: str
    ) -> Detection: ...

    def report(self, target: AiProbeTarget, outcome: ProbeOutcome) -> list[ScanResult]: ...


# `Ask` itself is not redefined here: `runner.py` imports it straight from
# `app.core.probes.ai.contract`, unchanged. The driver and the multi-turn
# runner reach the target through the identical scope-gated callable, so a
# probe suite can be driven by anything that can answer a prompt regardless
# of which runner is driving it.
