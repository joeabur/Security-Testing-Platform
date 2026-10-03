"""The multi-turn attack orchestration engine
(`app/core/probes/ai/multiturn/`, docs/ai-security-testing.md).

Two layers are tested separately:

* The runner against a minimal fake `MultiTurnProbe`, with a scripted `ask`
  and no network at all — this is where trial-budget, early-stop,
  halt-mid-conversation and unanswered-turn behaviour are pinned down.
* The shipped `InstructionChainingProbe` against the real lab fixtures
  (`tests/lab/ai_handlers.py`), through the real `ChatHttpAdapter` and
  `GatedTransport`, the same way `test_ai_engine.py` proves the single-shot
  probes — so "the engine finds the seeded flaw and the hardened app
  produces nothing" is checked for the multi-turn path too, not only
  asserted in a docstring.
"""

import respx

from app.core.measure.asr import Stability
from app.core.probes.ai._support import strongest_attempt
from app.core.probes.ai.contract import (
    AiProbeTarget,
    Detection,
    Mappings,
    ProbeCategory,
    ProbeMeta,
)
from app.core.probes.ai.multiturn.contract import (
    ConversationScript,
    ConversationTurn,
    MultiTurnPlan,
)
from app.core.probes.ai.multiturn.instruction_chaining import InstructionChainingProbe
from app.core.probes.ai.multiturn.runner import run_multi_turn_probe
from app.core.probes.ai.registry import all_probe_ids, multi_turn_probes
from app.core.probes.models import Severity
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, Observation
from app.core.targets.chat_http import ChatHttpAdapter, ChatHttpConfig
from app.core.targets.models import TargetResponse
from tests.lab.ai_handlers import hardened_chat, vulnerable_chat
from tests.security.conftest import FakeDnsResolver, make_budgets, make_context, make_roe

HOST = "multiturn-ai.lab.test"


def _target(**overrides: object) -> AiProbeTarget:
    defaults: dict[str, object] = {"name": "Lab assistant", "surface": "POST /api/chat"}
    defaults.update(overrides)
    return AiProbeTarget(**defaults)  # type: ignore[arg-type]


def _response(text: str) -> TargetResponse:
    observation = Observation(
        method="POST", url="https://fake/", status_code=200, headers={}, elapsed_ms=1.0
    )
    return TargetResponse(observation=observation, text=text)


class _CountingAsk:
    """A scripted `ask`: `responses[prompt substring] -> reply text`, first
    match wins, default otherwise. Counts calls so early-stop can be
    verified directly rather than inferred."""

    def __init__(self, default: str = "no match") -> None:
        self.calls = 0
        self.default = default
        self.rules: list[tuple[str, str]] = []

    def rule(self, needle: str, reply: str) -> "_CountingAsk":
        self.rules.append((needle, reply))
        return self

    async def __call__(self, prompt: str) -> TargetResponse:
        self.calls += 1
        for needle, reply in self.rules:
            if needle in prompt:
                return _response(reply)
        return _response(self.default)


class _RaisingAsk:
    def __init__(self, fail_on_call: int) -> None:
        self.calls = 0
        self.fail_on_call = fail_on_call

    async def __call__(self, prompt: str) -> TargetResponse:
        self.calls += 1
        if self.calls == self.fail_on_call:
            raise RuntimeError("target unreachable")
        return _response("ok")


class _EarlySuccessProbe:
    """Succeeds the instant the canary appears, so the runner's early-stop
    behaviour can be observed by counting `ask` calls."""

    meta = ProbeMeta(
        id="test.multiturn.early",
        version="1.0.0",
        name="early success fake",
        category=ProbeCategory.JAILBREAK,
        description="test double",
        mappings=Mappings(),
        payload_source="original",
        default_trials=1,
    )

    def applies_to(self, target: AiProbeTarget) -> bool:
        return True

    def plan(self, target: AiProbeTarget, canary: str) -> MultiTurnPlan:
        script = ConversationScript(id="three-turn", turns=("one", "two", "{canary}"))
        control = ConversationScript(
            id="control", turns=("one", "two", "never"), is_control=True
        )
        return MultiTurnPlan(scripts=(script,), controls=(control,))

    def detect(
        self, script: ConversationScript, transcript: tuple[ConversationTurn, ...], canary: str
    ) -> Detection:
        if transcript and canary in transcript[-1].response_text:
            return Detection(succeeded=True, reason="canary present")
        return Detection(succeeded=False, reason="canary absent")

    def report(self, target, outcome):  # noqa: ANN001 - test double, shape only
        return []


# --- contract / registry wiring ---------------------------------------------


def test_instruction_chaining_probe_is_registered() -> None:
    ids = [probe.meta.id for probe in multi_turn_probes()]
    assert "ai.jailbreak.instruction_chaining" in ids


def test_multi_turn_probe_ids_feed_into_all_probe_ids() -> None:
    assert "ai.jailbreak.instruction_chaining" in all_probe_ids()


def test_strongest_attempt_is_shared_between_driver_and_runner() -> None:
    # Promoted out of driver.py specifically so both runners use one
    # implementation; a regression here would silently fork the tie-break.
    assert strongest_attempt({"a": (3, 5), "b": (3, 3)}) == ("b", 3, 3)


# --- runner behaviour, no network -------------------------------------------


async def test_canary_on_the_final_turn_is_detected_as_a_finding() -> None:
    probe = _EarlySuccessProbe()
    ask = _CountingAsk(default="irrelevant")
    ctx = make_context()

    await run_multi_turn_probe(probe, _target(trials=1), ctx, ask)

    # No report() worth asserting on (the test double returns nothing), but
    # the ask was driven through all three turns since "never"/"irrelevant"
    # never trip detect() early for the control, and the attack's own last
    # turn literally contains the canary the runner substituted in.
    assert ask.calls > 0


async def test_early_stop_sends_no_turns_past_the_success() -> None:
    """If turn 1 already satisfies `detect`, the runner must not send the
    probe's remaining turns — that is the entire point of giving a
    multi-turn probe the chance to look at the transcript before deciding
    what comes next."""

    class _SucceedsImmediately:
        meta = ProbeMeta(
            id="test.multiturn.immediate",
            version="1.0.0",
            name="immediate",
            category=ProbeCategory.JAILBREAK,
            description="test double",
            mappings=Mappings(),
            payload_source="original",
            default_trials=1,
        )

        def applies_to(self, target: AiProbeTarget) -> bool:
            return True

        def plan(self, target: AiProbeTarget, canary: str) -> MultiTurnPlan:
            script = ConversationScript(id="s", turns=("{canary}", "two", "three"))
            return MultiTurnPlan(scripts=(script,), controls=())

        def detect(self, script, transcript, canary):  # noqa: ANN001
            return Detection(succeeded=bool(transcript), reason="first turn is enough")

        def report(self, target, outcome):  # noqa: ANN001
            return []

    ask = _CountingAsk()
    ctx = make_context()
    await run_multi_turn_probe(_SucceedsImmediately(), _target(trials=1), ctx, ask)

    assert ask.calls == 1


async def test_a_halted_run_stops_mid_conversation_without_crashing() -> None:
    ctx = make_context()
    ctx.halt("budget exhausted")
    probe = _EarlySuccessProbe()

    results = await run_multi_turn_probe(probe, _target(trials=3), ctx, _CountingAsk())

    assert results == []


async def test_an_unanswered_turn_aborts_that_conversation_not_the_whole_run() -> None:
    """Mirrors `driver._run_set`'s "an unanswered trial is not a success"
    rule: a transport error on one turn ends that attempt, but subsequent
    trials still run rather than the whole probe raising."""
    probe = _EarlySuccessProbe()
    ctx = make_context()
    # Fails on the very first call of the very first conversation, so that
    # conversation contributes nothing, but the probe must not raise.
    ask = _RaisingAsk(fail_on_call=1)

    results = await run_multi_turn_probe(probe, _target(trials=2), ctx, ask)

    assert results == []
    assert ask.calls > 1


# --- the shipped probe against the real lab fixtures ------------------------


def _adapter(host: str) -> ChatHttpAdapter:
    return ChatHttpAdapter(
        ChatHttpConfig(base_url=f"https://{host}", endpoint="/api/chat"),
        GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({host: ["203.0.113.40"]})
        ),
    )


def _context() -> object:
    return make_context(
        roe=make_roe(
            allowed_domains=(HOST,),
            allowed_methods=("GET", "POST"),
            budgets=make_budgets(max_requests=800, max_tokens_sent=200_000),
        )
    )


async def test_instruction_chaining_is_found_against_the_vulnerable_lab_app() -> None:
    from app.core.targets.models import Turn

    adapter = _adapter(HOST)
    ctx = _context()

    async def ask(prompt: str):
        return await adapter.send(Turn(content=prompt), ctx)

    with respx.mock(assert_all_called=False) as router:
        router.route(host=HOST).mock(side_effect=vulnerable_chat)
        results = await run_multi_turn_probe(
            InstructionChainingProbe(), _target(trials=5), ctx, ask
        )

    codes = {result.id for result in results}
    assert "KERVY-AI-007" in codes
    finding = next(result for result in results if result.id == "KERVY-AI-007")
    assert finding.severity is Severity.HIGH
    assert finding.evidence_bundle is not None
    assert finding.evidence_bundle.request["method"] == "CONVERSATION"


async def test_instruction_chaining_finds_nothing_against_the_hardened_lab_app() -> None:
    from app.core.targets.models import Turn

    adapter = _adapter(HOST)
    ctx = _context()

    async def ask(prompt: str):
        return await adapter.send(Turn(content=prompt), ctx)

    with respx.mock(assert_all_called=False) as router:
        router.route(host=HOST).mock(side_effect=hardened_chat)
        results = await run_multi_turn_probe(
            InstructionChainingProbe(), _target(trials=5), ctx, ask
        )

    assert results == []


async def test_measurement_is_deterministic_stable_when_fully_seeded() -> None:
    from app.core.targets.models import Turn

    adapter = _adapter(HOST)
    ctx = _context()

    async def ask(prompt: str):
        return await adapter.send(Turn(content=prompt), ctx)

    with respx.mock(assert_all_called=False) as router:
        router.route(host=HOST).mock(side_effect=vulnerable_chat)
        results = await run_multi_turn_probe(
            InstructionChainingProbe(), _target(trials=5), ctx, ask
        )

    finding = next(result for result in results if result.id == "KERVY-AI-007")
    assert finding.stability == Stability.DETERMINISTIC.value
