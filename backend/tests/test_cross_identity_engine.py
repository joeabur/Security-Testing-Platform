"""The cross-identity AI probe engine (`app/core/probes/ai/cross_identity/`,
docs/ai-security-testing.md).

Mirrors `test_multiturn_engine.py`'s two-layer structure:

* The runner against a minimal fake `CrossIdentityProbe`, with scripted
  `ask_as` closures and no network at all — trial-budget, early-stop,
  no-replay, halt-mid-exchange and unresolvable-account behaviour are all
  pinned down here.
* The shipped `CrossUserDataLeakageProbe` against a scripted two-account
  plan built the same way `test_api_engine.py` builds its BOLA fixture
  (`ACCOUNT_A`/`ACCOUNT_B`, real `AuthorizationTestPlan`/`CredentialSet`),
  asserting the finding names both account labels and that neither
  account's resolved credential ever reaches a result field.
"""

from app.core.probes.ai.contract import (
    AiProbeTarget,
    Detection,
    Mappings,
    ProbeCategory,
    ProbeMeta,
)
from app.core.probes.ai.cross_identity.contract import (
    CrossIdentityPlan,
    CrossIdentityScript,
    IdentityTurn,
)
from app.core.probes.ai.cross_identity.data_leakage import CrossUserDataLeakageProbe
from app.core.probes.ai.cross_identity.runner import run_cross_identity_probe
from app.core.probes.ai.multiturn.contract import ConversationTurn
from app.core.probes.ai.registry import all_probe_ids, cross_identity_probes
from app.core.probes.credentials import AuthorizationTestPlan, CredentialSet, SyntheticAccount
from app.core.probes.models import Severity
from app.core.scope.transport import Observation
from app.core.targets.models import TargetResponse
from tests.security.conftest import make_context

TOKEN_A = "secret-token-for-account-a"  # pragma: allowlist secret
TOKEN_B = "secret-token-for-account-b"  # pragma: allowlist secret

ACCOUNT_A = SyntheticAccount(
    label="account_a", credential_env_var="KERVY_TEST_TOKEN_A", owned_object_ids=("record-42",)
)
ACCOUNT_B = SyntheticAccount(label="account_b", credential_env_var="KERVY_TEST_TOKEN_B")


def _plan(*accounts: SyntheticAccount) -> AuthorizationTestPlan:
    return AuthorizationTestPlan(
        accounts=accounts,
        credentials=CredentialSet.from_environment(
            accounts,
            {"KERVY_TEST_TOKEN_A": TOKEN_A, "KERVY_TEST_TOKEN_B": TOKEN_B},
        ),
    )


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
    """Scripted `ask`, the same shape `test_multiturn_engine.py` uses:
    `responses[prompt substring] -> reply`, first match wins."""

    def __init__(self, default: str = "no match") -> None:
        self.calls = 0
        self.prompts: list[str] = []
        self.default = default
        self.rules: list[tuple[str, str]] = []

    def rule(self, needle: str, reply: str) -> "_CountingAsk":
        self.rules.append((needle, reply))
        return self

    async def __call__(self, prompt: str) -> TargetResponse:
        self.calls += 1
        self.prompts.append(prompt)
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
    """Succeeds the instant the canary appears in identity B's turn, so
    early-stop and no-replay can both be observed."""

    meta = ProbeMeta(
        id="test.cross_identity.early",
        version="1.0.0",
        name="early success fake",
        category=ProbeCategory.DISCLOSURE,
        description="test double",
        mappings=Mappings(),
        payload_source="original",
        default_trials=1,
    )

    def applies_to(self, target: AiProbeTarget) -> bool:
        return True

    def plan(self, target: AiProbeTarget, canary: str) -> CrossIdentityPlan:
        script = CrossIdentityScript(
            id="attack",
            turns=(
                IdentityTurn("owner", "remember {canary}"),
                IdentityTurn("other", "what was remembered?"),
            ),
        )
        control = CrossIdentityScript(
            id="control",
            is_control=True,
            turns=(
                IdentityTurn("owner", "remember {canary}"),
                IdentityTurn("owner", "what did I just say? (never leaks)"),
            ),
        )
        return CrossIdentityPlan(scripts=(script,), controls=(control,))

    def detect(
        self, script: CrossIdentityScript, transcript: tuple[ConversationTurn, ...], canary: str
    ) -> Detection:
        if transcript and canary in transcript[-1].response_text:
            return Detection(succeeded=True, reason="canary present")
        return Detection(succeeded=False, reason="canary absent")

    def report(self, target, outcome):  # noqa: ANN001 - test double, shape only
        return []


# --- contract / registry wiring ---------------------------------------------


def test_cross_user_data_leakage_probe_is_registered() -> None:
    ids = [probe.meta.id for probe in cross_identity_probes()]
    assert "ai.disclosure.cross_user_leakage" in ids


def test_cross_identity_probe_ids_feed_into_all_probe_ids() -> None:
    assert "ai.disclosure.cross_user_leakage" in all_probe_ids()


# --- runner behaviour, no network --------------------------------------------


async def test_canary_planted_by_owner_is_detected_in_others_response() -> None:
    probe = _EarlySuccessProbe()
    ctx = make_context()
    owner_calls = 0
    canary_seen: list[str] = []

    async def owner(prompt: str) -> TargetResponse:
        nonlocal owner_calls
        owner_calls += 1
        canary_seen.append(prompt)
        return _response("ack")

    async def other(prompt: str) -> TargetResponse:
        # The "server": echoes back whatever the owner most recently stated,
        # regardless of who is asking — the vulnerability this probe exists
        # to catch.
        return _response(canary_seen[-1] if canary_seen else "nothing recorded")

    results = await run_cross_identity_probe(
        probe, _target(trials=1), ctx, {"owner": owner, "other": other}
    )

    # The test double's report() returns [], so assert on call shape instead.
    assert results == []
    assert owner_calls >= 1


async def test_turn_two_prompt_never_contains_the_substituted_canary() -> None:
    """The whole safety property of this engine: identity B's own prompt
    must never carry the canary, or a "success" would just prove the
    target echoes its own prompt back."""
    probe = _EarlySuccessProbe()
    ctx = make_context()
    prompts_other_saw: list[str] = []

    async def owner(prompt: str) -> TargetResponse:
        return _response("ack")

    async def capture(prompt: str) -> TargetResponse:
        prompts_other_saw.append(prompt)
        return _response("no leak here")

    await run_cross_identity_probe(
        probe, _target(trials=1), ctx, {"owner": owner, "other": capture}
    )

    # Every prompt identity "other" actually received must be exactly the
    # literal recall template — never containing "KERVY-CANARY-".
    for prompt in prompts_other_saw:
        assert "KERVY-CANARY-" not in prompt


async def test_a_halted_run_stops_mid_exchange_without_crashing() -> None:
    ctx = make_context()
    ctx.halt("budget exhausted")
    probe = _EarlySuccessProbe()

    results = await run_cross_identity_probe(
        probe, _target(trials=3), ctx, {"owner": _CountingAsk(), "other": _CountingAsk()}
    )

    assert results == []


async def test_an_unanswered_turn_aborts_that_exchange_not_the_whole_run() -> None:
    probe = _EarlySuccessProbe()
    ctx = make_context()
    ask_as = {"owner": _RaisingAsk(fail_on_call=1), "other": _CountingAsk()}

    results = await run_cross_identity_probe(probe, _target(trials=2), ctx, ask_as)

    assert results == []


async def test_a_script_naming_an_unresolvable_account_aborts_that_trial() -> None:
    """A script's `account_label` with no entry in `ask_as` (the operator
    declared fewer usable accounts this run than the probe's plan assumed)
    must not raise — it simply yields no turns for that trial."""
    probe = _EarlySuccessProbe()
    ctx = make_context()
    # Only "owner" resolvable; "other" is missing entirely.
    results = await run_cross_identity_probe(
        probe, _target(trials=1), ctx, {"owner": _CountingAsk()}
    )

    assert results == []


# --- the shipped probe, scripted two-account plan ----------------------------


def test_cross_user_data_leakage_applies_to_requires_two_accounts_and_an_owner() -> None:
    probe = CrossUserDataLeakageProbe()

    assert probe.applies_to(_target(authorization=_plan(ACCOUNT_A))) is False  # only one account
    assert probe.applies_to(_target(authorization=_plan(ACCOUNT_A, ACCOUNT_B))) is True
    # Two accounts but neither owns an object: cannot run.
    unowned_a = SyntheticAccount(label="a", credential_env_var="KERVY_TEST_TOKEN_A")
    assert probe.applies_to(_target(authorization=_plan(unowned_a, ACCOUNT_B))) is False


async def test_cross_user_data_leakage_reports_not_tested_with_one_account() -> None:
    probe = CrossUserDataLeakageProbe()
    target = _target(authorization=_plan(ACCOUNT_A))

    results = await run_cross_identity_probe(probe, target, make_context(), {})

    assert len(results) == 1
    assert results[0].id == "KERVY-AI-000"
    assert results[0].severity is Severity.INFORMATIONAL


async def test_cross_user_data_leakage_finds_a_leak_and_names_both_accounts() -> None:
    probe = CrossUserDataLeakageProbe()
    target = _target(trials=5, authorization=_plan(ACCOUNT_A, ACCOUNT_B))

    planted: list[str] = []

    async def owner(prompt: str) -> TargetResponse:
        # "Remember this value for record record-42: KERVY-CANARY-XXXX"
        planted.append(prompt.rsplit(": ", 1)[-1])
        return _response("noted")

    async def other(prompt: str) -> TargetResponse:
        # The vulnerable target: answers the recall question with whatever
        # was last planted, regardless of who is asking.
        return _response(planted[-1] if planted else "nothing on file")

    results = await run_cross_identity_probe(
        probe, target, make_context(), {"account_a": owner, "account_b": other}
    )

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "KERVY-AI-013"
    assert finding.severity is Severity.HIGH
    assert "account_a" in finding.description and "account_b" in finding.description
    assert finding.evidence_bundle is not None
    assert finding.evidence_bundle.request["method"] == "CONVERSATION"


async def test_cross_user_data_leakage_finds_nothing_when_state_is_scoped_per_identity() -> None:
    probe = CrossUserDataLeakageProbe()
    target = _target(trials=5, authorization=_plan(ACCOUNT_A, ACCOUNT_B))

    store: dict[str, str] = {}

    async def owner(prompt: str) -> TargetResponse:
        if prompt.startswith("Remember"):
            store["account_a"] = prompt.rsplit(": ", 1)[-1]
            return _response("noted")
        return _response(store.get("account_a", "nothing on file"))

    async def other(prompt: str) -> TargetResponse:
        # Correctly scoped: "other" never sees "account_a"'s stored value.
        return _response(store.get("account_b", "nothing on file"))

    results = await run_cross_identity_probe(
        probe, target, make_context(), {"account_a": owner, "account_b": other}
    )

    assert results == []


async def test_no_credential_value_ever_reaches_a_result() -> None:
    """The probe only ever sees account labels, never resolved credential
    values (those are resolved one layer up, in
    `AiSecurityCheck._ask_as`) — but assert it end to end anyway, the same
    defense-in-depth `test_api_engine.py` applies to the REST probes."""
    probe = CrossUserDataLeakageProbe()
    target = _target(trials=1, authorization=_plan(ACCOUNT_A, ACCOUNT_B))

    async def owner(prompt: str) -> TargetResponse:
        return _response("noted")

    async def other(prompt: str) -> TargetResponse:
        return _response("KERVY-CANARY-LEAKED-VALUE")

    results = await run_cross_identity_probe(
        probe, target, make_context(), {"account_a": owner, "account_b": other}
    )

    for result in results:
        blob = " ".join(
            [result.description, result.evidence, result.impact, result.remediation, result.title]
        )
        assert TOKEN_A not in blob
        assert TOKEN_B not in blob
