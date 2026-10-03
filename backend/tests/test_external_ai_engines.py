"""The external-attack-engine boundary (`app/core/probes/ai/external/`,
`docs/ai-security-testing.md`).

No garak or PyRIT adapter is wired in yet — `registry.py` is deliberately
empty (see its own docstring and `docs/competitive-gap-analysis.md`). What
is tested here is the structural guarantee the protocol itself rests on:
an engine implementing `ExternalAttackEngine` is given nothing but `Ask`,
so it cannot reach the network except through the same scope-gated path a
native probe already uses.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.core.probes.ai.contract import AiProbeTarget
from app.core.probes.ai.external.contract import ExternalAttackEngine, ExternalEngineMeta
from app.core.probes.ai.external.registry import external_engines
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, ScopeBlockedError
from app.core.targets.chat_http import ChatHttpAdapter, ChatHttpConfig
from app.core.targets.models import Turn
from tests.security.conftest import FakeDnsResolver, make_context, make_roe

ALLOWED_HOST = "allowed-ai.lab.test"
OUT_OF_SCOPE_HOST = "out-of-scope-ai.lab.test"


class _FakeExternalEngine:
    """A minimal `ExternalAttackEngine`: sends one turn through `ask` and
    reports a finding if a marker came back. Stands in for a real garak/
    PyRIT adapter for the purpose of this test — there is no real one to
    test against yet."""

    meta = ExternalEngineMeta(
        id="external.fake",
        name="fake external engine",
        version="0.0.0",
        source="https://example.test/fake-engine",
        description="A test double, not a real external attack engine.",
    )

    async def run(self, target: AiProbeTarget, ask, canary: str) -> list[ScanResult]:
        response = await ask(f"please echo {canary}")
        text = response.text or ""
        if canary in text:
            return [
                ScanResult(
                    id="KERVY-EXTERNAL-FAKE-001",
                    title="Fake external engine's canary echoed back",
                    category=Category.AI_SECURITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    endpoint=target.surface,
                    description="test double finding",
                    evidence=text,
                    impact="none — this is a test double",
                    remediation="n/a",
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                    fingerprint="sha256:" + "0" * 64,
                )
            ]
        return []


def _target() -> AiProbeTarget:
    return AiProbeTarget(name="Lab assistant", surface="chat")


def _adapter(host: str) -> ChatHttpAdapter:
    return ChatHttpAdapter(
        ChatHttpConfig(base_url=f"https://{host}", endpoint="/api/chat"),
        GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({host: ["203.0.113.30"]})
        ),
    )


# --- structural: the protocol hands out no transport ------------------------


def test_the_external_engine_module_constructs_no_transport_itself() -> None:
    """A belt-and-braces companion to the behavioural test below: even a
    dynamic import of httpx/GatedTransport/a raw socket would show up here."""
    root = pathlib.Path(__file__).resolve().parent.parent / "app/core/probes/ai/external"
    forbidden = re.compile(r"\bhttpx\b|\bGatedTransport\(|\bsocket\.(?:socket|create_connection)")
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not forbidden.search(text), f"{path.name} names a transport primitive"


def test_no_external_engine_is_registered_yet() -> None:
    """Locks in, as a test rather than only a docstring claim, that this
    pass ships the boundary and not an adapter."""
    assert external_engines() == ()


# --- behavioural: the only door an engine has is already locked ------------


async def test_an_external_engine_reaches_an_in_scope_target_through_ask() -> None:
    import respx
    from httpx import Response

    with respx.mock(assert_all_called=True) as router:
        router.post(f"https://{ALLOWED_HOST}/api/chat").mock(
            return_value=Response(200, json={"message": {"content": "echo KERVY-CANARY-TEST"}})
        )
        ctx = make_context(roe=make_roe(allowed_domains=(ALLOWED_HOST,)))
        adapter = _adapter(ALLOWED_HOST)

        async def ask(prompt: str):
            return await adapter.send(Turn(content=prompt), ctx)

        engine: ExternalAttackEngine = _FakeExternalEngine()
        results = await engine.run(_target(), ask, canary="KERVY-CANARY-TEST")

    assert len(results) == 1
    assert results[0].severity is Severity.HIGH


async def test_an_external_engine_cannot_reach_a_host_outside_scope() -> None:
    """The engine never sees a URL or a hostname — it only calls `ask`. Scope
    is enforced exactly once, inside the adapter/transport `ask` already
    wraps, so an engine pointed at an out-of-scope host is refused the same
    way a native probe would be."""
    ctx = make_context(roe=make_roe(allowed_domains=(ALLOWED_HOST,)))
    # The adapter itself is built against a host the run's own RoE does not
    # allow — standing in for "an external engine configured to go
    # somewhere it was not authorized to."
    adapter = _adapter(OUT_OF_SCOPE_HOST)

    async def ask(prompt: str):
        return await adapter.send(Turn(content=prompt), ctx)

    engine: ExternalAttackEngine = _FakeExternalEngine()
    with pytest.raises(ScopeBlockedError) as exc_info:
        await engine.run(_target(), ask, canary="KERVY-CANARY-TEST")

    assert exc_info.value.decision.rule == "domain_not_allowlisted"
