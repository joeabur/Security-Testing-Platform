"""The plugin system (docs/BUILD_SPEC.md §16, §26 Phase 11).

Phase 11's acceptance criteria are that the example plugin from the docs loads
and runs, and that a test proves a plugin cannot bypass the scope engine. Both
are here, and the second one is asserted three ways, because it is the claim
the whole plugin system rests on:

* the contract hands out no raw client,
* a request a plugin makes through the contract is refused when out of scope,
* and a plugin's spend counts against the run's budget like anyone else's.
"""

import pathlib
import re
from typing import Any

import httpx
import pytest
import respx

from app.core.discovery.openapi import DiscoveredOperation
from app.core.orchestrator.plugin_check import PluginCheck
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, ScopeBlockedError
from app.plugins.allowlist import (
    AllowedPackage,
    PluginPolicy,
    distribution_hash,
    load_policy,
)
from app.plugins.contract import (
    GROUPS,
    PluginContext,
    PluginError,
    PluginKind,
    PluginRecord,
    validate_security_test,
)
from app.plugins.registry import discover
from tests.plugins.example_probe import HeaderReflectionProbe
from tests.security.conftest import FakeDnsResolver, make_budgets, make_context, make_roe

LAB_HOST = "plugin-lab.test"
LAB_URL = f"https://{LAB_HOST}"
EXAMPLE_PATH = pathlib.Path(__file__).resolve().parent / "plugins" / "example_probe.py"
DOCS = pathlib.Path(__file__).resolve().parents[2] / "docs" / "plugin-development.md"


# --- fixtures for driving a plugin ----------------------------------------


def _operations() -> tuple[DiscoveredOperation, ...]:
    return (
        DiscoveredOperation(method="GET", path="/api/echo", operation_id="echo"),
        DiscoveredOperation(method="POST", path="/api/write", operation_id="write"),
    )


def _target(base_url: str = LAB_URL) -> ProbeTarget:
    return ProbeTarget(base_url=base_url, operations=_operations(), safe_mode=True)


def _context(host: str = LAB_HOST, *, max_requests: int = 50) -> PluginContext:
    ctx = make_context(
        roe=make_roe(
            allowed_domains=(host,),
            allowed_methods=("GET", "POST"),
            budgets=make_budgets(max_requests=max_requests),
        )
    )
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({host: ["203.0.113.50"]})
    )
    return PluginContext(ctx=ctx, transport=transport, safe_mode=True)


def _reflecting_app(request: httpx.Request) -> httpx.Response:
    """Echoes the probe's header back, which is what it is looking for."""
    marker = request.headers.get("X-Kervy-Example", "")
    return httpx.Response(200, json={"seen": marker}, headers={"X-Echo": marker})


def _quiet_app(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


# --- the example from the docs --------------------------------------------


def test_the_documented_example_is_the_code_that_runs() -> None:
    """The docs cannot drift from the file.

    §26 Phase 11 requires the example plugin from the docs to load and run. An
    example that has quietly stopped compiling is worse than no example, so the
    two are asserted identical rather than kept in step by hand.
    """
    blocks = re.findall(r"```python\n(.*?)```", DOCS.read_text(encoding="utf-8"), re.DOTALL)
    assert blocks, "no python block in docs/plugin-development.md"
    assert EXAMPLE_PATH.read_text(encoding="utf-8") in blocks, (
        f"the example in docs/plugin-development.md is not the contents of {EXAMPLE_PATH.name}"
    )


async def test_the_example_plugin_loads_and_runs() -> None:
    probe = HeaderReflectionProbe()
    validate_security_test(probe, source="example")

    context = _context()
    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=_reflecting_app)
        found = await probe.run(_target(), context)

    assert len(found) == 1
    assert found[0].id == "EXAMPLE-001"
    assert found[0].severity is Severity.LOW
    assert "X-Echo" in found[0].evidence or "response body" in found[0].evidence
    assert found[0].reproduction


async def test_the_example_plugin_finds_nothing_against_a_target_that_does_not_reflect() -> None:
    context = _context()
    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=_quiet_app)
        found = await HeaderReflectionProbe().run(_target(), context)
    assert found == []


# --- the scope boundary ---------------------------------------------------


async def test_a_plugin_cannot_reach_a_host_outside_the_targets_scope() -> None:
    """The acceptance criterion, exercised end to end.

    The plugin is pointed at a host the Rules of Engagement do not allow. The
    request it makes through the gated transport is refused, and the plugin
    reports nothing — it has no other way out.
    """
    context = _context(host=LAB_HOST)
    with respx.mock(assert_all_called=False) as router:
        outside = router.route(host="evil.test").mock(side_effect=_reflecting_app)
        found = await HeaderReflectionProbe().run(_target("https://evil.test"), context)

    assert found == []
    assert not outside.called, "the scope engine let a plugin's request through"


async def test_the_refusal_reaches_a_plugin_as_an_exception_it_cannot_ignore() -> None:
    """A plugin that swallows the refusal still gets no response — there is no
    partial success to build a finding from."""
    context = _context(host=LAB_HOST)
    with pytest.raises(ScopeBlockedError):
        await context.transport.send(context.ctx, method="GET", url="https://evil.test/api/echo")


def test_the_plugin_contract_exposes_no_raw_http_client() -> None:
    """Structural, not behavioural: there must be no attribute on anything a
    plugin is handed that yields an ungated client.

    §16 claims no sandbox, so this is not a claim that a determined plugin
    cannot import httpx itself. It is the narrower, checkable promise: a plugin
    that stays inside the contract has no way to make an unchecked request.
    """
    context = _context()
    for holder in (context, context.ctx, context.transport):
        for name in dir(holder):
            if name.startswith("_"):
                continue
            value = getattr(holder, name, None)
            assert not isinstance(value, httpx.AsyncClient | httpx.Client), (
                f"{type(holder).__name__}.{name} hands a plugin a raw HTTP client"
            )


async def test_a_plugins_requests_count_against_the_runs_budget() -> None:
    """A plugin cannot spend more than the operator allowed. Two GET operations
    are exposed and the budget permits one request, so the second is refused."""
    context = _context(max_requests=1)
    with respx.mock(assert_all_called=False) as router:
        route = router.route(host=LAB_HOST).mock(side_effect=_reflecting_app)
        await HeaderReflectionProbe().run(
            ProbeTarget(
                base_url=LAB_URL,
                operations=(
                    DiscoveredOperation(method="GET", path="/api/a", operation_id="a"),
                    DiscoveredOperation(method="GET", path="/api/b", operation_id="b"),
                ),
                safe_mode=True,
            ),
            context,
        )
    assert route.call_count == 1


# --- discovery and the allowlist -----------------------------------------


class _Distribution:
    def __init__(self, name: str, version: str = "1.2.3") -> None:
        self.name = name
        self.version = version


class _Entry:
    """An entry point, duck-typed so a test need not install a package."""

    def __init__(self, name: str, obj: Any, distribution: str | None = "kervy-plugin-example"):
        self.name = name
        self.group = "kervy.probes"
        self._obj = obj
        self.dist = _Distribution(distribution) if distribution else None

    def load(self) -> Any:
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


@pytest.fixture
def entries(monkeypatch: pytest.MonkeyPatch):
    """Inject entry points, so discovery is exercised without a real install."""
    from app.plugins import registry

    def _install(items: list[_Entry]) -> None:
        monkeypatch.setattr(
            registry,
            "_entry_points",
            lambda group: [item for item in items if item.group == group],
        )

    return _install


def _allowed() -> PluginPolicy:
    return PluginPolicy(enabled=True, allowlist=(AllowedPackage(name="kervy-plugin-example"),))


def test_nothing_loads_when_discovery_is_off(entries) -> None:
    """`pip install` must not be what decides which code runs inside the scope
    engine's process."""
    entries([_Entry("reflection", HeaderReflectionProbe)])
    result = discover(PluginPolicy.disabled())
    assert result.loaded == []


def test_an_unlisted_package_is_refused_with_a_reason(entries) -> None:
    entries([_Entry("reflection", HeaderReflectionProbe, distribution="something-else")])
    result = discover(_allowed())

    assert result.loaded == []
    assert "not in plugins.allowlist" in result.refused[0]


def test_an_allowlisted_package_loads(entries) -> None:
    entries([_Entry("reflection", HeaderReflectionProbe)])
    result = discover(_allowed())

    assert len(result.loaded) == 1
    record = result.loaded[0]
    assert record.name == "example.header_reflection"
    assert record.kind is PluginKind.PROBE
    assert record.version == "1.2.3"
    assert not record.first_party


def test_a_plugin_of_unknown_provenance_is_refused(entries) -> None:
    """A plugin the platform cannot attribute cannot be allowed: there is no
    package name to check against the allowlist."""
    entries([_Entry("reflection", HeaderReflectionProbe, distribution=None)])
    result = discover(_allowed())
    assert result.loaded == []
    assert "unknown-distribution" in result.refused[0]


def test_invalid_metadata_is_refused_loudly(entries) -> None:
    """§16: invalid metadata fails loudly. A finding that cannot be attributed
    to an id reaches a report looking like every other finding."""

    class Nameless:
        id = ""
        name = "no id"
        category = "API_SECURITY"

        async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
            return []

    entries([_Entry("nameless", Nameless)])
    result = discover(_allowed())

    assert result.loaded == []
    assert "non-empty string `id`" in result.refused[0]


def test_an_unknown_category_is_refused(entries) -> None:
    class Weird:
        id = "weird.probe"
        name = "Weird"
        category = "VIBES"

        async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
            return []

    entries([_Entry("weird", Weird)])
    result = discover(_allowed())
    assert "unknown category" in result.refused[0]


def test_one_broken_plugin_does_not_lose_the_others(entries) -> None:
    """The same principle the orchestrator applies to probes: a run with a
    visible hole beats no run."""
    entries(
        [
            _Entry("broken", ImportError("no module named nope")),
            _Entry("reflection", HeaderReflectionProbe),
        ]
    )
    result = discover(_allowed())

    assert [record.name for record in result.loaded] == ["example.header_reflection"]
    assert any("failed to import" in reason for reason in result.refused)


def test_the_banner_names_every_third_party_plugin(entries) -> None:
    entries([_Entry("reflection", HeaderReflectionProbe)])
    banner = discover(_allowed()).banner()

    assert "kervy-plugin-example 1.2.3" in banner
    assert "not sandboxed" in banner


def test_the_banner_says_so_when_nothing_loaded() -> None:
    """A banner that appears only sometimes is one nobody learns to read."""
    assert "no third-party plugins loaded" in discover(PluginPolicy.disabled()).banner()


def test_every_documented_entry_point_group_is_recognised() -> None:
    assert set(GROUPS) == {
        "kervy.probes",
        "kervy.detectors",
        "kervy.adapters",
        "kervy.reporters",
    }


# --- the hash pin ---------------------------------------------------------


def test_a_pinned_package_whose_hash_does_not_match_is_refused(entries) -> None:
    entries([_Entry("reflection", HeaderReflectionProbe)])
    policy = PluginPolicy(
        enabled=True,
        allowlist=(AllowedPackage(name="kervy-plugin-example", sha256="0" * 64),),
    )

    result = discover(policy)

    assert result.loaded == []
    assert "does not match its pinned hash" in result.refused[0] or (
        "could not be read" in result.refused[0]
    )


def test_a_real_installed_distribution_hashes_reproducibly() -> None:
    """The pin has to mean something, so it is computed from an installed
    package rather than asserted on a fabricated one."""
    first = distribution_hash("httpx")
    assert first is not None and len(first) == 64
    assert first == distribution_hash("httpx")
    assert distribution_hash("no-such-package-anywhere") is None


# --- policy parsing ------------------------------------------------------


def test_the_documented_configuration_parses() -> None:
    policy = load_policy(
        """
plugins:
  enabled: true
  allowlist:
    - name: kervy-plugin-example
      sha256: 3f786850e387550fdab836ed7e6dc881de23001b00000000000000000000aaaa
    - kervy-plugin-simple
"""
    )
    assert policy.enabled
    assert policy.allowlist[0].sha256 is not None
    assert policy.allowlist[1].sha256 is None


def test_absent_configuration_means_off() -> None:
    assert not load_policy("").enabled


def test_punctuation_cannot_sidestep_the_allowlist() -> None:
    """PEP 503 normalization: `Kervy_Plugin.Example` and `kervy-plugin-example`
    are the same package."""
    policy = PluginPolicy(enabled=True, allowlist=(AllowedPackage(name="Kervy_Plugin.Example"),))
    assert policy.entry_for("kervy-plugin-example") is not None


@pytest.mark.parametrize(
    "document",
    [
        "plugins:\n  enabled: yes-please\n",
        "plugins:\n  allowlist: kervy-plugin\n",
        "plugins:\n  allowlist:\n    - name: ''\n",
        "plugins:\n  allowlist:\n    - name: p\n      sha256: tooshort\n",
        "plugins:\n  allowlist:\n    - name: p\n      unexpected: 1\n",
        "plugins:\n  allowlst: []\n",
        "plugins: [1, 2]\n",
    ],
)
def test_nonsense_plugin_configuration_is_refused(document: str) -> None:
    """A typo in a security control must not read as a permissive default."""
    with pytest.raises(PluginError):
        load_policy(document)


# --- attribution ---------------------------------------------------------


def _record(obj: Any, name: str = "example.header_reflection") -> PluginRecord:
    return PluginRecord(
        name=name,
        kind=PluginKind.PROBE,
        group="kervy.probes",
        distribution="kervy-plugin-example",
        version="1.2.3",
        obj=obj,
    )


async def test_a_plugin_cannot_file_findings_under_a_native_probes_name() -> None:
    """Otherwise an operator reading the report would draw conclusions about
    code that never ran."""

    class Impostor:
        id = "impostor"
        name = "Impostor"
        category = "AI_SECURITY"

        async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
            return [
                ScanResult(
                    id="KERVY-AI-001",
                    title="Direct prompt injection",
                    category=Category.AI_SECURITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    endpoint="POST /api/chat",
                    description="I am pretending to be a native probe.",
                    evidence="none",
                    impact="none",
                    remediation="none",
                    probe_id="ai.injection.direct.instruction_override",
                    probe_version="1.0.0",
                )
            ]

    check = PluginCheck(plugins=[_record(Impostor(), name="impostor")], probe_target=_target())
    context = _context()
    await check.run(context.ctx, context.transport)

    findings = [item for item in check.scan_results if item.severity is Severity.CRITICAL]
    assert len(findings) == 1
    assert findings[0].probe_id == "impostor"
    assert findings[0].probe_version == "1.2.3"


async def test_a_plugin_cannot_supply_its_own_evidence_bundle() -> None:
    """The contract gives a plugin no way to build a sealed bundle, so one
    arriving from a plugin came from somewhere the platform cannot vouch for."""
    from app.core.evidence.bundle import build_bundle

    class Forger:
        id = "forger"
        name = "Forger"
        category = "API_SECURITY"

        async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
            return [
                ScanResult(
                    id="FORGED-001",
                    title="Forged",
                    category=Category.API_SECURITY,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    endpoint="GET /",
                    description="d",
                    evidence="e",
                    impact="i",
                    remediation="r",
                    probe_id="forger",
                    probe_version="1.0.0",
                    evidence_bundle=build_bundle(
                        probe_id="forger",
                        probe_version="1.0.0",
                        method="GET",
                        url="https://forged.test/",
                    ),
                )
            ]

    check = PluginCheck(plugins=[_record(Forger(), name="forger")], probe_target=_target())
    context = _context()
    await check.run(context.ctx, context.transport)

    forged = [item for item in check.scan_results if item.id == "FORGED-001"]
    assert len(forged) == 1
    assert forged[0].evidence_bundle is None


async def test_a_run_that_loaded_a_plugin_records_that_it_did() -> None:
    """§14's coverage honesty cuts both ways: silence about a plugin is as
    misleading as silence about an untested area."""
    check = PluginCheck(plugins=[_record(HeaderReflectionProbe())], probe_target=_target())
    context = _context()
    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=_quiet_app)
        await check.run(context.ctx, context.transport)

    notes = [item for item in check.scan_results if item.id == "KERVY-PLUGIN-900"]
    assert len(notes) == 1
    assert "kervy-plugin-example 1.2.3" in notes[0].evidence


async def test_a_plugin_that_raises_becomes_a_visible_gap() -> None:
    class Exploding:
        id = "exploding"
        name = "Exploding"
        category = "API_SECURITY"

        async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
            raise RuntimeError("boom")

    check = PluginCheck(plugins=[_record(Exploding(), name="exploding")], probe_target=_target())
    context = _context()
    outcomes = await check.run(context.ctx, context.transport)

    assert outcomes[0].ok is False
    gaps = [item for item in check.scan_results if item.id == "KERVY-PLUGIN-099"]
    assert len(gaps) == 1
    assert "Not tested" in gaps[0].title


async def test_a_halted_run_stops_calling_plugins() -> None:
    calls: list[str] = []

    class Counting:
        id = "counting"
        name = "Counting"
        category = "API_SECURITY"

        async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
            calls.append(self.id)
            return []

    check = PluginCheck(plugins=[_record(Counting(), name="counting")], probe_target=_target())
    context = _context()
    context.ctx.halt("operator stopped the run")

    await check.run(context.ctx, context.transport)
    assert calls == []


def test_a_deployment_running_no_plugins_notes_it_without_refusing_anything() -> None:
    """`refused` is per-plugin and reaches a run's event log; a deployment that
    simply runs no plugins must not file an event on every run saying so."""
    result = discover(PluginPolicy(enabled=False, warnings=("no PLUGINS_CONFIG is set",)))

    assert result.refused == []
    assert result.notes == ["no PLUGINS_CONFIG is set"]
    assert "no PLUGINS_CONFIG is set" in result.banner()
