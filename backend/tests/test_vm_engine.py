"""The VM engine's control flow: gating and finding shape — exercised with
an injected `scan` double rather than a real `nmap` binary or live host, the
same reason `ContainerEngine`'s tests inject `pull`/`scan`/`remove` instead
of reaching for a real Docker daemon.
"""

from __future__ import annotations

from app.core.appsec.tooling import ToolResult
from app.core.vm.contract import VmTarget
from app.core.vm.engine import VmEngine

_XML = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
</ports>
</host>
</nmaprun>
"""


def _ok(stdout: str = "<nmaprun></nmaprun>") -> ToolResult:
    return ToolResult(ran=True, exit_code=0, stdout=stdout, stderr="")


def _failed(reason: str) -> ToolResult:
    return ToolResult(ran=False, exit_code=None, stdout="", stderr="", reason=reason)


async def test_an_empty_port_allowlist_is_a_visible_gap_and_never_scans() -> None:
    calls = []

    async def scan(target: VmTarget) -> ToolResult:
        calls.append(target)
        return _ok()

    engine = VmEngine(scan=scan)
    target = VmTarget(host="host.example.test", allowed_ports=())

    findings, open_ports, invocations = await engine.run(target)

    assert calls == []
    assert open_ports == []
    assert invocations == []
    assert findings[0].id == "AEGIS-VM-109"
    assert "allowed_ports is empty" in findings[0].evidence


async def test_a_host_resolving_to_a_blocked_address_is_a_visible_gap_and_never_scans() -> None:
    calls = []

    async def scan(target: VmTarget) -> ToolResult:
        calls.append(target)
        return _ok()

    engine = VmEngine(scan=scan)
    # loopback is always blocked, with no allowlist override possible via
    # this path — real DNS resolution of "localhost" always yields it.
    target = VmTarget(host="localhost", allowed_ports=(22,))

    findings, open_ports, invocations = await engine.run(target)

    assert calls == []
    assert open_ports == []
    assert invocations == []
    assert findings[0].id == "AEGIS-VM-109"
    assert "blocked address" in findings[0].evidence


async def test_a_scan_failure_is_a_visible_gap() -> None:
    async def scan(_target: VmTarget) -> ToolResult:
        return _failed("nmap is not installed on this worker")

    engine = VmEngine(scan=scan)
    target = VmTarget(host="8.8.8.8", allowed_ports=(22,))

    findings, open_ports, invocations = await engine.run(target)

    assert open_ports == []
    assert len(invocations) == 1
    assert invocations[0].tool_name == "nmap"
    assert findings[0].id == "AEGIS-VM-109"
    assert "port scan failed" in findings[0].evidence


async def test_malformed_nmap_output_is_a_visible_gap() -> None:
    async def scan(_target: VmTarget) -> ToolResult:
        return _ok("not xml at all")

    engine = VmEngine(scan=scan)
    target = VmTarget(host="8.8.8.8", allowed_ports=(22,))

    findings, open_ports, invocations = await engine.run(target)

    assert open_ports == []
    assert len(invocations) == 1
    assert findings[0].id == "AEGIS-VM-109"
    assert "not valid XML" in findings[0].evidence


async def test_a_clean_scan_still_emits_an_inventory_finding() -> None:
    """The same "coverage must show tested, not silently absent" rule
    `DomainEngine`'s subdomain-discovery finding applies — a clean scan that
    found nothing open must still show up as *tested*."""

    async def scan(_target: VmTarget) -> ToolResult:
        return _ok("<nmaprun></nmaprun>")

    engine = VmEngine(scan=scan)
    target = VmTarget(host="8.8.8.8", allowed_ports=(22, 80))

    findings, open_ports, invocations = await engine.run(target)

    assert open_ports == []
    assert len(findings) == 1
    assert findings[0].id == "AEGIS-VM-001"
    assert "None of the 2 declared port(s)" in findings[0].description
    assert len(invocations) == 1
    assert invocations[0].tool_name == "nmap"


async def test_open_ports_produce_an_inventory_and_noteworthy_port_findings() -> None:
    async def scan(_target: VmTarget) -> ToolResult:
        return _ok(_XML)

    engine = VmEngine(scan=scan)
    target = VmTarget(host="8.8.8.8", allowed_ports=(22, 6379, 8080))

    findings, open_ports, invocations = await engine.run(target)

    assert {item.port for item in open_ports} == {22, 6379, 8080}
    ids = [item.id for item in findings]
    assert ids.count("AEGIS-VM-001") == 1
    # 22 (ssh) and 8080 (http-proxy) are not in the noteworthy set; 6379
    # (redis) is.
    assert ids.count("AEGIS-VM-101") == 1

    noteworthy = next(item for item in findings if item.id == "AEGIS-VM-101")
    assert "6379" in noteworthy.title
    assert noteworthy.severity.value == "MEDIUM"
    assert noteworthy.fingerprint is not None

    inventory = next(item for item in findings if item.id == "AEGIS-VM-001")
    assert "3 of 3" in inventory.description
    assert len(invocations) == 1
