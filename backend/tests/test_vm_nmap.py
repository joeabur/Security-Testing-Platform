"""Host gating and nmap invocation/output parsing (pentest module Phase 5).

Mirrors `test_container_pull.py`'s shape for the analogous SDK/subprocess
boundary checks in `app/core/container/pull.py`.
"""

from __future__ import annotations

import pytest

from app.core.vm.contract import VmScanError, VmTarget
from app.core.vm.nmap import check_host_allowed, parse_open_ports, scan_ports

# --- check_host_allowed ---------------------------------------------------


def _resolver_returning(*addresses: str):
    def resolver(_host: str) -> list[str]:
        return list(addresses)

    return resolver


def test_a_host_resolving_to_a_blocked_address_is_refused() -> None:
    target = VmTarget(host="internal.example.test", allowed_ports=(22,))
    with pytest.raises(VmScanError, match="blocked address"):
        check_host_allowed(target, resolver=_resolver_returning("127.0.0.1"))


def test_a_host_resolving_to_the_cloud_metadata_address_is_refused_even_if_allowlisted() -> None:
    target = VmTarget(host="internal.example.test", allowed_ports=(22,))
    with pytest.raises(VmScanError, match="blocked address"):
        check_host_allowed(
            target,
            allowed_ip_ranges=("0.0.0.0/0",),
            resolver=_resolver_returning("169.254.169.254"),
        )


def test_a_host_resolving_to_an_explicitly_allowed_private_range_is_permitted() -> None:
    target = VmTarget(host="internal.example.test", allowed_ports=(22,))
    check_host_allowed(
        target, allowed_ip_ranges=("10.0.0.0/8",), resolver=_resolver_returning("10.1.2.3")
    )


def test_a_host_resolving_to_a_public_address_is_permitted() -> None:
    target = VmTarget(host="host.example.test", allowed_ports=(22,))
    check_host_allowed(target, resolver=_resolver_returning("203.0.113.10"))


def test_an_unresolvable_host_is_refused() -> None:
    def resolver(_host: str) -> list[str]:
        raise OSError("name resolution failed")

    target = VmTarget(host="nonexistent.example.test", allowed_ports=(22,))
    with pytest.raises(VmScanError, match="could not resolve"):
        check_host_allowed(target, resolver=resolver)


def test_a_host_that_resolves_to_nothing_is_refused() -> None:
    target = VmTarget(host="host.example.test", allowed_ports=(22,))
    with pytest.raises(VmScanError, match="did not resolve to any address"):
        check_host_allowed(target, resolver=_resolver_returning())


# --- scan_ports -------------------------------------------------------------


async def test_scan_ports_reports_a_missing_nmap_binary_without_crashing(monkeypatch) -> None:
    monkeypatch.setattr("app.core.appsec.tooling.shutil.which", lambda _binary: None)
    target = VmTarget(host="host.example.test", allowed_ports=(22, 80))
    result = await scan_ports(target)
    assert not result.ran
    assert "nmap" in result.reason


# --- parse_open_ports --------------------------------------------------------

_XML_WITH_MIXED_PORTS = """<?xml version="1.0"?>
<nmaprun>
<host>
<ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port>
</ports>
</host>
</nmaprun>
"""


def test_open_ports_are_parsed_with_service_detection() -> None:
    ports = parse_open_ports(_XML_WITH_MIXED_PORTS)
    by_port = {item.port: item for item in ports}

    assert set(by_port) == {22, 80}
    assert by_port[22].protocol == "tcp"
    assert by_port[22].service == "ssh"
    assert by_port[22].product == "OpenSSH"
    assert by_port[22].version == "8.9"
    assert by_port[80].service == "http"
    assert by_port[80].product == ""
    assert by_port[80].version == ""


def test_a_closed_port_is_excluded_even_if_present_in_the_xml() -> None:
    ports = parse_open_ports(_XML_WITH_MIXED_PORTS)
    assert 443 not in {item.port for item in ports}


def test_no_hosts_element_produces_an_empty_list() -> None:
    assert parse_open_ports("<nmaprun></nmaprun>") == []


def test_malformed_xml_is_refused() -> None:
    with pytest.raises(VmScanError, match="not valid XML"):
        parse_open_ports("not xml at all <<<")
