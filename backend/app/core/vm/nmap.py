"""Scanning an authorized VM host for open ports/services (Pentest module
Phase 5).

`nmap` does not route through `GatedTransport`, so the controls the
transport would have applied are applied here first, before `nmap` ever
starts — the same pattern `app/core/container/pull.py` already established
for `docker pull`:

* **The scan is restricted to exactly `asset_scope.allowed_ports`**, never a
  full port range — the same "declaring is authorizing, nothing more" rule
  `check_registry_allowed` applies to a registry allowlist.
* **The resolved address is checked against the scope engine's own blocked
  ranges** (`is_blocked_ip`), not a second implementation — a host that is
  declared but resolves to loopback, an RFC1918 address, or the cloud
  metadata service is still refused.
"""

from __future__ import annotations

import ipaddress
from xml.etree import ElementTree

from app.core.appsec.checkout import HostResolver, default_host_resolver
from app.core.appsec.tooling import NetworkUse, ToolInvocation, ToolResult, run_tool
from app.core.scope.hostmatch import is_blocked_ip, parse_ip_ranges
from app.core.vm.contract import OpenPort, VmScanError, VmTarget

SCAN_TIMEOUT_SECONDS = 300


def check_host_allowed(
    target: VmTarget,
    *,
    allowed_ip_ranges: tuple[str, ...] = (),
    resolver: HostResolver | None = None,
) -> None:
    """Refuse a host that resolves to a blocked address.

    Unlike `check_registry_allowed`'s registry allowlist, there is no
    separate name-allowlist step here: `VmTarget.host` already *is* the one
    declared host, so there is nothing to match it against — only the
    resolved-address check applies.
    """
    resolve = resolver or default_host_resolver
    try:
        addresses = [ipaddress.ip_address(value) for value in resolve(target.host)]
    except (OSError, ValueError) as exc:
        raise VmScanError(f"could not resolve host {target.host!r}: {exc}") from exc

    if not addresses:
        raise VmScanError(f"host {target.host!r} did not resolve to any address")

    ranges = parse_ip_ranges(allowed_ip_ranges)
    for address in addresses:
        if is_blocked_ip(address, ranges):
            raise VmScanError(
                f"host {target.host!r} resolves to blocked address {address}; refusing "
                "to scan a loopback, private or metadata address"
            )


async def scan_ports(target: VmTarget) -> ToolResult:
    """`nmap -Pn -sV --open`, restricted to exactly the declared ports, XML
    to stdout. `-Pn` skips host discovery — an authorized host that blocks
    ICMP is still scanned, rather than nmap wrongly reporting it down. No
    `-sS`: without root, nmap already falls back to a TCP connect scan, so
    no elevated privilege is required to run this.
    """
    ports = ",".join(str(port) for port in sorted(set(target.allowed_ports)))
    return await run_tool(
        ToolInvocation(
            command=("nmap", "-Pn", "-sV", "--open", "-p", ports, "-oX", "-", target.host),
            cwd=None,
            network=NetworkUse.DECLARED_SERVICE,
            timeout_seconds=SCAN_TIMEOUT_SECONDS,
        )
    )


def parse_open_ports(xml_text: str) -> list[OpenPort]:
    """Parse nmap's `-oX` XML into `OpenPort`s.

    Only ports nmap itself reports `state="open"` are kept — `--open`
    already filters at the tool level, but a defensive re-check here means
    a future flag change can never silently turn a closed port into a
    finding.
    """
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        raise VmScanError(f"nmap produced output that is not valid XML: {exc}") from exc

    results: list[OpenPort] = []
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_id = port_el.get("portid")
            if port_id is None or not port_id.isdigit():
                continue
            service_el = port_el.find("service")
            results.append(
                OpenPort(
                    port=int(port_id),
                    protocol=port_el.get("protocol") or "tcp",
                    service=(service_el.get("name") if service_el is not None else None) or "",
                    product=(service_el.get("product") if service_el is not None else None) or "",
                    version=(service_el.get("version") if service_el is not None else None) or "",
                )
            )
    return results
