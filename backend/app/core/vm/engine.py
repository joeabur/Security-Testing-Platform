"""The VM engine: authorized port/service discovery against a declared host.

`nmap -sV` fingerprints whatever is listening on each declared port; this
engine does not itself judge a service vulnerable — deeper, tool-driven
vulnerability scanning and validation against a discovered service is the
pentest-tool architecture's own job (Pentest module Phase 6, `PentestScope
.max_depth`), layered on top of this baseline the same way the domain
engine's own TLS/header checks are the baseline a later, deeper probe would
build on. What this engine does flag on its own is a small, fixed set of
ports whose mere reachability is already noteworthy — an unencrypted or
administrative protocol, or a database commonly deployed with no
authentication — the same "the surface being reachable at all is the
finding" reasoning `app/core/domain/engine.py`'s missing-security-header
check applies to a browser-facing header.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.core.appsec.tooling import NetworkUse, ToolResult
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.vm.contract import OpenPort, ToolInvocationRecord, VmScanError, VmTarget
from app.core.vm.nmap import check_host_allowed, parse_open_ports, scan_ports

ENGINE_ID = "vm.engine"
ENGINE_VERSION = "1.0.0"

ScanFn = Callable[[VmTarget], Awaitable[ToolResult]]

# Ports flagged purely for being open, independent of what nmap's -sV
# fingerprinted — well-known unencrypted, administrative, or commonly
# unauthenticated-by-default services. Not a vulnerability scanner: this
# says the surface is reachable, never that it is misconfigured.
_NOTEWORTHY_PORTS: dict[int, str] = {
    21: "FTP (often unencrypted, anonymous login common)",
    23: "Telnet (unencrypted remote administration)",
    135: "MSRPC (Windows RPC endpoint mapper)",
    139: "NetBIOS (legacy Windows file sharing)",
    445: "SMB (frequent target for lateral movement/ransomware)",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "RDP (remote desktop, frequent brute-force target)",
    5432: "PostgreSQL",
    6379: "Redis (frequently deployed with no authentication)",
    9200: "Elasticsearch (frequently deployed with no authentication)",
    27017: "MongoDB (frequently deployed with no authentication)",
}


@dataclass
class VmEngine:
    """Injectable `scan` so tests exercise the engine's own control flow
    (gating, finding shape) without a real `nmap` binary or live host — the
    same reason `ContainerEngine` injects `pull`/`scan`/`remove`."""

    scan: ScanFn = field(default=scan_ports)

    async def run(
        self, target: VmTarget
    ) -> tuple[list[ScanResult], list[OpenPort], list[ToolInvocationRecord]]:
        if not target.allowed_ports:
            return (
                [
                    _coverage_marker(
                        target.host,
                        "asset_scope.allowed_ports is empty. Scanning a host is a live "
                        "outbound action against it, so — like every other pentest "
                        "capability on this platform — it runs only against explicitly "
                        "declared ports, never a full range.",
                    )
                ],
                [],
                [],
            )

        try:
            check_host_allowed(target)
        except VmScanError as exc:
            return [_coverage_marker(target.host, str(exc))], [], []

        started = datetime.now(UTC)
        result = await self.scan(target)
        invocation = _invocation_record(target, result, started)

        if not result.ran or result.exit_code != 0:
            reason = result.reason or (
                f"nmap exited {result.exit_code}: {result.stderr.strip()[:300]}"
            )
            return [_coverage_marker(target.host, f"port scan failed: {reason}")], [], [invocation]

        try:
            open_ports = parse_open_ports(result.stdout)
        except VmScanError as exc:
            return [_coverage_marker(target.host, str(exc))], [], [invocation]

        return _findings(target, open_ports), open_ports, [invocation]


def _invocation_record(
    target: VmTarget, result: ToolResult, started_at: datetime
) -> ToolInvocationRecord:
    return ToolInvocationRecord(
        tool_name="nmap",
        tool_version=None,
        network_use=NetworkUse.DECLARED_SERVICE.value,
        # A redacted summary — never the literal argv — the same "describe,
        # don't dump" rule `RunToolInvocation.command_summary` documents.
        command_summary=f"nmap -sV -p <declared ports> {target.host}",
        started_at=started_at,
        finished_at=datetime.now(UTC) if result.ran else started_at,
        exit_status=result.exit_code,
    )


def _findings(target: VmTarget, open_ports: list[OpenPort]) -> list[ScanResult]:
    results: list[ScanResult] = [_inventory_finding(target, open_ports)]
    for item in open_ports:
        reason = _NOTEWORTHY_PORTS.get(item.port)
        if reason is None:
            continue
        results.append(_noteworthy_port_finding(target, item, reason))
    return results


def _inventory_finding(target: VmTarget, open_ports: list[OpenPort]) -> ScanResult:
    """Unconditional, informational — the same reason `DomainEngine` always
    emits its subdomain-discovery finding: a clean scan that found nothing
    open must still show up as *tested*, not silently absent from the
    report's coverage section (`_PILLAR_PREFIXES["VM"] = ("vm.",)`)."""
    ordered = sorted(open_ports, key=lambda item: item.port)
    listed = "\n".join(_format_port_line(item) for item in ordered)
    return ScanResult(
        id="KERVY-VM-001",
        title=f"{len(open_ports)} open port(s) found on {target.host}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        endpoint=f"vm:{target.host}",
        description=(
            f"{len(open_ports)} of {len(target.allowed_ports)} declared port(s) on "
            f"{target.host} responded open."
            if open_ports
            else f"None of the {len(target.allowed_ports)} declared port(s) on "
            f"{target.host} responded open."
        ),
        evidence=listed,
        impact="None from this inventory — nmap's -sV service probe makes no exploit attempt.",
        remediation="Review the list for anything unexpected.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )


def _format_port_line(item: OpenPort) -> str:
    line = f"{item.port}/{item.protocol}  {item.service or 'unknown'}"
    if item.product:
        line += f" ({f'{item.product} {item.version}'.strip()})"
    return line


def _noteworthy_port_finding(target: VmTarget, item: OpenPort, reason: str) -> ScanResult:
    banner = f"{item.service} {item.product} {item.version}".strip()
    return ScanResult(
        id="KERVY-VM-101",
        title=f"{target.host}:{item.port} exposes {reason.split(' (')[0]}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        endpoint=f"vm:{target.host}:{item.port}",
        description=(
            f"Port {item.port}/{item.protocol} on {target.host} is open and identified as "
            f"{banner or 'an unidentified service'}. {reason}"
        ),
        evidence=banner or "(no service banner)",
        impact=(
            "An exposed administrative or legacy-protocol service is a common initial "
            "foothold or lateral-movement target; this finding says the port is "
            "reachable, not that it is misconfigured."
        ),
        remediation=(
            f"Confirm {target.host}:{item.port} needs to be reachable from this network "
            "position; if not, close it or restrict it with a firewall rule."
        ),
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
        reproduction=(f"nmap -Pn -sV -p {item.port} {target.host}",),
        fingerprint="sha256:"
        + hashlib.sha256(f"{target.host}|{item.port}".encode()).hexdigest(),
    )


def _coverage_marker(surface: str, reason: str) -> ScanResult:
    return ScanResult(
        id="KERVY-VM-109",
        title=f"Not tested: {surface}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=f"vm/{surface}",
        description=f"{reason}. This assessment says nothing about {surface}.",
        evidence=reason,
        impact="Unknown — not tested.",
        remediation=(
            "Authorize the declared ports and confirm the host is reachable, or confirm "
            "the gap is expected."
        ),
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )
