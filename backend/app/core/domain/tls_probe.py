"""TLS certificate inspection.

`httpx`/`GatedTransport` do not surface peer-certificate details, so
inspecting a certificate needs its own raw connection — but it must not
become a second, unchecked way to reach an address. Before connecting, this
resolves the hostname through the same `DnsResolver` every scope check uses
and applies the identical `is_blocked_ip`/`allowed_ip_ranges` check
`ScopeEngine` would, then connects to the resolved address directly (never
re-resolving at connect time, which is exactly the DNS-rebinding gap the
scope engine's own no-caching resolver exists to close).
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver
from app.core.scope.hostmatch import is_blocked_ip, parse_ip_ranges

DEFAULT_TLS_PORT = 443
DEFAULT_TIMEOUT_SECONDS = 10.0


class TlsProbeError(Exception):
    """The certificate could not be inspected — refused, unreachable, or the
    handshake failed. Recorded as a coverage gap, never retried a second way."""


@dataclass(frozen=True)
class TlsCertificateInfo:
    subject_common_name: str | None
    not_after: datetime
    protocol_version: str | None
    cipher_name: str | None

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.not_after

    @property
    def days_until_expiry(self) -> int:
        return (self.not_after - datetime.now(UTC)).days


def _connect_and_inspect(
    address: str, hostname: str, port: int, timeout_seconds: float
) -> TlsCertificateInfo:
    context = ssl.create_default_context()
    with (
        socket.create_connection((address, port), timeout=timeout_seconds) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as tls_sock,
    ):
        cert = tls_sock.getpeercert()
        if not cert or "notAfter" not in cert:
            raise TlsProbeError(f"{hostname} presented no usable certificate")
        not_after_str = cast(str, cert["notAfter"])
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        subject_rdns = cast("tuple[tuple[tuple[str, str], ...], ...]", cert.get("subject", ()))
        subject = dict(rdn[0] for rdn in subject_rdns)
        cipher = tls_sock.cipher()
        return TlsCertificateInfo(
            subject_common_name=subject.get("commonName"),
            not_after=not_after,
            protocol_version=tls_sock.version(),
            cipher_name=cipher[0] if cipher else None,
        )


async def probe_tls_certificate(
    ctx: RunContext,
    dns_resolver: DnsResolver,
    hostname: str,
    *,
    port: int = DEFAULT_TLS_PORT,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> TlsCertificateInfo:
    try:
        ips = await dns_resolver.resolve(hostname)
    except Exception as exc:  # noqa: BLE001 - unresolvable is a normal, reportable outcome
        raise TlsProbeError(f"{hostname} could not be resolved: {exc}") from exc
    if not ips:
        raise TlsProbeError(f"{hostname} resolved to no addresses")

    allowed_ranges = parse_ip_ranges(ctx.roe.allowed_ip_ranges)
    for ip in ips:
        if is_blocked_ip(ip, allowed_ranges):
            raise TlsProbeError(f"{hostname} resolved to blocked address {ip}")

    address = str(ips[0])
    try:
        return await asyncio.to_thread(
            _connect_and_inspect, address, hostname, port, timeout_seconds
        )
    except TlsProbeError:
        raise
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        raise TlsProbeError(f"TLS handshake with {hostname} failed: {exc}") from exc
