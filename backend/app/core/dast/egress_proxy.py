"""A local, scope-checking forward proxy for third-party DAST scanners.

docs/egress-security.md has the full security model; this is the summary
needed to read the code below.

Nuclei and ZAP are launched as OS subprocesses
(`app/core/appsec/tooling.py`) and open their own sockets — they cannot be
routed through `GatedTransport`, which only wraps `httpx`. Until this
module existed, neither tool's own DNS resolution or TCP connections were
checked against the scope engine at all: a host that was clean when the
crawler checked it at crawl time could resolve to a private IP, a loopback
address, or the cloud metadata endpoint by the time the scanner actually
connected minutes later, and the scanner would follow it with nothing in
the way.

`EgressGateway` closes that gap the same way a corporate TLS-forward-proxy
would. It is a short-lived local proxy, started for the duration of one
DAST run and pointed to by Nuclei's `-proxy` flag and ZAP's
`network.connection.httpProxy.*` config, that re-resolves DNS and re-checks
the destination against *this run's* `RulesOfEngagement` immediately
before allowing a connection — never trusting that a URL cleared minutes
earlier at crawl time is still safe to connect to now.

**Known, documented limitation.** For an HTTPS target (the overwhelming
majority of real DAST targets), this proxy validates the destination host
and its freshly-resolved IP at `CONNECT` time, then relays opaque encrypted
bytes end to end — it cannot see the method, path, or headers inside the
TLS tunnel without intercepting the connection, which this platform does
not do (that would need a locally-trusted CA and a certificate per target,
a materially larger and riskier change than closing the egress hole).
Path/method/header-level `RulesOfEngagement` rules therefore do not apply
to HTTPS traffic through this gateway — only the domain allowlist and the
private/loopback/link-local/metadata/CIDR IP-blocking rules do, which is
exactly the protection against SSRF and DNS rebinding that was missing.
A redirect or spider-discovered link to a *different* host still gets its
own fresh `CONNECT` and is independently re-checked, so Nuclei or ZAP
cannot pivot to an unauthorized host mid-scan even though the proxy cannot
see inside an established tunnel.

Budget reservation is deliberately not performed here either: Nuclei's
`-rate-limit` and ZAP's own scan-window flags already bound these tools'
own request volume, and `BudgetTracker` was designed around one request at
a time, not an opaque third-party tool's full traffic. Scope enforcement —
the security boundary — is what this module adds; request accounting is
not claimed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver, SystemDnsResolver
from app.core.scope.hostmatch import hostname_matches_any, is_blocked_ip, parse_ip_ranges
from app.core.scope.models import ScopeDecision

logger = logging.getLogger(__name__)

_CONNECT_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
_FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\n\r\n"
_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
_RELAY_CHUNK = 65536
_DEFAULT_HTTPS_PORT = 443
_DEFAULT_HTTP_PORT = 80


@dataclass(frozen=True)
class ConnectCheck:
    """The result of re-validating one destination at connect time."""

    decision: ScopeDecision
    resolved_ip: str | None


class EgressGateway:
    """One instance per DAST run.

    Used as an async context manager: started before the first scanner
    invocation for a run, stopped once that run's scanners have finished.
    Every CONNECT (or absolute-URI HTTP request) the scanner sends through
    it is independently re-checked against `ctx.roe` with fresh DNS — there
    is no per-run cache of "this host was fine earlier."
    """

    def __init__(
        self,
        ctx: RunContext,
        *,
        dns_resolver: DnsResolver | None = None,
    ) -> None:
        self._ctx = ctx
        self._dns_resolver = dns_resolver or SystemDnsResolver()
        self._server: asyncio.AbstractServer | None = None
        self._port: int | None = None
        #: Every decision made this run, for the caller to log/audit. Kept
        #: here rather than requiring a callback, because scanner traffic can
        #: be voluminous and the caller may only want it after the fact.
        self.decisions: list[ScopeDecision] = []

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError("EgressGateway has not been started")
        return self._port

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def __aenter__(self) -> EgressGateway:
        await self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.stop()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, host="127.0.0.1", port=0)
        sockets = self._server.sockets or ()
        if not sockets:
            raise RuntimeError("egress gateway failed to bind a local port")
        self._port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        server, self._server = self._server, None
        self._port = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def check_target(self, host: str, port: int) -> ConnectCheck:
        """Re-resolve DNS and re-check `host` against this run's scope
        *right now*, not against whatever the crawler decided minutes ago.

        Deliberately narrower than `ScopeEngine._check_url_shape`: a CONNECT
        tunnel has no method, path, or headers to check, and checking the
        run's halted/kill-switch/authorization-expiry state here too would
        duplicate state best read from one place — the caller is expected to
        check `ctx.halted`/`ctx.kill_switch` itself before relaying (and
        `_serve` below does exactly that).
        """
        host = (host or "").strip()
        if not host:
            return ConnectCheck(
                ScopeDecision(False, "unparseable_target", "no host given"), None
            )

        roe = self._ctx.roe
        if hostname_matches_any(host, roe.excluded_domains):
            return ConnectCheck(
                ScopeDecision(False, "excluded_domain", f"{host} is explicitly excluded"), None
            )
        if not hostname_matches_any(host, roe.allowed_domains):
            return ConnectCheck(
                ScopeDecision(False, "domain_not_allowlisted", f"{host} is not allowlisted"),
                None,
            )

        try:
            ips = await self._dns_resolver.resolve(host)
        except Exception as exc:  # noqa: BLE001 - an unresolvable host is a normal outcome
            return ConnectCheck(
                ScopeDecision(
                    False,
                    "dns_resolution_failed",
                    f"{host} could not be resolved ({exc}); refusing to connect",
                ),
                None,
            )

        if not ips:
            return ConnectCheck(
                ScopeDecision(False, "dns_resolution_failed", f"{host} resolved to no addresses"),
                None,
            )

        allowed_ranges = parse_ip_ranges(roe.allowed_ip_ranges)
        for ip in ips:
            if is_blocked_ip(ip, allowed_ranges):
                return ConnectCheck(
                    ScopeDecision(False, "blocked_ip", f"{host} resolved to blocked IP {ip}"),
                    None,
                )

        # Pin the exact address that was just checked — the scanner's own
        # socket connects to this literal IP, not to the hostname again, so
        # nothing can rebind between the check above and the connection
        # below.
        return ConnectCheck(ScopeDecision(True, "allow", "target is in scope"), str(ips[0]))

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._serve(reader, writer)
        except Exception as exc:  # noqa: BLE001 - fail closed: drop, never crash the server
            logger.debug("egress gateway connection ended: %s", exc)
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._ctx.halted or self._ctx.kill_switch.tripped:
            writer.write(_FORBIDDEN)
            await writer.drain()
            return

        request_line = await reader.readline()
        if not request_line:
            return
        header_blob = await reader.readuntil(b"\r\n\r\n")

        parts = request_line.decode("latin-1").strip().split(" ", 2)
        if len(parts) != 3:
            writer.write(_FORBIDDEN)
            await writer.drain()
            return
        method, target, _version = parts

        if method.upper() == "CONNECT":
            host, _, port_str = target.rpartition(":")
            port = int(port_str) if port_str.isdigit() else _DEFAULT_HTTPS_PORT
        else:
            parsed = urlsplit(target)
            host = parsed.hostname or ""
            port = parsed.port or (
                _DEFAULT_HTTPS_PORT if parsed.scheme == "https" else _DEFAULT_HTTP_PORT
            )

        check = await self.check_target(host, port)
        self.decisions.append(check.decision)
        if not check.decision.allowed or check.resolved_ip is None:
            writer.write(_FORBIDDEN)
            await writer.drain()
            return

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                check.resolved_ip, port
            )
        except OSError:
            writer.write(_BAD_GATEWAY)
            await writer.drain()
            return

        try:
            if method.upper() == "CONNECT":
                writer.write(_CONNECT_OK)
                await writer.drain()
            else:
                # Relaying, not rewriting: the original request line and
                # headers go upstream byte for byte.
                upstream_writer.write(request_line)
                upstream_writer.write(header_blob)
                await upstream_writer.drain()

            await self._relay(reader, writer, upstream_reader, upstream_writer)
        finally:
            with contextlib.suppress(Exception):
                upstream_writer.close()

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await src.read(_RELAY_CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.write_eof()

        await asyncio.gather(
            pump(client_reader, upstream_writer),
            pump(upstream_reader, client_writer),
        )
