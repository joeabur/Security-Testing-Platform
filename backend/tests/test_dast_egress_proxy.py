"""`EgressGateway` — the scope-checking forward proxy Nuclei and ZAP are now
pointed at (`app/core/dast/egress_proxy.py`, `docs/egress-security.md`).

These tests exercise the gateway as a real local TCP server (not mocked),
proving the security property end to end: a CONNECT is only tunneled when
the freshly-resolved destination clears this run's rules of engagement, and
is refused — with the upstream connection never attempted — otherwise.
"""

from __future__ import annotations

import asyncio

import pytest

from app.core.dast.egress_proxy import EgressGateway
from app.core.scope.kill_switch import KillSwitch
from tests.security.conftest import FakeDnsResolver, make_context, make_roe


async def _start_echo_server() -> tuple[asyncio.AbstractServer, int]:
    """A tiny TCP server standing in for the real DAST target: it echoes
    back whatever it receives, prefixed, so a test can prove bytes actually
    reached it (or didn't)."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(1024)
        writer.write(b"echo:" + data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]  # type: ignore[index]
    return server, port


async def _connect(
    gateway: EgressGateway, *, host: str, port: int
) -> tuple[bytes, asyncio.StreamWriter | None]:
    """Issue a raw CONNECT through the gateway. Returns the status line and,
    if the tunnel was established, the writer so the caller can push bytes
    through it."""
    reader, writer = await asyncio.open_connection("127.0.0.1", gateway.port)
    writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    await writer.drain()
    response = await reader.readuntil(b"\r\n\r\n")
    status_line = response.split(b"\r\n", 1)[0] + b"\r\n"
    if not status_line.startswith(b"HTTP/1.1 200"):
        writer.close()
        return status_line, None
    return status_line, writer, reader  # type: ignore[return-value]


@pytest.fixture
def fake_dns() -> FakeDnsResolver:
    return FakeDnsResolver()


async def test_a_connect_to_an_allowlisted_resolvable_host_is_tunneled(
    fake_dns: FakeDnsResolver,
) -> None:
    server, target_port = await _start_echo_server()
    try:
        fake_dns.set("target.test", ["127.0.0.1"])
        ctx = make_context(
            roe=make_roe(
                allowed_domains=("target.test",),
                # Loopback is blocked by default; this run's RoE deliberately
                # allows it, the same way an internal staging host would be
                # allowed — exactly what the override exists for.
                allowed_ip_ranges=("127.0.0.0/8",),
            )
        )
        async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
            status_line, writer, reader = await _connect(
                gateway, host="target.test", port=target_port
            )
            assert status_line == b"HTTP/1.1 200 Connection Established\r\n"

            writer.write(b"hello")
            await writer.drain()
            writer.write_eof()
            reply = await reader.read()
            assert reply == b"echo:hello"
            writer.close()

        assert gateway.decisions[-1].allowed is True
    finally:
        server.close()
        await server.wait_closed()


async def test_a_connect_to_a_non_allowlisted_domain_is_refused_before_connecting(
    fake_dns: FakeDnsResolver,
) -> None:
    server, target_port = await _start_echo_server()
    try:
        fake_dns.set("evil.test", ["127.0.0.1"])
        ctx = make_context(roe=make_roe(allowed_domains=("target.test",)))
        async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
            status_line, writer = (
                await _connect(gateway, host="evil.test", port=target_port)
            )[:2]
            assert status_line == b"HTTP/1.1 403 Forbidden\r\n"
            assert writer is None

        assert gateway.decisions[-1].allowed is False
        assert gateway.decisions[-1].rule == "domain_not_allowlisted"
    finally:
        server.close()
        await server.wait_closed()


async def test_a_host_that_rebinds_to_a_private_ip_is_refused(fake_dns: FakeDnsResolver) -> None:
    """The allowlisted host now resolves to a private address — exactly the
    bait-and-switch DNS rebinding relies on, and exactly the case that was
    invisible before this gateway existed, because nuclei/zap did their own
    unchecked DNS resolution."""
    fake_dns.set("target.test", ["10.0.0.5"])
    ctx = make_context(roe=make_roe(allowed_domains=("target.test",)))
    async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
        status_line, writer = (await _connect(gateway, host="target.test", port=443))[:2]
        assert status_line == b"HTTP/1.1 403 Forbidden\r\n"
        assert writer is None

    assert gateway.decisions[-1].rule == "blocked_ip"


async def test_the_metadata_endpoint_is_refused_even_with_a_wide_open_ip_allowlist(
    fake_dns: FakeDnsResolver,
) -> None:
    fake_dns.set("target.test", ["169.254.169.254"])
    ctx = make_context(
        roe=make_roe(allowed_domains=("target.test",), allowed_ip_ranges=("0.0.0.0/0",))
    )
    async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
        status_line, writer = (await _connect(gateway, host="target.test", port=443))[:2]
        assert status_line == b"HTTP/1.1 403 Forbidden\r\n"
        assert writer is None

    assert gateway.decisions[-1].rule == "blocked_ip"


async def test_dns_is_re_resolved_on_every_connect_not_cached_from_an_earlier_one(
    fake_dns: FakeDnsResolver,
) -> None:
    """The whole point of checking at connect time rather than trusting the
    crawler's earlier check: if the same host resolves differently a second
    time, the gateway must not remember the first, safe answer."""
    ctx = make_context(
        roe=make_roe(allowed_domains=("target.test",), allowed_ip_ranges=("127.0.0.0/8",))
    )
    server, target_port = await _start_echo_server()
    try:
        async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
            fake_dns.set("target.test", ["127.0.0.1"])
            first_status, first_writer = (
                await _connect(gateway, host="target.test", port=target_port)
            )[:2]
            assert first_status == b"HTTP/1.1 200 Connection Established\r\n"
            if first_writer is not None:
                first_writer.close()

            # Same host, now rebound to a private address the allowlist does
            # not cover.
            fake_dns.set("target.test", ["10.1.2.3"])
            second_status, second_writer = (
                await _connect(gateway, host="target.test", port=target_port)
            )[:2]
            assert second_status == b"HTTP/1.1 403 Forbidden\r\n"
            assert second_writer is None

        assert fake_dns.calls.count("target.test") >= 2
    finally:
        server.close()
        await server.wait_closed()


async def test_a_second_host_in_the_same_run_is_checked_independently(
    fake_dns: FakeDnsResolver,
) -> None:
    """Proves ZAP (or nuclei) pivoting to a second, unauthorized host mid-scan
    gets its own fresh check rather than inheriting the first host's
    allow decision."""
    fake_dns.set("target.test", ["127.0.0.1"])
    fake_dns.set("pivot.test", ["127.0.0.1"])
    ctx = make_context(
        roe=make_roe(allowed_domains=("target.test",), allowed_ip_ranges=("127.0.0.0/8",))
    )
    server, target_port = await _start_echo_server()
    try:
        async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
            ok_status, ok_writer = (
                await _connect(gateway, host="target.test", port=target_port)
            )[:2]
            assert ok_status == b"HTTP/1.1 200 Connection Established\r\n"
            if ok_writer is not None:
                ok_writer.close()

            blocked_status, blocked_writer = (
                await _connect(gateway, host="pivot.test", port=target_port)
            )[:2]
            assert blocked_status == b"HTTP/1.1 403 Forbidden\r\n"
            assert blocked_writer is None
    finally:
        server.close()
        await server.wait_closed()


async def test_a_halted_run_refuses_every_connect_immediately(fake_dns: FakeDnsResolver) -> None:
    fake_dns.set("target.test", ["127.0.0.1"])
    ctx = make_context(
        roe=make_roe(allowed_domains=("target.test",), allowed_ip_ranges=("127.0.0.0/8",))
    )
    ctx.halt("budget exceeded")
    async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
        status_line, writer = (await _connect(gateway, host="target.test", port=443))[:2]
        assert status_line == b"HTTP/1.1 403 Forbidden\r\n"
        assert writer is None
        # Halted before the target check even runs: no decision recorded.
        assert gateway.decisions == []


async def test_a_tripped_kill_switch_refuses_every_connect_immediately(
    fake_dns: FakeDnsResolver,
) -> None:
    fake_dns.set("target.test", ["127.0.0.1"])
    kill_switch = KillSwitch()
    kill_switch.trip()
    ctx = make_context(
        roe=make_roe(allowed_domains=("target.test",), allowed_ip_ranges=("127.0.0.0/8",))
    )
    ctx.kill_switch = kill_switch
    async with EgressGateway(ctx, dns_resolver=fake_dns) as gateway:
        status_line, writer = (await _connect(gateway, host="target.test", port=443))[:2]
        assert status_line == b"HTTP/1.1 403 Forbidden\r\n"
        assert writer is None


# --- nuclei / zap command-line wiring ---------------------------------------


def test_the_nuclei_command_carries_the_proxy_flag_when_given() -> None:
    from app.core.dast.nuclei import command_for
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    command = command_for(
        policy, ["https://target.test/"], rate=5, proxy_url="http://127.0.0.1:19999"
    )
    assert "-proxy" in command
    assert command[command.index("-proxy") + 1] == "http://127.0.0.1:19999"


def test_the_nuclei_command_omits_the_proxy_flag_when_not_given() -> None:
    from app.core.dast.nuclei import command_for
    from app.core.dast.policy import tool_policy

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    command = command_for(policy, ["https://target.test/"], rate=5)
    assert "-proxy" not in command


def test_the_zap_command_carries_the_proxy_config_when_given() -> None:
    from app.core.dast.policy import tool_policy
    from app.core.dast.zap import command_for

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    command = command_for(
        policy, "https://target.test/", "/tmp/report.json", proxy_url="http://127.0.0.1:19999"
    )
    zap_config = command[command.index("-z") + 1]
    assert "network.connection.httpProxy.host=127.0.0.1" in zap_config
    assert "network.connection.httpProxy.port=19999" in zap_config
    assert "network.connection.httpProxy.enabled=true" in zap_config


def test_the_zap_command_omits_the_proxy_config_when_not_given() -> None:
    from app.core.dast.policy import tool_policy
    from app.core.dast.zap import command_for

    policy = tool_policy(allow_state_mutation=False, allowed_methods=("GET",))
    command = command_for(policy, "https://target.test/", "/tmp/report.json")
    zap_config = command[command.index("-z") + 1]
    assert "httpProxy" not in zap_config


# --- the engine actually starts and stops a gateway around both tools -------


async def test_the_engine_gives_both_tools_a_running_gateway_s_proxy_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.dast.contract import CrawledPage, CrawlOutcome, CrawlResult, DastTarget
    from app.core.dast.engine import DastEngine

    seen: dict[str, str | None] = {}

    async def fake_crawl(self: object, ctx: object, target: object) -> CrawlResult:
        page = CrawledPage(
            url="https://target.test/", status_code=200, content_type="text/html", depth=0
        )
        return CrawlResult(
            seed="https://target.test/",
            pages=[page],
            refused=[],
            outcome=CrawlOutcome.EXHAUSTED,
            unvisited=[],
        )

    async def fake_run_nuclei(
        targets: object, policy: object, *, rate: int, proxy_url: str | None = None
    ):
        seen["nuclei"] = proxy_url
        return []

    async def fake_run_zap(
        seed: object, policy: object, *, allowed_domains: object, proxy_url: str | None = None
    ):
        seen["zap"] = proxy_url
        return []

    monkeypatch.setattr("app.core.dast.crawl.ScopedCrawler.crawl", fake_crawl)
    monkeypatch.setattr("app.core.dast.engine.run_nuclei", fake_run_nuclei)
    monkeypatch.setattr("app.core.dast.engine.run_zap", fake_run_zap)

    ctx = make_context(roe=make_roe(allowed_domains=("target.test",)))
    engine = DastEngine()
    await engine.run(ctx, DastTarget(seed_url="https://target.test/", allow_state_mutation=False))

    assert seen["nuclei"] is not None
    assert seen["nuclei"] == seen["zap"]
    assert seen["nuclei"].startswith("http://127.0.0.1:")
