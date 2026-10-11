"""The Go module proxy freshness client
(`app/core/appsec/supplychain/freshness/go_client.py`): the module-path
case-escaping rule, request shape, response parsing, HTTP error,
malformed JSON, and the real scope engine proving this context can reach
exactly `proxy.golang.org`.
"""

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.core.appsec.supplychain.freshness.egress import GO_PROXY_HOST, go_proxy_egress_context
from app.core.appsec.supplychain.freshness.go_client import (
    GoProxyClient,
    GoProxyClientError,
    escape_module_path,
)
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, Observation, ScopeBlockedError
from tests.security.conftest import FakeDnsResolver


def test_uppercase_letters_are_escaped() -> None:
    assert escape_module_path("github.com/BurntSushi/toml") == "github.com/!burnt!sushi/toml"


def test_an_already_lowercase_path_round_trips_unchanged() -> None:
    assert escape_module_path("github.com/pkg/errors") == "github.com/pkg/errors"


class FakeTransport:
    def __init__(self, responses: list[tuple[int, object]]) -> None:
        self._responses = responses
        self.calls: list[dict[str, object]] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append(kwargs)
        status, body = self._responses.pop(0)
        return Observation(
            method=str(kwargs.get("method")),
            url=str(kwargs.get("url")),
            status_code=status,
            headers={},
            elapsed_ms=1.0,
            body=json.dumps(body).encode("utf-8") if body is not None else b"",
        )


def _client(responses: list[tuple[int, object]]) -> tuple[GoProxyClient, FakeTransport]:
    transport = FakeTransport(responses)
    return GoProxyClient(transport=transport), transport  # type: ignore[arg-type]


_INFO = {"Version": "v0.9.1", "Time": "2020-01-14T19:47:44Z"}


async def test_a_known_version_is_returned() -> None:
    client, _ = _client([(200, _INFO)])
    ctx = go_proxy_egress_context()

    published = await client.get_publish_time(ctx, "github.com/pkg/errors", "v0.9.1")

    assert published == datetime(2020, 1, 14, 19, 47, 44, tzinfo=UTC)


async def test_the_request_escapes_a_mixed_case_module_path() -> None:
    client, transport = _client([(200, _INFO)])
    ctx = go_proxy_egress_context()

    await client.get_publish_time(ctx, "github.com/BurntSushi/toml", "v0.3.1")

    assert "!burnt!sushi" in str(transport.calls[0]["url"])
    assert str(transport.calls[0]["url"]).endswith("/@v/v0.3.1.info")


async def test_a_404_returns_none_rather_than_raising() -> None:
    client, _ = _client([(404, {})])
    ctx = go_proxy_egress_context()

    assert await client.get_publish_time(ctx, "github.com/pkg/errors", "v99.0.0") is None


async def test_an_http_error_raises_go_proxy_client_error() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = go_proxy_egress_context()

    with pytest.raises(GoProxyClientError):
        await client.get_publish_time(ctx, "github.com/pkg/errors", "v0.9.1")


async def test_a_non_json_body_raises_go_proxy_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="GET",
                url="https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.info",
                status_code=200,
                headers={},
                elapsed_ms=1.0,
                body=b"not json",
            )

    client = GoProxyClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = go_proxy_egress_context()

    with pytest.raises(GoProxyClientError):
        await client.get_publish_time(ctx, "github.com/pkg/errors", "v0.9.1")


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_the_go_proxy() -> None:
    route = respx.get(f"https://{GO_PROXY_HOST}/github.com/pkg/errors/@v/v0.9.1.info").mock(
        return_value=httpx.Response(200, json=_INFO)
    )
    client = GoProxyClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({GO_PROXY_HOST: ["203.0.113.82"]})
        )
    )
    ctx = go_proxy_egress_context()

    result = await client.get_publish_time(ctx, "github.com/pkg/errors", "v0.9.1")

    assert result == datetime(2020, 1, 14, 19, 47, 44, tzinfo=UTC)
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = go_proxy_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
