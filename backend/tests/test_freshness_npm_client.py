"""The npm registry freshness client
(`app/core/appsec/supplychain/freshness/npm_client.py`): request shape,
response parsing, HTTP error, malformed JSON, and the real scope engine
proving this context can reach exactly `registry.npmjs.org`. `FakeTransport`
mirrors `tests/test_osv_client.py`'s own.
"""

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.core.appsec.supplychain.freshness.egress import NPM_HOST, npm_egress_context
from app.core.appsec.supplychain.freshness.npm_client import (
    NpmRegistryClient,
    NpmRegistryClientError,
)
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, Observation, ScopeBlockedError
from tests.security.conftest import FakeDnsResolver


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


def _client(responses: list[tuple[int, object]]) -> tuple[NpmRegistryClient, FakeTransport]:
    transport = FakeTransport(responses)
    return NpmRegistryClient(transport=transport), transport  # type: ignore[arg-type]


_PACKUMENT = {
    "name": "left-pad",
    "time": {
        "created": "2014-03-14T09:09:20.762Z",
        "1.3.0": "2018-04-08T21:50:45.678Z",
    },
}


async def test_a_known_version_is_returned() -> None:
    client, _ = _client([(200, _PACKUMENT)])
    ctx = npm_egress_context()

    published = await client.get_publish_time(ctx, "left-pad", "1.3.0")

    assert published == datetime(2018, 4, 8, 21, 50, 45, 678000, tzinfo=UTC)


async def test_the_request_names_the_package() -> None:
    client, transport = _client([(200, _PACKUMENT)])
    ctx = npm_egress_context()

    await client.get_publish_time(ctx, "left-pad", "1.3.0")

    assert str(transport.calls[0]["url"]).endswith("/left-pad")


async def test_a_scoped_package_name_is_url_encoded() -> None:
    client, transport = _client([(200, {"time": {}})])
    ctx = npm_egress_context()

    await client.get_publish_time(ctx, "@types/node", "1.0.0")

    assert "%2F" in str(transport.calls[0]["url"])
    assert str(transport.calls[0]["url"]).endswith("@types%2Fnode")


async def test_a_version_missing_from_the_time_map_returns_none() -> None:
    client, _ = _client([(200, _PACKUMENT)])
    ctx = npm_egress_context()

    assert await client.get_publish_time(ctx, "left-pad", "9.9.9") is None


async def test_a_404_returns_none_rather_than_raising() -> None:
    client, _ = _client([(404, {})])
    ctx = npm_egress_context()

    assert await client.get_publish_time(ctx, "nonexistent-pkg", "1.0.0") is None


async def test_an_http_error_raises_npm_registry_client_error() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = npm_egress_context()

    with pytest.raises(NpmRegistryClientError):
        await client.get_publish_time(ctx, "left-pad", "1.3.0")


async def test_a_non_json_body_raises_npm_registry_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="GET",
                url="https://registry.npmjs.org/left-pad",
                status_code=200,
                headers={},
                elapsed_ms=1.0,
                body=b"not json",
            )

    client = NpmRegistryClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = npm_egress_context()

    with pytest.raises(NpmRegistryClientError):
        await client.get_publish_time(ctx, "left-pad", "1.3.0")


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_npm() -> None:
    route = respx.get(f"https://{NPM_HOST}/left-pad").mock(
        return_value=httpx.Response(200, json={"time": {}})
    )
    client = NpmRegistryClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({NPM_HOST: ["203.0.113.80"]})
        )
    )
    ctx = npm_egress_context()

    result = await client.get_publish_time(ctx, "left-pad", "1.3.0")

    assert result is None
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = npm_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
