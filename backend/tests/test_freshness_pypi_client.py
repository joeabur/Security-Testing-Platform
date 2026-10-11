"""PyPI's per-release JSON API freshness client
(`app/core/appsec/supplychain/freshness/pypi_client.py`): request shape,
response parsing, HTTP error, malformed JSON, and the real scope engine
proving this context can reach exactly `pypi.org`.
"""

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.core.appsec.supplychain.freshness.egress import PYPI_HOST, pypi_egress_context
from app.core.appsec.supplychain.freshness.pypi_client import (
    PypiRegistryClient,
    PypiRegistryClientError,
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


def _client(responses: list[tuple[int, object]]) -> tuple[PypiRegistryClient, FakeTransport]:
    transport = FakeTransport(responses)
    return PypiRegistryClient(transport=transport), transport  # type: ignore[arg-type]


_RELEASE = {
    "urls": [
        {"upload_time_iso_8601": "2023-05-22T15:12:44.175995Z"},
        {"upload_time_iso_8601": "2023-05-22T15:12:42.313790Z"},
    ]
}


async def test_the_earliest_upload_time_across_files_is_returned() -> None:
    client, _ = _client([(200, _RELEASE)])
    ctx = pypi_egress_context()

    published = await client.get_publish_time(ctx, "requests", "2.31.0")

    assert published == datetime(2023, 5, 22, 15, 12, 42, 313790, tzinfo=UTC)


async def test_the_request_names_the_package_and_version() -> None:
    client, transport = _client([(200, _RELEASE)])
    ctx = pypi_egress_context()

    await client.get_publish_time(ctx, "requests", "2.31.0")

    assert str(transport.calls[0]["url"]).endswith("/requests/2.31.0/json")


async def test_no_urls_returns_none() -> None:
    client, _ = _client([(200, {"urls": []})])
    ctx = pypi_egress_context()

    assert await client.get_publish_time(ctx, "requests", "2.31.0") is None


async def test_a_404_returns_none_rather_than_raising() -> None:
    client, _ = _client([(404, {})])
    ctx = pypi_egress_context()

    assert await client.get_publish_time(ctx, "nonexistent-pkg", "1.0.0") is None


async def test_an_http_error_raises_pypi_registry_client_error() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = pypi_egress_context()

    with pytest.raises(PypiRegistryClientError):
        await client.get_publish_time(ctx, "requests", "2.31.0")


async def test_a_non_json_body_raises_pypi_registry_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="GET",
                url="https://pypi.org/pypi/requests/2.31.0/json",
                status_code=200,
                headers={},
                elapsed_ms=1.0,
                body=b"not json",
            )

    client = PypiRegistryClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = pypi_egress_context()

    with pytest.raises(PypiRegistryClientError):
        await client.get_publish_time(ctx, "requests", "2.31.0")


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_pypi() -> None:
    route = respx.get(f"https://{PYPI_HOST}/pypi/requests/2.31.0/json").mock(
        return_value=httpx.Response(404)
    )
    client = PypiRegistryClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({PYPI_HOST: ["203.0.113.81"]})
        )
    )
    ctx = pypi_egress_context()

    result = await client.get_publish_time(ctx, "requests", "2.31.0")

    assert result is None
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = pypi_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
