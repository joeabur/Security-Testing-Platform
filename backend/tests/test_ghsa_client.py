"""GitHub's global security advisory API client
(`app/core/appsec/enrichment/ghsa_client.py`): request shape, response
parsing, HTTP error, malformed JSON, and the real scope engine proving this
context can reach exactly `api.github.com`. `FakeTransport` mirrors
`tests/test_osv_client.py`'s own.
"""

import json

import httpx
import pytest
import respx

from app.core.appsec.enrichment.egress import GHSA_HOST, ghsa_egress_context
from app.core.appsec.enrichment.ghsa_client import GhsaClient, GhsaClientError, cvss_detail
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


def _client(responses: list[tuple[int, object]]) -> tuple[GhsaClient, FakeTransport]:
    transport = FakeTransport(responses)
    return GhsaClient(transport=transport), transport  # type: ignore[arg-type]


_ADVISORY = {
    "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
    "summary": "A GHSA thing.",
    "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"},
}


async def test_a_known_advisory_is_returned() -> None:
    client, _ = _client([(200, _ADVISORY)])
    ctx = ghsa_egress_context()

    advisory = await client.get_advisory(ctx, "GHSA-xxxx-xxxx-xxxx")

    assert advisory is not None
    assert advisory["summary"] == "A GHSA thing."


async def test_the_request_names_the_ghsa_id() -> None:
    client, transport = _client([(200, _ADVISORY)])
    ctx = ghsa_egress_context()

    await client.get_advisory(ctx, "GHSA-xxxx-xxxx-xxxx")

    assert str(transport.calls[0]["url"]).endswith("/advisories/GHSA-xxxx-xxxx-xxxx")


async def test_a_404_returns_none_rather_than_raising() -> None:
    client, _ = _client([(404, {})])
    ctx = ghsa_egress_context()

    assert await client.get_advisory(ctx, "GHSA-0000-0000-0000") is None


async def test_an_http_error_raises_ghsa_client_error() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = ghsa_egress_context()

    with pytest.raises(GhsaClientError):
        await client.get_advisory(ctx, "GHSA-xxxx-xxxx-xxxx")


async def test_a_non_json_body_raises_ghsa_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="GET",
                url="https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx",
                status_code=200,
                headers={},
                elapsed_ms=1.0,
                body=b"not json",
            )

    client = GhsaClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = ghsa_egress_context()

    with pytest.raises(GhsaClientError):
        await client.get_advisory(ctx, "GHSA-xxxx-xxxx-xxxx")


def test_cvss_detail_is_read() -> None:
    assert cvss_detail(_ADVISORY) == (7.5, "CVSS:3.1/AV:N")


def test_no_cvss_object_has_no_detail() -> None:
    assert cvss_detail({}) is None


def test_a_non_numeric_score_has_no_detail() -> None:
    assert cvss_detail({"cvss": {"score": None, "vector_string": "CVSS:3.1/AV:N"}}) is None


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_ghsa() -> None:
    route = respx.get(f"https://{GHSA_HOST}/advisories/GHSA-xxxx-xxxx-xxxx").mock(
        return_value=httpx.Response(404)
    )
    client = GhsaClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({GHSA_HOST: ["203.0.113.70"]})
        )
    )
    ctx = ghsa_egress_context()

    result = await client.get_advisory(ctx, "GHSA-xxxx-xxxx-xxxx")

    assert result is None
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = ghsa_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
