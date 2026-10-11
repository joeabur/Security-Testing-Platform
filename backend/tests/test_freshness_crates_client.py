"""crates.io's per-version freshness client
(`app/core/appsec/supplychain/freshness/crates_client.py`): request shape
(including the descriptive User-Agent crates.io's own policy requires),
response parsing (publisher-account-age present and absent), HTTP error,
malformed JSON, and the real scope engine proving this context can reach
exactly `crates.io`.
"""

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.core.appsec.supplychain.freshness.crates_client import (
    USER_AGENT,
    CratesRegistryClient,
    CratesRegistryClientError,
)
from app.core.appsec.supplychain.freshness.egress import CRATES_HOST, crates_egress_context
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


def _client(responses: list[tuple[int, object]]) -> tuple[CratesRegistryClient, FakeTransport]:
    transport = FakeTransport(responses)
    return CratesRegistryClient(transport=transport), transport  # type: ignore[arg-type]


_VERSION_WITH_PUBLISHER = {
    "version": {
        "created_at": "2026-07-18T23:05:13.266456Z",
        "published_by": {"login": "dtolnay", "created_at": "2012-07-09T03:55:40Z"},
    }
}
_VERSION_WITHOUT_PUBLISHER = {"version": {"created_at": "2026-07-18T23:05:13.266456Z"}}


async def test_publish_time_and_publisher_age_are_both_read() -> None:
    client, _ = _client([(200, _VERSION_WITH_PUBLISHER)])
    ctx = crates_egress_context()

    detail = await client.get_version_detail(ctx, "serde", "1.0.229")

    assert detail is not None
    assert detail.published_at == datetime(2026, 7, 18, 23, 5, 13, 266456, tzinfo=UTC)
    assert detail.publisher_account_created_at == datetime(2012, 7, 9, 3, 55, 40, tzinfo=UTC)


async def test_a_missing_published_by_leaves_the_account_field_none() -> None:
    client, _ = _client([(200, _VERSION_WITHOUT_PUBLISHER)])
    ctx = crates_egress_context()

    detail = await client.get_version_detail(ctx, "serde", "1.0.229")

    assert detail is not None
    assert detail.publisher_account_created_at is None


async def test_the_request_carries_a_descriptive_user_agent() -> None:
    client, transport = _client([(200, _VERSION_WITH_PUBLISHER)])
    ctx = crates_egress_context()

    await client.get_version_detail(ctx, "serde", "1.0.229")

    headers = transport.calls[0]["headers"]
    assert headers["User-Agent"] == USER_AGENT
    assert "kervy-security" in USER_AGENT


async def test_a_404_returns_none_rather_than_raising() -> None:
    client, _ = _client([(404, {})])
    ctx = crates_egress_context()

    assert await client.get_version_detail(ctx, "nonexistent-crate", "1.0.0") is None


async def test_an_http_error_raises_crates_registry_client_error() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = crates_egress_context()

    with pytest.raises(CratesRegistryClientError):
        await client.get_version_detail(ctx, "serde", "1.0.229")


async def test_a_non_json_body_raises_crates_registry_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="GET",
                url="https://crates.io/api/v1/crates/serde/1.0.229",
                status_code=200,
                headers={},
                elapsed_ms=1.0,
                body=b"not json",
            )

    client = CratesRegistryClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = crates_egress_context()

    with pytest.raises(CratesRegistryClientError):
        await client.get_version_detail(ctx, "serde", "1.0.229")


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_crates_io() -> None:
    route = respx.get(f"https://{CRATES_HOST}/api/v1/crates/serde/1.0.229").mock(
        return_value=httpx.Response(200, json=_VERSION_WITH_PUBLISHER)
    )
    client = CratesRegistryClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({CRATES_HOST: ["203.0.113.83"]})
        )
    )
    ctx = crates_egress_context()

    detail = await client.get_version_detail(ctx, "serde", "1.0.229")

    assert detail is not None
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = crates_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
