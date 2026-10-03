"""The OSV.dev client (`app/core/appsec/osv/client.py`): batch-query
chunking, mapping results back to the right query, and bounded detail
lookups. `FakeTransport` mirrors the one `tests/test_vcs.py` already uses
for `GitHubClient` — same shape, same reason: these are the client's own
request-construction and response-parsing rules, not the scope engine,
which `tests/test_osv_engine.py`'s end-to-end test covers separately with
the real `GatedTransport`.
"""

import json

import pytest

from app.core.appsec.osv.client import (
    BATCH_CHUNK_SIZE,
    MAX_DETAIL_LOOKUPS,
    OsvClient,
    OsvClientError,
    PackageQuery,
)
from app.core.appsec.osv.egress import osv_egress_context
from app.core.scope.transport import Observation


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


def _client(responses: list[tuple[int, object]]) -> tuple[OsvClient, FakeTransport]:
    transport = FakeTransport(responses)
    return OsvClient(transport=transport), transport  # type: ignore[arg-type]


async def test_a_query_with_no_match_is_absent_from_the_result() -> None:
    client, _ = _client([(200, {"results": [{}]})])
    ctx = osv_egress_context()

    result = await client.query_vulnerable_ids(
        ctx, [PackageQuery(name="left-pad", version="1.0.0", ecosystem="npm")]
    )

    assert result == {}


async def test_a_matched_query_maps_back_to_its_own_vulnerability_ids() -> None:
    client, transport = _client(
        [
            (
                200,
                {
                    "results": [
                        {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2026-01-01"}]},
                        {},
                    ]
                },
            )
        ]
    )
    ctx = osv_egress_context()
    queries = [
        PackageQuery(name="braces", version="2.3.2", ecosystem="npm"),
        PackageQuery(name="left-pad", version="1.0.0", ecosystem="npm"),
    ]

    result = await client.query_vulnerable_ids(ctx, queries)

    assert result == {queries[0]: ("GHSA-aaaa-bbbb-cccc",)}
    # The request body names every query's package and version, in order.
    sent = json.loads(transport.calls[0]["content"])
    assert sent["queries"][0]["package"] == {"name": "braces", "ecosystem": "npm"}
    assert sent["queries"][0]["version"] == "2.3.2"


async def test_a_batch_larger_than_the_chunk_size_is_split_into_multiple_requests() -> None:
    queries = [
        PackageQuery(name=f"pkg-{i}", version="1.0.0", ecosystem="npm")
        for i in range(BATCH_CHUNK_SIZE + 5)
    ]
    responses = [
        (200, {"results": [{} for _ in queries[:BATCH_CHUNK_SIZE]]}),
        (200, {"results": [{} for _ in queries[BATCH_CHUNK_SIZE:]]}),
    ]
    client, transport = _client(responses)
    ctx = osv_egress_context()

    await client.query_vulnerable_ids(ctx, queries)

    assert len(transport.calls) == 2
    first_body = json.loads(transport.calls[0]["content"])
    second_body = json.loads(transport.calls[1]["content"])
    assert len(first_body["queries"]) == BATCH_CHUNK_SIZE
    assert len(second_body["queries"]) == 5


async def test_vulnerability_details_are_fetched_one_request_per_id() -> None:
    client, transport = _client(
        [
            (200, {"id": "GHSA-aaaa-bbbb-cccc", "summary": "one"}),
            (200, {"id": "GHSA-dddd-eeee-ffff", "summary": "two"}),
        ]
    )
    ctx = osv_egress_context()

    details = await client.get_vulnerability_details(
        ctx, {"GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"}
    )

    assert details["GHSA-aaaa-bbbb-cccc"]["summary"] == "one"
    assert details["GHSA-dddd-eeee-ffff"]["summary"] == "two"
    assert {str(call["url"]).rsplit("/", 1)[-1] for call in transport.calls} == {
        "GHSA-aaaa-bbbb-cccc",
        "GHSA-dddd-eeee-ffff",
    }


async def test_detail_lookups_beyond_the_bound_are_not_fetched() -> None:
    ids = {f"GHSA-{i:04d}-aaaa-bbbb" for i in range(MAX_DETAIL_LOOKUPS + 10)}
    responses = [(200, {"id": "x"}) for _ in range(MAX_DETAIL_LOOKUPS)]
    client, transport = _client(responses)
    ctx = osv_egress_context()

    await client.get_vulnerability_details(ctx, ids)

    assert len(transport.calls) == MAX_DETAIL_LOOKUPS


async def test_an_http_error_raises_an_osv_client_error_rather_than_returning_nothing() -> None:
    client, _ = _client([(500, {"error": "boom"})])
    ctx = osv_egress_context()

    with pytest.raises(OsvClientError):
        await client.query_vulnerable_ids(
            ctx, [PackageQuery(name="braces", version="3.0.3", ecosystem="npm")]
        )


async def test_a_non_json_body_raises_an_osv_client_error() -> None:
    class _BadBodyTransport(FakeTransport):
        async def send(self, ctx: object, **kwargs: object) -> Observation:
            return Observation(
                method="POST", url="https://api.osv.dev/v1/querybatch",
                status_code=200, headers={}, elapsed_ms=1.0, body=b"not json",
            )

    client = OsvClient(transport=_BadBodyTransport([]))  # type: ignore[arg-type]
    ctx = osv_egress_context()

    with pytest.raises(OsvClientError):
        await client.query_vulnerable_ids(
            ctx, [PackageQuery(name="braces", version="3.0.3", ecosystem="npm")]
        )
