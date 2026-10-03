"""A thin, direct client for `osv.dev`'s public API.

Every request goes through `GatedTransport` under the fixed context
`osv_egress_context()` builds — the same "no ungated httpx" rule every
other outbound path in this codebase obeys (`tests/security/
test_scope_controls.py::test_no_ungated_httpx_client_construction_outside_transport`).

OSV's batch endpoint (`POST /v1/querybatch`) deliberately returns only each
match's id and modified timestamp, to keep a large batch's response small —
so a second call, `GET /v1/vulns/{id}`, is needed per unique id to get the
summary, severity and fixed-version data a finding actually needs. Fetching
details is therefore its own bounded step, not folded into the batch call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import OSV_HOST

BASE_URL = f"https://{OSV_HOST}/v1"
#: OSV accepts larger batches, but this keeps any one request's body and the
#: engine's own request count predictable regardless of lockfile size.
BATCH_CHUNK_SIZE = 200
#: However vulnerable a lockfile is, this engine will fetch details for at
#: most this many distinct advisories — bounding the worst case to a fixed
#: number of requests rather than one per finding.
MAX_DETAIL_LOOKUPS = 150


class OsvClientError(Exception):
    """A request to osv.dev could not be completed or understood."""


@dataclass(frozen=True)
class PackageQuery:
    name: str
    version: str
    ecosystem: str


class OsvClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def _post(self, ctx: RunContext, path: str, body: dict[str, Any]) -> Any:
        return await self._request(ctx, method="POST", path=path, body=body)

    async def _get(self, ctx: RunContext, path: str) -> Any:
        return await self._request(ctx, method="GET", path=path, body=None)

    async def _request(
        self, ctx: RunContext, *, method: str, path: str, body: dict[str, Any] | None
    ) -> Any:
        content = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"User-Agent": "kervy-security"}
        if content is not None:
            headers["Content-Type"] = "application/json"
        try:
            observation = await self._transport.send(
                ctx,
                method=method,
                url=f"{BASE_URL}{path}",
                headers=headers,
                content=content,
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise OsvClientError(f"refused by scope engine: {exc.decision.reason}") from exc

        if observation.status_code >= 400:
            raise OsvClientError(f"{method} {path} returned HTTP {observation.status_code}")
        if not observation.body:
            return None
        try:
            return json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise OsvClientError(f"{method} {path} returned a body that is not JSON") from exc

    async def query_vulnerable_ids(
        self, ctx: RunContext, queries: list[PackageQuery]
    ) -> dict[PackageQuery, tuple[str, ...]]:
        """Which packages osv.dev reports a vulnerability for, by id only.

        The batch endpoint's own response is positional — result `i`
        answers query `i` — so the mapping back to each `PackageQuery` is
        done here rather than left to the caller to get wrong.
        """
        results: dict[PackageQuery, tuple[str, ...]] = {}
        for start in range(0, len(queries), BATCH_CHUNK_SIZE):
            chunk = queries[start : start + BATCH_CHUNK_SIZE]
            payload = await self._post(
                ctx,
                "/querybatch",
                {
                    "queries": [
                        {
                            "version": query.version,
                            "package": {"name": query.name, "ecosystem": query.ecosystem},
                        }
                        for query in chunk
                    ]
                },
            )
            chunk_results = (payload or {}).get("results", []) if isinstance(payload, dict) else []
            for query, result in zip(chunk, chunk_results, strict=False):
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                ids = tuple(
                    str(vuln["id"])
                    for vuln in vulns
                    if isinstance(vuln, dict) and vuln.get("id")
                )
                if ids:
                    results[query] = ids
        return results

    async def get_vulnerability_details(
        self, ctx: RunContext, vuln_ids: set[str]
    ) -> dict[str, dict[str, Any]]:
        """Full advisory records for a bounded set of ids.

        Ids beyond `MAX_DETAIL_LOOKUPS` are silently not fetched — the
        affected packages they belong to are still reported, with only the
        id and whatever other ids *were* fetched describing them, never
        dropped outright for having been unlucky in ordering.
        """
        details: dict[str, dict[str, Any]] = {}
        for vuln_id in sorted(vuln_ids)[:MAX_DETAIL_LOOKUPS]:
            payload = await self._get(ctx, f"/vulns/{vuln_id}")
            if isinstance(payload, dict):
                details[vuln_id] = payload
        return details
