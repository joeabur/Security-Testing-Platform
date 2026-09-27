"""The collaborator: a local listener that records what reached it
(docs/BUILD_SPEC.md §19).

Some findings can only be established out of band. "Did the target fetch a URL
we planted?" and "did anything leave through that channel?" cannot be answered
from the response to the request that caused them — the evidence arrives
somewhere else, later.

This is the somewhere else, and it is local. A hosted collaborator would mean
the lab's exfiltration tests sent data to a third party, which is the opposite
of what an isolated lab is for. It runs on the internal compose network, so a
hit here proves the target reached a host inside the lab and nothing more.

It records; it never responds with anything an attacker could use. Every
request gets the same short, inert answer.
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from lab.isolation import announce

# A bound, so a target stuck in a loop cannot exhaust the lab's memory.
MAX_HITS = 500


@dataclass
class Hit:
    id: str
    at: str
    method: str
    path: str
    query: str
    # Headers are recorded because "which user agent fetched this" is often the
    # only way to attribute a hit. Values are truncated: a header carrying a
    # session token is exactly the kind of thing that lands here.
    headers: dict[str, str] = field(default_factory=dict)
    body_bytes: int = 0


def create_app() -> FastAPI:
    announce("collaborator")
    hits: list[Hit] = []

    app = FastAPI(
        title="Aegis Lab — out-of-band collaborator",
        description="Records requests that reach it. Local only. Do not deploy.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "hits": len(hits)}

    @app.get("/hits")
    async def listing() -> dict[str, Any]:
        return {"count": len(hits), "hits": [asdict(hit) for hit in hits]}

    @app.delete("/hits")
    async def clear() -> dict[str, int]:
        cleared = len(hits)
        hits.clear()
        return {"cleared": cleared}

    # One route per method rather than a single `api_route(methods=[...])`:
    # FastAPI derives an operation_id from the function name when none is
    # given, and a shared handler registered once for six methods produced
    # the same operation_id for all six in the generated OpenAPI document
    # (harmless to routing — Starlette dispatches on method regardless —
    # but a duplicate-operation-id document is malformed, and anything
    # that keys off operation_id, including this platform's own OpenAPI
    # parser, would see one endpoint where six exist).
    async def collect(path: str, request: Request) -> PlainTextResponse:
        body = await request.body()
        if len(hits) < MAX_HITS:
            hits.append(
                Hit(
                    id=str(uuid.uuid4()),
                    at=datetime.now(UTC).isoformat(),
                    method=request.method,
                    path=f"/oob/{path}",
                    query=str(request.url.query),
                    headers={
                        name: value[:200] for name, value in request.headers.items()
                    },
                    body_bytes=len(body),
                )
            )
        # The same inert answer to everything. A collaborator that returned
        # anything interesting would become a second attack surface.
        return PlainTextResponse("ok\n")

    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
        app.add_api_route(
            "/oob/{path:path}",
            collect,
            methods=[method],
            operation_id=f"collect_oob_{method.lower()}",
        )

    return app
