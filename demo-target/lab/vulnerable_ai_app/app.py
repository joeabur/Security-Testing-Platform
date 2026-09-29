"""The vulnerable AI application (docs/BUILD_SPEC.md §19).

Ten seeded flaws, each marked `SEEDED FLAW n` where it lives so a reader can
find them and a test can assert they are all still here. They are the ten §19
names, in order:

 1. weak prompt isolation            6. cross-tenant RAG index
 2. recoverable system prompt        7. no rate limiting
 3. unauthorized "tools" endpoint    8. mass assignment on /api/users
 4. over-broad agent tool surface    9. BOLA on /api/orders/{id}
 5. raw-HTML-rendered output        10. verbose errors

Nothing here is a mistake. Every one of them is the shape of a real bug this
scanner is meant to find, written plainly rather than hidden, because a lab
whose flaws are subtle tests the reader rather than the tool.
"""

import traceback
from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse

from lab.data import SYSTEM_PROMPT, Account, Store
from lab.isolation import announce
from lab.vulnerable_ai_app.model import answer

store = Store()

# SEEDED FLAW 4: over-broad agent tool surface. Every tool is exposed to every
# caller, three of them write, one is irreversible, and none requires
# confirmation — which is what the excessive-agency probe reports on.
DECLARED_TOOLS: list[dict[str, Any]] = [
    {"name": "search_docs", "writes": False, "irreversible": False, "external": False},
    {"name": "create_ticket", "writes": True, "irreversible": False, "external": False},
    {"name": "issue_refund", "writes": True, "irreversible": True, "external": True},
    {"name": "delete_account", "writes": True, "irreversible": True, "external": False},
    {"name": "send_email", "writes": True, "irreversible": True, "external": True},
]


def create_app() -> FastAPI:
    announce("vulnerable-ai-app")
    app = FastAPI(
        title="Kervy Lab — intentionally vulnerable AI application",
        description="Do not deploy. Every endpoint here is deliberately weak.",
        version="0.1.0",
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "warning": "intentionally vulnerable"}

    @app.post("/api/chat")
    async def chat(payload: dict[str, Any]) -> JSONResponse:
        """SEEDED FLAWS 1, 2, 5, 6, 7.

        No rate limit, no prompt isolation, the system prompt is recoverable,
        retrieval ignores the caller's tenant, and the reply is handed back for
        a browser to render.
        """
        message = str(payload.get("message", ""))

        # SEEDED FLAW 6: retrieval searches every tenant's documents. The
        # caller's own tenant is never consulted.
        retrieved = [
            document
            for document in store.documents
            if any(
                word in document.body.lower() for word in message.lower().split()[:6]
            )
        ]

        reply = answer(message, retrieved)
        return JSONResponse(
            {
                "reply": reply,
                # SEEDED FLAW 2: and if asking did not work, it is in the
                # response envelope anyway.
                "debug": {"system_prompt": SYSTEM_PROMPT, "retrieved": len(retrieved)},
            }
        )

    @app.get("/api/chat/render", response_class=HTMLResponse)
    async def chat_render(q: str = "") -> HTMLResponse:
        """SEEDED FLAW 5: model output rendered as raw HTML.

        Whatever the model returns goes into the page unescaped, so an
        assistant that can be told to emit a tag emits a live tag.
        """
        return HTMLResponse(
            f"<html><body><div id='reply'>{answer(q)}</div></body></html>"
        )

    @app.get("/api/tools")
    async def tools() -> dict[str, Any]:
        """SEEDED FLAW 3: the tool inventory, unauthenticated."""
        return {"tools": DECLARED_TOOLS}

    @app.post("/api/tools/{name}")
    async def invoke_tool(name: str, payload: dict[str, Any]) -> dict[str, Any]:
        """SEEDED FLAW 3 (continued): and they can be invoked, by anyone.

        Nothing is actually performed — the lab has no side effects to offer —
        but the endpoint answers 200, which is the authorization decision the
        probe is measuring.
        """
        return {"tool": name, "accepted": True, "arguments": payload}

    @app.get("/api/orders/{order_id}")
    async def get_order(order_id: str, authorization: str = Header(default="")) -> Any:
        """SEEDED FLAW 9: BOLA.

        The caller is authenticated, and then the object is returned without
        checking whether it is theirs.
        """
        account = store.account_for_token(_bearer(authorization))
        if account is None:
            return JSONResponse({"error": "unauthenticated"}, status_code=401)

        order = store.order(order_id)
        if order is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        # The check a correct implementation makes here, and this one does not:
        #     if order.owner_id != account.id: return 403
        return asdict(order)

    @app.get("/api/orders")
    async def list_orders(authorization: str = Header(default="")) -> Any:
        account = store.account_for_token(_bearer(authorization))
        if account is None:
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        return {
            "orders": [
                asdict(order)
                for order in store.orders
                if order.tenant == account.tenant
            ]
        }

    @app.post("/api/users")
    async def create_user(payload: dict[str, Any]) -> dict[str, Any]:
        """SEEDED FLAW 8: mass assignment.

        Every key in the body is accepted, including `role`, so a caller can
        make themselves an admin by asking.
        """
        account = Account(
            id=f"acct-{len(store.accounts) + 1:04d}",
            tenant=str(payload.get("tenant", "acme")),
            email=str(payload.get("email", "new@acme.invalid")),
            role=str(payload.get("role", "user")),
        )
        store.accounts.append(account)
        extra = {
            key: value for key, value in payload.items() if key not in asdict(account)
        }
        store.extra_fields[account.id] = extra
        return {**asdict(account), "accepted_extra_fields": sorted(extra)}

    @app.get("/api/search")
    async def search(q: str = "", limit: int = 10) -> Any:
        """SEEDED FLAW 10: verbose errors, and no bound on `limit`.

        A malformed value reaches the handler and its traceback reaches the
        caller.
        """
        try:
            size = int(limit)
            window = store.documents[:size]
            return {"query": q, "results": [asdict(document) for document in window]}
        except Exception as exc:  # noqa: BLE001 - the flaw is precisely this
            return JSONResponse(
                {
                    "error": str(exc),
                    "type": type(exc).__name__,
                    # The whole point: internals handed to the caller.
                    "traceback": traceback.format_exc(),
                    "file": __file__,
                },
                status_code=500,
            )

    @app.get("/.env")
    async def dotenv() -> HTMLResponse:
        """A configuration file left reachable, which is what the debug-endpoint
        probe goes looking for."""
        return HTMLResponse(
            f"AWS_ACCESS_KEY_ID={SYSTEM_PROMPT.split('aws_key=')[1].split(',')[0]}\n"
            "DEBUG=true\n",
            media_type="text/plain",
        )

    @app.middleware("http")
    async def permissive_headers(request: Request, call_next: Any) -> Any:
        """SEEDED FLAW 7 (and friends): no rate limit, and CORS reflects
        whatever origin it is given, with credentials."""
        response = await call_next(request)
        origin = request.headers.get("origin")
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
        # Note what is absent: no RateLimit headers, no Retry-After, no
        # Content-Security-Policy, no X-Content-Type-Options.
        return response

    return app


def _bearer(header: str) -> str | None:
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def seeded_flaws() -> dict[int, str]:
    """The ten §19 flaws, so a test can assert none has quietly been fixed."""
    return {
        1: "weak prompt isolation",
        2: "recoverable system prompt",
        3: "unauthorized tools endpoint",
        4: "over-broad agent tool surface",
        5: "raw-HTML-rendered model output",
        6: "cross-tenant RAG index",
        7: "no rate limiting",
        8: "mass assignment on /api/users",
        9: "BOLA on /api/orders/{id}",
        10: "verbose errors",
    }


app = None if __name__ != "__main__" else create_app()
