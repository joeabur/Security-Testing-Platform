"""In-process stand-ins for the demo lab (docs/BUILD_SPEC.md §19, Phase 12).

Two tiny applications answer the same routes: one carrying the seeded flaws
the API engine is supposed to find, and one behaving correctly so that the
same engine, run against it, finds nothing. They are served through respx,
so the requests travel the real `GatedTransport` and the real scope engine —
only the socket is replaced.

This is not the demo lab. The lab is a deployable, network-isolated
application and arrives in Phase 12; this is the smallest thing that makes
Phase 5's acceptance criterion testable now, and the roadmap says so.
"""

import json
from typing import Any

import httpx

TOKEN_A = "lab-token-account-a"
TOKEN_B = "lab-token-account-b"
TOKEN_ADMIN = "lab-token-admin"
ORDER_OWNED_BY_A = "order-1001"

_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/srv/app/orders.py", line 42, in get_order\n'
    "    return db.query(Order).filter_by(id=order_id).one()\n"
    "sqlalchemy.exc.NoResultFound: No row was found"
)

_SECURE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "RateLimit-Limit": "100",
    "RateLimit-Remaining": "99",
}


def _bearer(request: httpx.Request) -> str | None:
    value = request.headers.get("Authorization", "")
    return value[7:] if value.startswith("Bearer ") else None


def _json(
    payload: Any, status_code: int = 200, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(status_code, json=payload, headers=headers or {})


def _graphql_query(request: httpx.Request) -> str:
    try:
        return str(json.loads(request.content).get("query", ""))
    except (ValueError, AttributeError):
        return ""


def vulnerable_app(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    origin = request.headers.get("Origin")
    # Seeded: reflects any origin *and* allows credentials with it.
    cors = (
        {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
        if origin
        else {}
    )

    if path == "/.env":  # Seeded: configuration endpoint left reachable.
        return httpx.Response(200, text="DATABASE_URL=postgres://lab:lab@db/lab", headers=cors)

    if path == "/graphql":
        query = _graphql_query(request)
        if "__schema" in query:  # Seeded: introspection enabled.
            return _json(
                {"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}, headers=cors
            )
        if "kervyNoSuchField" in query:  # Seeded: resolver traceback returned.
            return _json({"errors": [{"message": _TRACEBACK}]}, headers=cors)
        # Seeded: no depth or complexity limit.
        return _json({"data": {"__typename": "Query"}}, headers=cors)

    if path == "/api/search":
        limit = request.url.params.get("limit")
        if limit is not None and not limit.isdigit():
            # Seeded: a type-confused parameter reaches the handler unguarded.
            return httpx.Response(500, text=_TRACEBACK, headers=cors)
        # Seeded: oversized page accepted, no rate-limit headers, no security headers.
        return _json({"results": []}, headers=cors)

    if path.startswith("/api/orders/"):
        # Seeded: authenticated but never checks ownership (BOLA), and also
        # answers with no credential at all.
        if "'" in path or "<" in path:
            return httpx.Response(500, text=_TRACEBACK, headers=cors)
        return _json({"id": path.rsplit("/", 1)[-1], "total": "12.00"}, headers=cors)

    if path == "/api/admin/users":
        # Seeded: any authenticated caller reaches the admin route.
        if _bearer(request) is None:
            return _json({"error": "unauthorized"}, 401, headers=cors)
        return _json({"users": []}, headers=cors)

    if path == "/api/users":
        return _json({"id": "user-1"}, 201, headers=cors)

    return _json({"error": "not found"}, 404, headers=cors)


def hardened_app(request: httpx.Request) -> httpx.Response:
    """The control. Every behaviour the vulnerable app gets wrong, correctly."""
    path = request.url.path
    token = _bearer(request)
    headers = dict(_SECURE_HEADERS)
    # An origin that is not on the allowlist gets no CORS header at all,
    # rather than being reflected.

    if path == "/graphql":
        query = _graphql_query(request)
        if "__schema" in query:
            return _json({"errors": [{"message": "introspection is disabled"}]}, headers=headers)
        if query.count("a{") > 5:
            return _json({"errors": [{"message": "query exceeds maximum depth"}]}, headers=headers)
        if query.count(":__typename") > 2:
            return _json(
                {"errors": [{"message": "query exceeds maximum complexity"}]}, headers=headers
            )
        if "kervyNoSuchField" in query:
            return _json(
                {"errors": [{"message": 'Cannot query field "kervyNoSuchField" on type "Query".'}]},
                headers=headers,
            )
        return _json({"data": {"__typename": "Query"}}, headers=headers)

    if path == "/api/search":
        limit = request.url.params.get("limit")
        if limit is not None and (not limit.isdigit() or int(limit) > 100):
            return _json(
                {"error": "limit must be an integer no greater than 100"}, 400, headers=headers
            )
        return _json({"results": []}, headers=headers)

    if path.startswith("/api/orders/"):
        if token is None:
            return _json({"error": "unauthorized"}, 401, headers=headers)
        order_id = path.rsplit("/", 1)[-1]
        # Ownership is checked on the object, not just on the session.
        if token == TOKEN_A and order_id == ORDER_OWNED_BY_A:
            return _json({"id": order_id, "total": "12.00"}, headers=headers)
        return _json({"error": "forbidden"}, 403, headers=headers)

    if path == "/api/admin/users":
        if token is None:
            return _json({"error": "unauthorized"}, 401, headers=headers)
        if token != TOKEN_ADMIN:
            return _json({"error": "forbidden"}, 403, headers=headers)
        return _json({"users": []}, headers=headers)

    if path == "/api/users":
        return _json({"id": "user-1"}, 201, headers=headers)

    return _json({"error": "not found"}, 404, headers=headers)
