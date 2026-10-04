"""The shape every error response takes (app/main.py's exception handlers).

A `raise HTTPException` and a malformed request body are both handled here,
but only the former went through `http_exception_handler` before this
file's own fix — a request FastAPI itself rejects before any route handler
runs produced its own bare `{"detail": [...]}` instead, in a different
shape than every other error this API returns. `lib/errors.ts`'s `ApiError`
only ever reads `body.error.message`, so that case silently fell back to a
generic "request failed" text client-side even though the specific reason
was already known server-side.
"""

from __future__ import annotations

from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME


async def test_a_malformed_request_body_gets_the_same_error_shape_as_other_errors(
    client: AsyncClient,
) -> None:
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    # Missing "password" and an invalid "email" — FastAPI raises
    # RequestValidationError for this before `register`'s own body runs.
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email", "full_name": "Missing Password"},
        headers={HEADER_NAME: anon_token},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert "request_id" in body["error"]
    # The specific field-level reasons Pydantic already produced must
    # survive into the message, not be replaced by a generic string.
    assert "password" in body["error"]["message"]


async def test_a_malformed_path_parameter_gets_the_same_shape_too(
    client: AsyncClient, strong_password: str
) -> None:
    # A path parameter FastAPI itself fails to parse (not a route handler's
    # own 404/409) is the same RequestValidationError case as a bad body.
    # Authenticated, so the 401 an anonymous caller gets first doesn't mask
    # the path-parsing failure this test is actually about.
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    registered = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "error-shape@example.test",
            "full_name": "Error Shape",
            "password": strong_password,
        },
        headers={HEADER_NAME: anon_token},
    )
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}

    response = await client.get("/api/v1/organizations/not-a-uuid/workflows", headers=headers)
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert "request_id" in body["error"]
