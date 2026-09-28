import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.constants import API_VERSION_PREFIX, PRODUCT_NAME
from app.core.csrf import enforce as csrf
from app.schemas.errors import ErrorDetail, ErrorResponse
from app.web.router import STATIC_DIR as WEB_STATIC_DIR
from app.web.router import router as web_router

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=PRODUCT_NAME, version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def csrf_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Enforce CSRF before a handler runs.

        Middleware rather than a per-route dependency, deliberately: a
        dependency protects the routes somebody remembered to decorate, and
        the one they forget is the one that matters. This covers every route
        in the application, including any added later, and narrows by the
        *request* — unsafe method, cookie-authenticated, not exempt — rather
        than by a list.

        A form field cannot be read here without consuming the body, so the
        header is what middleware checks; the dashboard's own form posts are
        checked in their handlers, which have the parsed form.
        """
        try:
            csrf.check(request)
        except HTTPException as exc:
            return await http_exception_handler(request, exc)
        return await call_next(request)

    @app.middleware("http")
    async def request_id_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        logger.info(
            "http_exception",
            status_code=exc.status_code,
            path=request.url.path,
            detail=exc.detail,
        )
        body = ErrorResponse(
            error=ErrorDetail(
                code=_status_to_code(exc.status_code),
                message=str(exc.detail),
                request_id=request_id,
            )
        )
        # `exc.headers` must survive. Rebuilding the response without them
        # silently dropped every header a raiser had attached — which meant a
        # 429 arrived with no `Retry-After`, telling a client it was throttled
        # but not for how long. Found by the rate-limit tests; it would have
        # applied equally to `WWW-Authenticate` or `Allow`.
        return JSONResponse(
            status_code=exc.status_code,
            content=body.model_dump(),
            headers=exc.headers or None,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        logger.error(
            "unhandled_exception",
            path=request.url.path,
            error_type=type(exc).__name__,
        )
        body = ErrorResponse(
            error=ErrorDetail(
                code="INTERNAL_ERROR",
                message="An unexpected error occurred.",
                request_id=request_id,
            )
        )
        return JSONResponse(status_code=500, content=body.model_dump())

    app.include_router(api_router, prefix=API_VERSION_PREFIX)

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        # Bare host with no path — someone typing just the origin they were
        # given, not an API caller (those always know the versioned path).
        # Without this, that visit is an unmatched route: a raw
        # `{"detail":"Not Found"}` with no indication `/app` or `/docs` exists.
        return RedirectResponse("/app")

    # The server-rendered dashboard, on the same application as the API so
    # there is one process, one session cookie and one authorization gate
    # rather than a second front end with its own copy of both. Every route it
    # adds is a GET — `app/web/router.py` says why, and a test proves it.
    app.include_router(web_router)
    if WEB_STATIC_DIR.is_dir():
        app.mount("/app/static", StaticFiles(directory=str(WEB_STATIC_DIR)), name="web-static")

    return app


def _status_to_code(status_code: int) -> str:
    return {
        400: "BAD_REQUEST",
        401: "UNAUTHENTICATED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        422: "VALIDATION_ERROR",
        429: "RATE_LIMITED",
    }.get(status_code, "ERROR")


app = create_app()
