"""A thin, direct client for the Go module proxy's per-version info file.

Every request goes through `GatedTransport` under the fixed context
`go_proxy_egress_context()` builds. `GET /<escaped-module>/@v/<version>.info`
is the Go module proxy protocol's own documented per-version metadata
endpoint, returning a `Time` field — confirmed live against
`github.com/pkg/errors`@v0.9.1 before relying on it.

**Module path case-escaping is required, not optional**, confirmed live:
an unescaped mixed-case module path (`github.com/BurntSushi/toml`)
returns `400 invalid escaped module path`, while the escaped form
(`github.com/!burnt!sushi/toml`) returns the right record. This is the Go
module proxy's own protocol rule (`golang.org/x/mod/module.EscapePath`):
every uppercase letter is replaced with `!` followed by its lowercase
form, so the proxy's own case-insensitive storage cannot collide two
modules that differ only in case.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import GO_PROXY_HOST

BASE_URL = f"https://{GO_PROXY_HOST}"


class GoProxyClientError(Exception):
    """A request to the Go module proxy could not be completed or understood."""


def escape_module_path(path: str) -> str:
    """Go's own module-proxy case-escaping rule: every uppercase letter
    becomes `!` followed by its lowercase form. A path with no uppercase
    letters round-trips unchanged."""
    escaped = []
    for char in path:
        if char.isupper():
            escaped.append("!" + char.lower())
        else:
            escaped.append(char)
    return "".join(escaped)


class GoProxyClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def get_publish_time(
        self, ctx: RunContext, module: str, version: str
    ) -> datetime | None:
        """When `version` of `module` was published, or `None` if the
        proxy has no record of it.

        Raises `GoProxyClientError` for anything else that went wrong —
        the caller (`engine.py`) treats that the same as `None`.
        """
        escaped_module = escape_module_path(module)
        escaped_version = escape_module_path(version)
        path = "/".join(quote(part, safe="!") for part in escaped_module.split("/"))
        try:
            observation = await self._transport.send(
                ctx,
                method="GET",
                url=f"{BASE_URL}/{path}/@v/{quote(escaped_version, safe='!')}.info",
                headers={"User-Agent": "kervy-security", "Accept": "application/json"},
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise GoProxyClientError(f"refused by scope engine: {exc.decision.reason}") from exc

        if observation.status_code == 404:
            return None
        if observation.status_code >= 400:
            raise GoProxyClientError(
                f"GET {module}@{version} returned HTTP {observation.status_code}"
            )
        if not observation.body:
            return None
        try:
            payload = json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise GoProxyClientError(
                f"GET {module}@{version} returned a body that is not JSON"
            ) from exc

        return _parse_time(payload)


def _parse_time(payload: Any) -> datetime | None:
    if not isinstance(payload, dict):
        return None
    raw = payload.get("Time")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
