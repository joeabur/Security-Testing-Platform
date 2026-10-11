"""A thin, direct client for the npm registry's per-package packument.

Every request goes through `GatedTransport` under the fixed context
`npm_egress_context()` builds. A package's publish time for a given
version lives only in the full packument at `GET /<name>` (the per-version
document at `GET /<name>/<version>` carries no timestamp at all) — the
`time` map there was confirmed live against `left-pad` and the scoped
package `@types/node` before relying on it, not assumed from documentation
alone. Scoped names (`@scope/pkg`) are passed as one URL-encoded path
segment (`@scope%2Fpkg`), confirmed working the same way live.

A large, long-lived package's full packument can be tens of megabytes
(`vite`'s is ~37MB for 725 versions) — `timeout_seconds` bounds the cost of
that rather than this client refusing to ask, since most dependencies are
not that large, and a slow or oversized response is handled the same as
any other failed lookup: skipped by the caller, not fatal to the run.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import NPM_HOST

BASE_URL = f"https://{NPM_HOST}"


class NpmRegistryClientError(Exception):
    """A request to the npm registry could not be completed or understood."""


class NpmRegistryClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def get_publish_time(
        self, ctx: RunContext, name: str, version: str
    ) -> datetime | None:
        """When `version` of `name` was published, or `None` if the
        registry has no record of it (unpublished, never published at
        that version, or a package that no longer exists).

        Raises `NpmRegistryClientError` for anything else that went
        wrong — the caller (`engine.py`) treats that the same as `None`:
        a single dependency's freshness check is optional, never required
        for the rest of a run to complete.
        """
        try:
            observation = await self._transport.send(
                ctx,
                method="GET",
                url=f"{BASE_URL}/{quote(name, safe='@')}",
                headers={"User-Agent": "kervy-security", "Accept": "application/json"},
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise NpmRegistryClientError(
                f"refused by scope engine: {exc.decision.reason}"
            ) from exc

        if observation.status_code == 404:
            return None
        if observation.status_code >= 400:
            raise NpmRegistryClientError(
                f"GET {name} returned HTTP {observation.status_code}"
            )
        if not observation.body:
            return None
        try:
            payload = json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise NpmRegistryClientError(f"GET {name} returned a body that is not JSON") from exc

        return _parse_time(payload, version)


def _parse_time(payload: Any, version: str) -> datetime | None:
    if not isinstance(payload, dict):
        return None
    time_map = payload.get("time")
    if not isinstance(time_map, dict):
        return None
    raw = time_map.get(version)
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
