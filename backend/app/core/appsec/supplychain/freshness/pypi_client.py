"""A thin, direct client for PyPI's per-release JSON API.

Every request goes through `GatedTransport` under the fixed context
`pypi_egress_context()` builds. `GET /pypi/<name>/<version>/json` is PyPI's
documented per-version endpoint — lighter than fetching the whole
project's release history just to read one version's upload time — and
its `urls[*].upload_time_iso_8601` field was confirmed live against
`requests` before relying on it, not assumed from documentation alone.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import PYPI_HOST

BASE_URL = f"https://{PYPI_HOST}/pypi"


class PypiRegistryClientError(Exception):
    """A request to PyPI's JSON API could not be completed or understood."""


class PypiRegistryClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def get_publish_time(
        self, ctx: RunContext, name: str, version: str
    ) -> datetime | None:
        """When `version` of `name` was uploaded, or `None` if PyPI has no
        record of that release (never published at that version, or a
        project that no longer exists).

        Raises `PypiRegistryClientError` for anything else that went
        wrong — the caller (`engine.py`) treats that the same as `None`.
        """
        try:
            observation = await self._transport.send(
                ctx,
                method="GET",
                url=f"{BASE_URL}/{quote(name, safe='')}/{quote(version, safe='')}/json",
                headers={"User-Agent": "kervy-security", "Accept": "application/json"},
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise PypiRegistryClientError(
                f"refused by scope engine: {exc.decision.reason}"
            ) from exc

        if observation.status_code == 404:
            return None
        if observation.status_code >= 400:
            raise PypiRegistryClientError(
                f"GET {name}/{version} returned HTTP {observation.status_code}"
            )
        if not observation.body:
            return None
        try:
            payload = json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise PypiRegistryClientError(
                f"GET {name}/{version} returned a body that is not JSON"
            ) from exc

        return _earliest_upload_time(payload)


def _earliest_upload_time(payload: Any) -> datetime | None:
    if not isinstance(payload, dict):
        return None
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        return None
    times: list[datetime] = []
    for entry in urls:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("upload_time_iso_8601")
        if not isinstance(raw, str):
            continue
        try:
            times.append(datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC))
        except ValueError:
            continue
    return min(times) if times else None
