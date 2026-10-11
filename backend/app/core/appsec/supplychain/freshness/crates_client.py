"""A thin, direct client for crates.io's per-version metadata endpoint.

Every request goes through `GatedTransport` under the fixed context
`crates_egress_context()` builds, carrying a descriptive User-Agent per
crates.io's own stated API policy (confirmed via research: anonymous use
is capped around 1 request/second and a client naming only its HTTP
library, rather than identifying the calling application with contact
information, risks being blocked outright).

`GET /api/v1/crates/<name>/<version>` returns `version.created_at` (the
publish time) and, uniquely among the four registries this package calls,
`version.published_by.created_at` — the publishing GitHub account's own
creation date. Confirmed live against `serde`@1.0.229 before relying on
either field. Neither npm's packument nor PyPI's JSON API exposes an
equivalent publisher-account-age field through an unauthenticated call
(confirmed via research, not assumed) — this is a genuine, confirmed
asymmetry across ecosystems, not an oversight in the other two clients.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import CRATES_HOST

BASE_URL = f"https://{CRATES_HOST}/api/v1/crates"

#: Identifies the calling application with a real contact point, per
#: crates.io's own stated policy — see the module docstring.
USER_AGENT = "kervy-security (+https://github.com/joeabur/Security-Testing-Platform)"


class CratesRegistryClientError(Exception):
    """A request to crates.io could not be completed or understood."""


@dataclass(frozen=True)
class CrateVersionDetail:
    published_at: datetime
    #: The publishing account's own creation date, when crates.io reports
    #: one — absent for a crate published before that field existed, or
    #: for an account crates.io otherwise has no creation date for.
    publisher_account_created_at: datetime | None = None


class CratesRegistryClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def get_version_detail(
        self, ctx: RunContext, name: str, version: str
    ) -> CrateVersionDetail | None:
        """Publish time (and, where available, publisher-account age) for
        `version` of `name`, or `None` if crates.io has no record of it.

        Raises `CratesRegistryClientError` for anything else that went
        wrong — the caller (`engine.py`) treats that the same as `None`.
        """
        try:
            observation = await self._transport.send(
                ctx,
                method="GET",
                url=f"{BASE_URL}/{quote(name, safe='')}/{quote(version, safe='')}",
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise CratesRegistryClientError(
                f"refused by scope engine: {exc.decision.reason}"
            ) from exc

        if observation.status_code == 404:
            return None
        if observation.status_code >= 400:
            raise CratesRegistryClientError(
                f"GET {name}/{version} returned HTTP {observation.status_code}"
            )
        if not observation.body:
            return None
        try:
            payload = json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise CratesRegistryClientError(
                f"GET {name}/{version} returned a body that is not JSON"
            ) from exc

        return _parse_detail(payload)


def _parse_timestamp(raw: object) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _parse_detail(payload: Any) -> CrateVersionDetail | None:
    if not isinstance(payload, dict):
        return None
    version = payload.get("version")
    if not isinstance(version, dict):
        return None
    published_at = _parse_timestamp(version.get("created_at"))
    if published_at is None:
        return None

    publisher_created_at = None
    published_by = version.get("published_by")
    if isinstance(published_by, dict):
        publisher_created_at = _parse_timestamp(published_by.get("created_at"))

    return CrateVersionDetail(
        published_at=published_at, publisher_account_created_at=publisher_created_at
    )
