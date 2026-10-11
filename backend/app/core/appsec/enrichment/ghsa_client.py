"""A thin, direct client for GitHub's global security advisory API.

Every request goes through `GatedTransport` under the fixed context
`ghsa_egress_context()` builds. Called with no token: GitHub's REST API
docs state `GET /advisories/{ghsa_id}` can be used without authentication
when only public resources are requested — confirmed, not assumed, and
exactly this client's use case (every GHSA id reaching this client came
from a finding's own verified `frameworks`, never from a private source).
"""

from __future__ import annotations

import json
from typing import Any

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import GHSA_HOST

BASE_URL = f"https://{GHSA_HOST}/advisories"
API_VERSION = "2022-11-28"


class GhsaClientError(Exception):
    """A request to GitHub's advisory API could not be completed or understood."""


class GhsaClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def get_advisory(self, ctx: RunContext, ghsa_id: str) -> dict[str, Any] | None:
        """The global advisory record for `ghsa_id`, or `None` if GitHub
        has nothing for it (including a private advisory this
        unauthenticated client cannot see — indistinguishable from "does
        not exist" at this endpoint, by design: public, unauthenticated
        access to anything else would be the actual bug).

        Raises `GhsaClientError` for anything else that went wrong — the
        caller (`advisory_detail.py`) treats that the same as `None`.
        """
        try:
            observation = await self._transport.send(
                ctx,
                method="GET",
                url=f"{BASE_URL}/{ghsa_id}",
                headers={
                    "User-Agent": "kervy-security",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": API_VERSION,
                },
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise GhsaClientError(f"refused by scope engine: {exc.decision.reason}") from exc

        if observation.status_code == 404:
            return None
        if observation.status_code >= 400:
            raise GhsaClientError(f"GET {ghsa_id} returned HTTP {observation.status_code}")
        if not observation.body:
            return None
        try:
            payload = json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise GhsaClientError(f"GET {ghsa_id} returned a body that is not JSON") from exc

        return payload if isinstance(payload, dict) else None


def cvss_detail(advisory: dict[str, Any]) -> tuple[float, str] | None:
    """`(score, vector_string)` from the advisory's own `cvss` object, or
    `None` if it carries no numeric score."""
    cvss = advisory.get("cvss")
    if not isinstance(cvss, dict):
        return None
    score, vector = cvss.get("score"), cvss.get("vector_string")
    if isinstance(score, (int, float)) and isinstance(vector, str):
        return float(score), vector
    return None
