"""A thin, direct client for the NVD CVE API 2.0.

Every request goes through `GatedTransport` under the fixed context
`nvd_egress_context()` builds — the same "no ungated httpx" rule every
other outbound path in this codebase obeys. Called with no API key: NVD's
own CVE API works unauthenticated for public data, just at a lower rate
limit (5 requests/30s vs. 50/30s with a key) — confirmed, not assumed,
and acceptable here since this is a bounded, occasional enrichment call,
not a bulk backfill.

Only CVSS v3.0/v3.1 metrics are read. A record carrying only a v2 score
(no v3 metric present at all) is a named limitation, not chased — current
CVEs overwhelmingly carry v3 data, and v2's schema differs enough
(`baseSeverity` is not nested under `cvssData` the way v3's is) that
supporting it would roughly double this client's parsing surface for a
shrinking share of real records.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

from .egress import NVD_HOST

BASE_URL = f"https://{NVD_HOST}/rest/json/cves/2.0"


class NvdClientError(Exception):
    """A request to NVD could not be completed or understood."""


class NvdClient:
    def __init__(self, *, transport: GatedTransport | None = None) -> None:
        self._transport = transport or GatedTransport()

    async def get_cve(self, ctx: RunContext, cve_id: str) -> dict[str, Any] | None:
        """The CVE record for `cve_id`, or `None` if NVD has nothing for it.

        Raises `NvdClientError` for anything else that went wrong (refused
        by the scope engine, a non-2xx response, an unparseable body) —
        the caller (`advisory_detail.py`) treats that the same as `None`:
        a finding enrichment is optional, never required.
        """
        try:
            observation = await self._transport.send(
                ctx,
                method="GET",
                url=f"{BASE_URL}?cveId={cve_id}",
                headers={"User-Agent": "kervy-security", "Accept": "application/json"},
                timeout_seconds=20.0,
            )
        except ScopeBlockedError as exc:
            raise NvdClientError(f"refused by scope engine: {exc.decision.reason}") from exc

        if observation.status_code == 404:
            return None
        if observation.status_code >= 400:
            raise NvdClientError(f"GET {cve_id} returned HTTP {observation.status_code}")
        if not observation.body:
            return None
        try:
            payload = json.loads(observation.body)
        except json.JSONDecodeError as exc:
            raise NvdClientError(f"GET {cve_id} returned a body that is not JSON") from exc

        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return None
        first = vulnerabilities[0]
        cve = first.get("cve") if isinstance(first, dict) else None
        return cve if isinstance(cve, dict) else None


def cvss_v3_detail(cve: dict[str, Any]) -> tuple[float, str, str] | None:
    """`(base_score, base_severity, vector_string)` from the first
    available v3.1 or v3.0 metric, or `None` if the record carries no v3
    metric at all (see the module docstring's named limitation)."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        data = entries[0].get("cvssData") if isinstance(entries[0], dict) else None
        if not isinstance(data, dict):
            continue
        score, severity, vector = (
            data.get("baseScore"),
            data.get("baseSeverity"),
            data.get("vectorString"),
        )
        if isinstance(score, (int, float)) and isinstance(severity, str) and isinstance(
            vector, str
        ):
            return float(score), severity, vector
    return None


def english_description(cve: dict[str, Any]) -> str | None:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return None
    for entry in descriptions:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            value = entry.get("value")
            return value if isinstance(value, str) else None
    return None
