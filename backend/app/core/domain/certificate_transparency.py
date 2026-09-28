"""Certificate-transparency-log subdomain discovery via crt.sh.

Goes through `GatedTransport` like every other outbound request this
platform makes — crt.sh is just another host, checked against the run's
`allowed_domains`/blocked-IP rules the same as anything else `transport.send`
touches. A query the scope engine refuses (crt.sh not allowlisted) is not an
error: it is skipped, the same way DAST treats a refused discovered link.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote

from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, ScopeBlockedError

_CRT_SH_URL = "https://crt.sh/?q={query}&output=json"
_VALID_HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)


async def query_certificate_transparency(
    ctx: RunContext, transport: GatedTransport, root_domain: str
) -> tuple[set[str], str | None]:
    """Returns `(hostnames, skip_reason)`.

    `skip_reason` is set, and `hostnames` left empty, whenever the query
    could not be made or parsed — never raised, since a CT-log outage says
    nothing about the target being assessed.
    """
    url = _CRT_SH_URL.format(query=quote(f"%.{root_domain}"))
    try:
        observation = await transport.send(ctx, method="GET", url=url, timeout_seconds=20.0)
    except ScopeBlockedError as exc:
        return set(), f"crt.sh query refused: {exc.decision.reason}"
    except Exception as exc:  # noqa: BLE001 - a CT-log outage is not this run's failure
        return set(), f"crt.sh query failed: {exc}"

    if observation.status_code != 200:
        return set(), f"crt.sh responded with {observation.status_code}"

    try:
        entries = json.loads(observation.body or b"[]")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return set(), f"crt.sh response was not valid JSON: {exc}"

    root = root_domain.lower()
    hostnames: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        raw = entry.get("name_value", "") if isinstance(entry, dict) else ""
        for candidate in str(raw).split("\n"):
            candidate = candidate.strip().lower()
            # A wildcard SAN ("*.example.test") names no single host, so it is
            # skipped outright rather than stripped down to "example.test" —
            # `str.lstrip` removes *characters*, not a literal prefix, and
            # would otherwise fold a wildcard entry into the root domain.
            if candidate.startswith("*."):
                continue
            candidate = candidate.rstrip(".")
            if not candidate or not _VALID_HOSTNAME.match(candidate):
                continue
            if candidate == root or candidate.endswith(f".{root}"):
                hostnames.add(candidate)
    return hostnames, None
