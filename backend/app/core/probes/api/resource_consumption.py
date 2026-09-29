"""Unrestricted resource consumption — OWASP API4:2023
(docs/BUILD_SPEC.md §10).

This is the probe most able to hurt a target if written carelessly, so it
does not try to exhaust anything. It asks two cheap questions instead: does
the API advertise a rate limit, and does it accept a pagination size the
specification itself says is out of range? Both are answered in single
requests, and the run's own budget bounds them regardless.
"""

from urllib.parse import urlencode

from app.core.discovery.openapi import DiscoveredOperation, DiscoveredParameter
from app.core.probes.api._support import (
    clip,
    evidence_of,
    operation_url,
    surface_label,
    try_send,
)
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport

_RATE_LIMIT_HEADER_PREFIXES = ("x-ratelimit-", "ratelimit-", "x-rate-limit-")
_RATE_LIMIT_HEADERS = frozenset({"retry-after"})

_PAGINATION_PARAM_NAMES = frozenset(
    {"limit", "per_page", "perpage", "page_size", "pagesize", "count", "size", "top"}
)

# Large enough that no sane API should serve it, small enough that a target
# which *does* serve it is not being asked for an unbounded amount of work.
_OVERSIZED_PAGE = 10_000


class RateLimitPresenceProbe:
    id = "api.consumption.rate_limit_headers"
    version = "1.0.0"
    name = "Rate limit advertisement"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        operation = _first_get(target)
        if operation is None:
            return []

        url = operation_url(target.base_url, operation)
        observation = await try_send(ctx, transport, method=operation.method, url=url)
        if observation is None:
            return []

        names = {name.lower() for name in observation.headers}
        advertises = any(
            name.startswith(_RATE_LIMIT_HEADER_PREFIXES) or name in _RATE_LIMIT_HEADERS
            for name in names
        )
        if advertises:
            return []

        surface = surface_label(operation)
        return [
            ScanResult(
                id="KERVY-API-020",
                title="No rate limit is advertised",
                category=Category.API_SECURITY,
                severity=Severity.LOW,
                # The absence of a header is evidence about the *advertisement*,
                # not proof that no limit is enforced, and the confidence has
                # to reflect that rather than overclaiming from one response.
                confidence=Confidence.LOW,
                endpoint=surface,
                description=(
                    "The response carries no RateLimit, X-RateLimit or Retry-After "
                    "header. A limit may still be enforced upstream — this probe does "
                    "not flood the target to find out — but clients have no way to see "
                    "one, and none was observable here."
                ),
                evidence=clip(
                    f"{operation.method} {url} -> HTTP {observation.status_code}; "
                    f"no rate-limit headers among: {', '.join(sorted(names)) or '(none)'}"
                ),
                impact=(
                    "Without a published limit, well-behaved clients cannot back off, "
                    "and an abusive one is bounded only by whatever the infrastructure "
                    "happens to do."
                ),
                remediation=(
                    "Enforce a per-client limit at the gateway and return the RateLimit "
                    "headers (RFC 9239-style) plus Retry-After on 429."
                ),
                probe_id=self.id,
                probe_version=self.version,
                frameworks=("OWASP-API-2023:API4", "CWE-770"),
                reproduction=(
                    f"Send a single {operation.method} {url}.",
                    "Inspect the response headers for RateLimit/Retry-After; none present.",
                ),
                evidence_bundle=evidence_of(
                    observation,
                    probe_id=self.id,
                    probe_version=self.version,
                    verdict="no rate-limit or Retry-After header on the response",
                ),
            )
        ]


class PaginationLimitProbe:
    """Does the API honour the page-size bound its own spec declares?"""

    id = "api.consumption.pagination_limits"
    version = "1.0.0"
    name = "Pagination limits"

    def applies_to(self, target: ProbeTarget) -> bool:
        return any(_pagination_parameter(op) is not None for op in target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []

        for operation in target.operations:
            if ctx.halted:
                break
            parameter = _pagination_parameter(operation)
            if parameter is None or operation.method != "GET":
                continue

            url = (
                operation_url(target.base_url, operation)
                + "?"
                + urlencode({parameter.name: _OVERSIZED_PAGE})
            )
            observation = await try_send(ctx, transport, method="GET", url=url)
            if observation is None or not 200 <= observation.status_code < 300:
                continue

            surface = surface_label(operation)
            results.append(
                ScanResult(
                    id="KERVY-API-021",
                    title="Oversized page size is accepted",
                    category=Category.API_SECURITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    endpoint=surface,
                    description=(
                        f"{surface} accepted {parameter.name}={_OVERSIZED_PAGE} and "
                        "returned success rather than rejecting or clamping it. A caller "
                        "can choose how much work the server does per request."
                    ),
                    evidence=clip(
                        f"GET {url} -> HTTP {observation.status_code}, "
                        f"{len(observation.body)} byte body"
                    ),
                    impact=(
                        "One cheap request can be turned into an expensive query and a "
                        "large response, which is both a denial-of-service lever and a "
                        "bulk-extraction one."
                    ),
                    remediation=(
                        "Clamp the page size server-side to a documented maximum and "
                        "reject values above it explicitly instead of trusting the client."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API4", "CWE-770"),
                    reproduction=(
                        f"Send GET {url}.",
                        f"Observe HTTP {observation.status_code} rather than a 4xx or a "
                        "clamped page.",
                    ),
                    # No body: it is a page of the target's records, and how
                    # large it was is already in the verdict.
                    evidence_bundle=evidence_of(
                        observation,
                        probe_id=self.id,
                        probe_version=self.version,
                        verdict=(
                            f"accepted {parameter.name}={_OVERSIZED_PAGE}: HTTP "
                            f"{observation.status_code}, {len(observation.body)} bytes"
                        ),
                    ),
                )
            )
        return results


def _first_get(target: ProbeTarget) -> DiscoveredOperation | None:
    candidates = [op for op in target.operations if op.method == "GET"]
    if not candidates:
        return None
    return min(candidates, key=lambda op: (op.path.count("{"), len(op.path)))


def _pagination_parameter(operation: DiscoveredOperation) -> DiscoveredParameter | None:
    for parameter in operation.parameters:
        if (
            parameter.location == "query"
            and parameter.name.strip().lower().replace("-", "_") in _PAGINATION_PARAM_NAMES
        ):
            return parameter
    return None
