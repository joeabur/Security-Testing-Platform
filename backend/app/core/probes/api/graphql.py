"""GraphQL — introspection, depth, batching and error verbosity
(docs/BUILD_SPEC.md §10).

GraphQL moves work the client asks for onto the server, so the questions
are different from REST: not "may I call this?" but "how much can one query
cost, and how much does the schema tell me for free?".

The amplification checks are written to *detect a missing limit without
exercising it*. The nested query sent here is deep but tiny, and the alias
batch is a handful of aliases, not thousands — enough for a server with a
complexity limit to reject, and not enough to hurt one without.
"""

import json
from urllib.parse import urljoin

from app.core.probes.api._support import body_text, clip, evidence_of, try_send
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, Observation

_GRAPHQL_PATH_HINTS = ("graphql", "graphiql", "gql")

# Small enough to be harmless, deep enough that any configured depth limit
# (they are conventionally 5-15) rejects it.
_DEPTH = 20
_ALIAS_COUNT = 10

_INTROSPECTION_QUERY = "{__schema{queryType{name} types{name kind}}}"

_ERROR_MARKERS = (
    "traceback (most recent call last)",
    "at java.",
    "sqlalchemy.exc",
    "psycopg2.",
    "stack trace:",
)


def _graphql_operations(target: ProbeTarget) -> list[str]:
    """Paths that look like a GraphQL endpoint, from the declared surface."""
    paths: list[str] = []
    for operation in target.operations:
        lowered = operation.path.lower()
        if any(hint in lowered for hint in _GRAPHQL_PATH_HINTS) and operation.path not in paths:
            paths.append(operation.path)
    return paths


def _nested_query(depth: int) -> str:
    """`{a{a{a{ ... __typename ... }}}}` — deep, but a few hundred bytes."""
    body = "__typename"
    for _ in range(depth):
        body = "a{" + body + "}"
    return "{" + body + "}"


def _alias_query(count: int) -> str:
    aliases = " ".join(f"a{index}:__typename" for index in range(count))
    return "{" + aliases + "}"


async def _post_query(
    ctx: RunContext, transport: GatedTransport, url: str, query: str
) -> Observation | None:
    return await try_send(
        ctx,
        transport,
        method="POST",
        url=url,
        headers={"Content-Type": "application/json"},
        content=json.dumps({"query": query}).encode("utf-8"),
    )


def _errored(observation: Observation) -> bool:
    """Did the server refuse the query, by status or by GraphQL error?

    GraphQL conventionally answers 200 with an `errors` array, so status
    alone would read a rejection as an acceptance.
    """
    if observation.status_code >= 400:
        return True
    try:
        payload = json.loads(observation.body)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(payload, dict) and bool(payload.get("errors"))


class GraphQLIntrospectionProbe:
    id = "api.graphql.introspection"
    version = "1.0.0"
    name = "GraphQL introspection exposure"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(_graphql_operations(target))

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        base = target.base_url if target.base_url.endswith("/") else target.base_url + "/"

        for path in _graphql_operations(target):
            if ctx.halted:
                break
            url = urljoin(base, path.lstrip("/"))
            observation = await _post_query(ctx, transport, url, _INTROSPECTION_QUERY)
            if observation is None or _errored(observation):
                continue
            if "__schema" not in body_text(observation):
                continue

            results.append(
                ScanResult(
                    id="KERVY-API-060",
                    title="GraphQL introspection is enabled",
                    category=Category.API_SECURITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    endpoint=f"POST {path}",
                    description=(
                        "The endpoint answered an introspection query with its schema. "
                        "Introspection publishes every type, field and mutation, "
                        "including the ones that were never meant to be part of the "
                        "public contract."
                    ),
                    evidence=clip(
                        f"POST {url} {_INTROSPECTION_QUERY} -> "
                        f"HTTP {observation.status_code}, schema returned"
                    ),
                    impact=(
                        "An attacker gets a complete, accurate map of the API for free, "
                        "including deprecated and internal fields that are usually where "
                        "the weak authorization lives."
                    ),
                    remediation=(
                        "Disable introspection outside development, and publish a "
                        "reviewed schema to the clients that need one instead."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API9", "CWE-200"),
                    reproduction=(
                        f"POST {url} with query {_INTROSPECTION_QUERY}.",
                        "Observe the schema in the response rather than an error.",
                    ),
                    # The schema is the finding, and it is the target's own
                    # published contract rather than anybody's data.
                    evidence_bundle=evidence_of(
                        observation,
                        probe_id=self.id,
                        probe_version=self.version,
                        request_body=_INTROSPECTION_QUERY,
                        verdict="introspection answered with a schema",
                        include_body=True,
                    ),
                )
            )
        return results


class GraphQLQueryCostProbe:
    """Are depth and aliasing bounded, or does the client decide the cost?"""

    id = "api.graphql.query_cost"
    version = "1.0.0"
    name = "GraphQL query depth and aliasing limits"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(_graphql_operations(target))

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        base = target.base_url if target.base_url.endswith("/") else target.base_url + "/"

        for path in _graphql_operations(target):
            if ctx.halted:
                break
            url = urljoin(base, path.lstrip("/"))

            depth_response = await _post_query(ctx, transport, url, _nested_query(_DEPTH))
            if depth_response is not None and not _errored(depth_response):
                results.append(
                    self._result(
                        path,
                        url,
                        observation=depth_response,
                        request_body=_nested_query(_DEPTH),
                        title="GraphQL query depth is not limited",
                        detail=(
                            f"A query nested {_DEPTH} levels deep was accepted without a "
                            "depth or complexity error."
                        ),
                        status_code=depth_response.status_code,
                        query=f"{_DEPTH}-level nested query",
                        framework_note="depth",
                    )
                )

            alias_response = await _post_query(ctx, transport, url, _alias_query(_ALIAS_COUNT))
            if alias_response is not None and not _errored(alias_response):
                results.append(
                    self._result(
                        path,
                        url,
                        observation=alias_response,
                        request_body=_alias_query(_ALIAS_COUNT),
                        title="GraphQL aliasing is not limited",
                        detail=(
                            f"A query repeating {_ALIAS_COUNT} aliases of the same field "
                            "was accepted without a complexity error. Aliases multiply "
                            "the work per request, so an unbounded count turns one "
                            "request into arbitrarily many resolver calls."
                        ),
                        status_code=alias_response.status_code,
                        query=f"{_ALIAS_COUNT} aliased fields",
                        framework_note="aliasing",
                    )
                )
        return results

    def _result(
        self,
        path: str,
        url: str,
        *,
        observation: Observation,
        request_body: str,
        title: str,
        detail: str,
        status_code: int,
        query: str,
        framework_note: str,
    ) -> ScanResult:
        return ScanResult(
            id="KERVY-API-061",
            title=title,
            category=Category.API_SECURITY,
            severity=Severity.MEDIUM,
            # A small probe query proves no limit *at this size*. That is
            # real evidence of a missing bound but not a measured breaking
            # point, and the confidence says so rather than implying a
            # load test that was deliberately not run.
            confidence=Confidence.MEDIUM,
            endpoint=f"POST {path}",
            description=detail,
            evidence=clip(f"POST {url} with a {query} -> HTTP {status_code}, no error returned"),
            impact=(
                "One request can be made arbitrarily expensive, so a single client can "
                "consume the server's capacity without needing volume."
            ),
            remediation=(
                f"Apply a query {framework_note} limit and a cost/complexity budget at "
                "the GraphQL layer, and reject queries above it before execution starts."
            ),
            probe_id=self.id,
            probe_version=self.version,
            frameworks=("OWASP-API-2023:API4", "CWE-770"),
            reproduction=(
                f"POST {url} with a {query}.",
                f"Observe HTTP {status_code} with no depth or complexity error.",
            ),
            # No body: what matters is that the query was accepted, not what
            # it returned, and an unbounded query's response can be large.
            evidence_bundle=evidence_of(
                observation,
                probe_id=self.id,
                probe_version=self.version,
                request_body=request_body,
                verdict=f"accepted a {query}: HTTP {status_code}, no complexity error",
            ),
        )


class GraphQLErrorVerbosityProbe:
    id = "api.graphql.error_verbosity"
    version = "1.0.0"
    name = "GraphQL error verbosity"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(_graphql_operations(target))

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        base = target.base_url if target.base_url.endswith("/") else target.base_url + "/"

        for path in _graphql_operations(target):
            if ctx.halted:
                break
            url = urljoin(base, path.lstrip("/"))
            observation = await _post_query(ctx, transport, url, "{ kervyNoSuchField }")
            if observation is None:
                continue

            lowered = body_text(observation).lower()
            marker = next((m for m in _ERROR_MARKERS if m in lowered), None)
            if marker is None:
                continue

            results.append(
                ScanResult(
                    id="KERVY-API-062",
                    title="GraphQL errors expose internal details",
                    category=Category.API_SECURITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    endpoint=f"POST {path}",
                    description=(
                        "A query for a field that does not exist returned server "
                        f"internals (matched {marker!r}) rather than a schema error."
                    ),
                    evidence=clip(
                        f"POST {url} {{ kervyNoSuchField }} -> "
                        f"HTTP {observation.status_code}\n{body_text(observation)}"
                    ),
                    impact=(
                        "Resolver stack traces reveal internal structure and library "
                        "versions, and often the shape of the data store behind them."
                    ),
                    remediation=(
                        "Mask errors in non-development environments: return the GraphQL "
                        "error with a correlation id and keep the trace server-side."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API8", "CWE-209"),
                    reproduction=(
                        f"POST {url} with query {{ kervyNoSuchField }}.",
                        f"Observe {marker!r} in the response body.",
                    ),
                    evidence_bundle=evidence_of(
                        observation,
                        probe_id=self.id,
                        probe_version=self.version,
                        request_body="{ kervyNoSuchField }",
                        verdict=f"resolver internals matched {marker!r}",
                        include_body=True,
                    ),
                )
            )
        return results
