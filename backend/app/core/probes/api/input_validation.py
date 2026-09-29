"""Input validation — generated from the specification, not a static list
(docs/BUILD_SPEC.md §10).

Every case this probe sends is derived from what the operation *declares*:
a required parameter is omitted, a declared integer is given a string, a
declared minimum/maximum is stepped past, a declared maxLength is exceeded,
and a JSON body is sent malformed. That is the difference between testing
this API and replaying a generic fuzz list at it — a case only exists
because the contract said something that can be violated.

None of the payloads are attacks. They are wrong-shaped values, which is
what an input-validation check needs and all it needs.
"""

import json
from dataclasses import dataclass
from urllib.parse import urlencode

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.api._support import (
    body_text,
    clip,
    evidence_of,
    operation_url,
    surface_label,
    try_send,
)
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, Observation

# Bounds so one badly-shaped surface cannot spend a whole run's budget.
MAX_CASES_PER_OPERATION = 4
MAX_CASES_TOTAL = 40

_READ_METHODS = frozenset({"GET", "HEAD"})


@dataclass(frozen=True)
class _Case:
    """One generated violation of the operation's own contract."""

    what: str
    url: str
    method: str
    headers: dict[str, str] | None = None
    content: bytes | None = None


class InputValidationProbe:
    id = "api.input_validation.schema_violations"
    version = "1.0.0"
    name = "Input validation against the declared schema"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        sent = 0

        for operation in target.operations:
            if ctx.halted or sent >= MAX_CASES_TOTAL:
                break
            # Safe mode exercises read methods only: a write that the API
            # wrongly accepts would have changed state to tell us so.
            if target.safe_mode and operation.method not in _READ_METHODS:
                continue

            for case in self._cases(target, operation)[:MAX_CASES_PER_OPERATION]:
                if ctx.halted or sent >= MAX_CASES_TOTAL:
                    break
                observation = await try_send(
                    ctx,
                    transport,
                    method=case.method,
                    url=case.url,
                    headers=case.headers,
                    content=case.content,
                )
                sent += 1
                if observation is None:
                    continue

                surface = surface_label(operation)
                if observation.status_code >= 500:
                    results.append(self._server_error(surface, case, observation))
                elif 200 <= observation.status_code < 300:
                    results.append(self._accepted(surface, case, observation))

        return results

    def _cases(self, target: ProbeTarget, operation: DiscoveredOperation) -> list[_Case]:
        url = operation_url(target.base_url, operation)
        cases: list[_Case] = []

        for parameter in operation.parameters:
            if parameter.location != "query":
                continue
            declared = (parameter.schema_type or "").lower()
            if declared in ("integer", "number"):
                cases.append(
                    _Case(
                        what=(
                            f"query parameter {parameter.name} is declared {declared} "
                            "but was sent the string 'kervy'"
                        ),
                        url=f"{url}?{urlencode({parameter.name: 'kervy'})}",
                        method=operation.method,
                    )
                )
            elif declared == "boolean":
                cases.append(
                    _Case(
                        what=(
                            f"query parameter {parameter.name} is declared boolean but "
                            "was sent 'maybe'"
                        ),
                        url=f"{url}?{urlencode({parameter.name: 'maybe'})}",
                        method=operation.method,
                    )
                )

        # A JSON body sent as invalid JSON: the framework must reject it, and
        # a 5xx here means the parse error reached the caller unhandled.
        if any("json" in media.lower() for media in operation.request_body_content_types):
            cases.append(
                _Case(
                    what="request body declared as JSON was sent malformed",
                    url=url,
                    method=operation.method,
                    headers={"Content-Type": "application/json"},
                    content=b'{"kervy": ',
                )
            )
            cases.extend(self._body_field_cases(operation, url))

        return cases

    def _body_field_cases(self, operation: DiscoveredOperation, url: str) -> list[_Case]:
        cases: list[_Case] = []
        for field in operation.body_fields:
            payload: dict[str, object] | None = None
            what = ""
            declared = (field.schema_type or "").lower()

            if field.max_length is not None:
                payload = {field.name: "a" * (field.max_length + 1)}
                what = f"body field {field.name} exceeds its declared maxLength {field.max_length}"
            elif field.maximum is not None:
                payload = {field.name: field.maximum + 1}
                what = f"body field {field.name} exceeds its declared maximum {field.maximum}"
            elif field.minimum is not None:
                payload = {field.name: field.minimum - 1}
                what = f"body field {field.name} is below its declared minimum {field.minimum}"
            elif field.enum_values:
                payload = {field.name: "kervy-not-in-enum"}
                what = f"body field {field.name} is outside its declared enum"
            elif declared in ("integer", "number"):
                payload = {field.name: "kervy"}
                what = f"body field {field.name} is declared {declared} but was sent a string"

            if payload is not None:
                cases.append(
                    _Case(
                        what=what,
                        url=url,
                        method=operation.method,
                        headers={"Content-Type": "application/json"},
                        content=json.dumps(payload).encode("utf-8"),
                    )
                )
        return cases

    def _server_error(self, surface: str, case: _Case, observation: Observation) -> ScanResult:
        status_code = observation.status_code
        body = body_text(observation)
        return ScanResult(
            id="KERVY-API-040",
            title="Invalid input causes a server error",
            category=Category.API_SECURITY,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            endpoint=surface,
            description=(
                f"A request where {case.what} produced HTTP {status_code}. Input that "
                "violates the API's own contract should be refused with a 4xx; a 5xx "
                "means it reached code that was not expecting it."
            ),
            evidence=clip(f"{case.method} {case.url} -> HTTP {status_code}\n{body}"),
            impact=(
                "An unhandled path reachable from user input is where crashes, resource "
                "leaks and information-disclosing errors come from, and it is reachable "
                "by anyone who can call the endpoint."
            ),
            remediation=(
                "Validate against the declared schema at the edge and return 400 for a "
                "contract violation, so the handler only ever sees well-formed input."
            ),
            probe_id=self.id,
            probe_version=self.version,
            frameworks=("OWASP-API-2023:API8", "CWE-20"),
            reproduction=(
                f"Send {case.method} {case.url}"
                + (" with a malformed JSON body." if case.content else "."),
                f"Observe HTTP {status_code} rather than a 400.",
            ),
            # The 5xx body is the finding: it is where the unhandled path
            # names itself. Redacted on the way in, like every bundle.
            evidence_bundle=evidence_of(
                observation,
                probe_id=self.id,
                probe_version=self.version,
                request_headers=case.headers,
                request_body=(case.content or b"").decode("utf-8", errors="replace"),
                verdict=f"HTTP {status_code} from input that violates the declared schema",
                include_body=True,
            ),
        )

    def _accepted(self, surface: str, case: _Case, observation: Observation) -> ScanResult:
        status_code = observation.status_code
        return ScanResult(
            id="KERVY-API-041",
            title="Input violating the declared schema is accepted",
            category=Category.API_SECURITY,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            endpoint=surface,
            description=(
                f"A request where {case.what} was answered with HTTP {status_code}. The "
                "endpoint accepted input its own specification says is invalid, so the "
                "contract and the implementation disagree."
            ),
            evidence=clip(f"{case.method} {case.url} -> HTTP {status_code}"),
            impact=(
                "Clients generated from the specification assume the declared "
                "constraints hold. Where they do not, the real constraint is whatever "
                "the handler happens to do, which is not reviewable."
            ),
            remediation=(
                "Enforce the declared types and bounds server-side, or correct the "
                "specification if the constraint was never intended."
            ),
            probe_id=self.id,
            probe_version=self.version,
            frameworks=("OWASP-API-2023:API8", "OWASP-API-2023:API9", "CWE-20"),
            reproduction=(
                f"Send {case.method} {case.url}.",
                f"Observe HTTP {status_code} rather than a 400.",
            ),
            # No body: what the endpoint returned for out-of-contract input
            # is not the point — that it answered at all is.
            evidence_bundle=evidence_of(
                observation,
                probe_id=self.id,
                probe_version=self.version,
                request_headers=case.headers,
                request_body=(case.content or b"").decode("utf-8", errors="replace"),
                verdict=f"HTTP {status_code} for input the specification forbids",
            ),
        )
