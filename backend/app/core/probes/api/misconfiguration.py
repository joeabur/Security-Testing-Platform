"""Security misconfiguration — OWASP API8:2023 (docs/BUILD_SPEC.md §10).

These are header- and error-shape observations on responses the run was
going to make anyway, so they cost little and are among the few API
findings that are genuinely deterministic.
"""

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.api._support import (
    body_text,
    clip,
    evidence_of,
    operation_url,
    surface_label,
    try_send,
    untested,
)
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport, Observation

# Only headers whose *absence* is meaningful for an API (not a web page) are
# listed: an API that is never rendered in a browser does not need a CSP to
# be considered configured, but it does need to stop content sniffing and to
# pin clients to TLS.
_EXPECTED_HEADERS = {
    "x-content-type-options": (
        "Browsers and some clients will sniff a response body and act on a type the "
        "server did not intend."
    ),
    "strict-transport-security": (
        "Clients can be downgraded to plaintext on a later request, which undoes TLS "
        "for exactly the requests an attacker chooses."
    ),
}

# Strings that only appear when a framework is returning an internal error
# verbatim. Each is a phrase from a stack trace or debug page, not a word a
# normal error message would use.
_VERBOSE_ERROR_MARKERS = (
    "traceback (most recent call last)",
    "stack trace:",
    "at java.",
    "org.springframework",
    "system.nullreferenceexception",
    "werkzeug.exceptions",
    "django.core.exceptions",
    "sqlalchemy.exc",
    "psycopg2.",
    "ora-0",
    "sql syntax",
    "goroutine ",
)

# Paths that expose an application's internals when left enabled. Each is
# requested through the scope engine like anything else, so a target whose
# RoE does not cover them is simply not tested for them.
_DEBUG_PATHS = (
    "/.env",
    "/actuator/env",
    "/debug",
    "/debug/pprof/",
    "/metrics",
    "/server-status",
)


class SecurityHeadersProbe:
    id = "api.misconfig.security_headers"
    version = "1.0.0"
    name = "Security response headers"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        operation = _first_readable(target)
        if operation is None:
            return []

        url = operation_url(target.base_url, operation)
        observation = await try_send(ctx, transport, method=operation.method, url=url)
        if observation is None:
            return [
                untested(
                    probe_id=self.id,
                    probe_version=self.version,
                    endpoint=surface_label(operation),
                    what="Security response headers",
                    reason="No response was obtained from the target to inspect.",
                )
            ]

        present = {name.lower() for name in observation.headers}
        missing = sorted(header for header in _EXPECTED_HEADERS if header not in present)
        if not missing:
            return []

        surface = surface_label(operation)
        return [
            ScanResult(
                id="KERVY-API-010",
                title="Security response headers are missing",
                category=Category.API_SECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                endpoint=surface,
                description=(
                    "The response omits "
                    + ", ".join(missing)
                    + ". "
                    + " ".join(_EXPECTED_HEADERS[header] for header in missing)
                ),
                evidence=clip(
                    f"{operation.method} {url} -> HTTP {observation.status_code}; "
                    f"headers present: {', '.join(sorted(present)) or '(none)'}"
                ),
                impact=(
                    "Each missing header removes one defence that would otherwise "
                    "hold even when something else has already gone wrong."
                ),
                remediation=(
                    "Set the missing headers globally in the gateway or application "
                    "middleware rather than per route, so a new endpoint inherits them."
                ),
                probe_id=self.id,
                probe_version=self.version,
                frameworks=("OWASP-API-2023:API8", "CWE-693"),
                reproduction=(
                    f"Send {operation.method} {url}.",
                    f"Inspect the response headers and note that {', '.join(missing)} are absent.",
                ),
                evidence_bundle=evidence_of(
                    observation,
                    probe_id=self.id,
                    probe_version=self.version,
                    verdict=f"missing: {', '.join(missing)}",
                ),
            )
        ]


class CorsPolicyProbe:
    """Does the API hand its origin policy to the caller?"""

    id = "api.misconfig.cors"
    version = "1.0.0"
    name = "CORS policy"

    # An origin that is obviously not the target's own. If the API reflects
    # this back, it is reflecting whatever it is given.
    PROBE_ORIGIN = "https://kervy-probe.invalid"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        operation = _first_readable(target)
        if operation is None:
            return []

        url = operation_url(target.base_url, operation)
        observation = await try_send(
            ctx,
            transport,
            method=operation.method,
            url=url,
            headers={"Origin": self.PROBE_ORIGIN},
        )
        if observation is None:
            return []

        headers = {name.lower(): value for name, value in observation.headers.items()}
        allow_origin = headers.get("access-control-allow-origin", "").strip()
        allow_credentials = headers.get("access-control-allow-credentials", "").strip().lower()
        if not allow_origin:
            return []

        reflected = allow_origin == self.PROBE_ORIGIN
        wildcard = allow_origin == "*"
        if not reflected and not wildcard:
            return []

        with_credentials = allow_credentials == "true"
        # A wildcard origin cannot carry credentials — browsers refuse it —
        # so the dangerous combination is a *reflected* origin plus
        # credentials, and the severity has to say which case this is.
        severity = Severity.HIGH if reflected and with_credentials else Severity.MEDIUM
        surface = surface_label(operation)
        description = (
            f"The API echoed the arbitrary origin {self.PROBE_ORIGIN} back in "
            "Access-Control-Allow-Origin"
            if reflected
            else "The API allows any origin via Access-Control-Allow-Origin: *"
        )
        if with_credentials:
            description += " while also setting Access-Control-Allow-Credentials: true"

        return [
            ScanResult(
                id="KERVY-API-011",
                title="Permissive CORS policy",
                category=Category.API_SECURITY,
                severity=severity,
                confidence=Confidence.HIGH,
                endpoint=surface,
                description=description + ".",
                evidence=clip(
                    f"Request Origin: {self.PROBE_ORIGIN}\n"
                    f"Access-Control-Allow-Origin: {allow_origin}\n"
                    f"Access-Control-Allow-Credentials: {allow_credentials or '(absent)'}"
                ),
                impact=(
                    "A page on any origin can read this API's responses in a victim's "
                    "browser with the victim's session attached."
                    if reflected and with_credentials
                    else "Any origin can read responses from this API in a browser."
                ),
                remediation=(
                    "Reflect only origins from an explicit allowlist, and never combine "
                    "a reflected or wildcard origin with Allow-Credentials: true."
                ),
                probe_id=self.id,
                probe_version=self.version,
                frameworks=("OWASP-API-2023:API8", "CWE-942"),
                reproduction=(
                    f"Send {operation.method} {url} with Origin: {self.PROBE_ORIGIN}.",
                    f"Observe Access-Control-Allow-Origin: {allow_origin} in the response.",
                ),
                evidence_bundle=evidence_of(
                    observation,
                    probe_id=self.id,
                    probe_version=self.version,
                    request_headers={"Origin": self.PROBE_ORIGIN},
                    verdict=(
                        f"Access-Control-Allow-Origin: {allow_origin}; "
                        f"Allow-Credentials: {allow_credentials or '(absent)'}"
                    ),
                ),
            )
        ]


class VerboseErrorProbe:
    """Does an error response hand back the framework's internals?"""

    id = "api.misconfig.verbose_errors"
    version = "1.0.0"
    name = "Verbose error responses"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        operation = _first_parameterized_readable(target) or _first_readable(target)
        if operation is None:
            return []

        # A type-confused path segment is the least invasive way to make a
        # well-built API return a handled 4xx and a fragile one return its
        # stack trace — so this probe wants an operation that *has* a path
        # parameter, unlike the header checks, which want the simplest one.
        url = operation_url(target.base_url, operation, value="kervy-probe'\"<>")
        observation = await try_send(ctx, transport, method=operation.method, url=url)
        if observation is None:
            return []

        marker = _verbose_marker(observation)
        if marker is None:
            return []

        surface = surface_label(operation)
        return [
            ScanResult(
                id="KERVY-API-012",
                title="Error responses expose internal details",
                category=Category.API_SECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                endpoint=surface,
                description=(
                    "A malformed request produced a response containing framework "
                    f"internals (matched {marker!r}) rather than a handled error."
                ),
                evidence=clip(
                    f"{operation.method} {url} -> HTTP {observation.status_code}\n"
                    f"{body_text(observation)}"
                ),
                impact=(
                    "Stack traces name internal paths, library versions and query "
                    "shapes, which is the reconnaissance an attacker would otherwise "
                    "have to guess at."
                ),
                remediation=(
                    "Turn off debug mode in this environment and return a generic error "
                    "body with a correlation id, keeping the detail in server-side logs."
                ),
                probe_id=self.id,
                probe_version=self.version,
                frameworks=("OWASP-API-2023:API8", "CWE-209"),
                reproduction=(
                    f"Send {operation.method} {url}.",
                    f"Observe HTTP {observation.status_code} with {marker!r} in the body.",
                ),
                # Here the body is the finding — a stack trace is the thing
                # being reported — so it is retained, redacted.
                evidence_bundle=evidence_of(
                    observation,
                    probe_id=self.id,
                    probe_version=self.version,
                    verdict=f"framework internals matched {marker!r}",
                    include_body=True,
                ),
            )
        ]


class DebugEndpointProbe:
    """Are operational endpoints left reachable alongside the API?"""

    id = "api.misconfig.debug_endpoints"
    version = "1.0.0"
    name = "Exposed debug and introspection endpoints"

    def applies_to(self, target: ProbeTarget) -> bool:
        return True

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        from urllib.parse import urljoin

        results: list[ScanResult] = []
        base = target.base_url if target.base_url.endswith("/") else target.base_url + "/"

        for path in _DEBUG_PATHS:
            if ctx.halted:
                break
            url = urljoin(base, path.lstrip("/"))
            observation = await try_send(ctx, transport, method="GET", url=url)
            if observation is None or not 200 <= observation.status_code < 300:
                continue

            results.append(
                ScanResult(
                    id="KERVY-API-013",
                    title=f"Debug endpoint {path} is reachable",
                    category=Category.API_SECURITY,
                    severity=Severity.HIGH if path == "/.env" else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    endpoint=f"GET {path}",
                    description=(
                        f"{path} answered a request with HTTP {observation.status_code}. "
                        "Endpoints of this kind expose configuration, environment or "
                        "runtime internals and are not meant to be reachable by API "
                        "clients."
                    ),
                    evidence=clip(
                        f"GET {url} -> HTTP {observation.status_code}, "
                        f"{len(observation.body)} byte body"
                    ),
                    impact=(
                        "Configuration and environment endpoints frequently contain "
                        "credentials outright; runtime ones map internal structure."
                    ),
                    remediation=(
                        "Do not route these paths from the public listener; bind them to "
                        "an internal interface or require an operator credential."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API8", "OWASP-API-2023:API9", "CWE-497"),
                    reproduction=(
                        f"Send GET {url}.",
                        f"Observe HTTP {observation.status_code} rather than 404.",
                    ),
                    # No body, deliberately. A reachable /.env often contains
                    # credentials outright; that it answered at all is the
                    # finding, and copying its contents into the evidence
                    # store would spread the exposure rather than record it.
                    evidence_bundle=evidence_of(
                        observation,
                        probe_id=self.id,
                        probe_version=self.version,
                        verdict=(
                            f"{path} answered HTTP {observation.status_code} with "
                            f"{len(observation.body)} bytes"
                        ),
                    ),
                )
            )
        return results


def _first_readable(target: ProbeTarget) -> DiscoveredOperation | None:
    """A GET the run may safely repeat, preferring one without path params."""
    candidates = [op for op in target.operations if op.method == "GET"]
    if not candidates:
        return None
    return min(candidates, key=lambda op: (op.path.count("{"), len(op.path)))


def _first_parameterized_readable(target: ProbeTarget) -> DiscoveredOperation | None:
    """A GET that takes a path parameter, which is where a malformed value
    can actually reach a handler."""
    candidates = [op for op in target.operations if op.method == "GET" and "{" in op.path]
    if not candidates:
        return None
    return min(candidates, key=lambda op: (op.path.count("{"), len(op.path)))


def _verbose_marker(observation: Observation) -> str | None:
    lowered = body_text(observation).lower()
    for marker in _VERBOSE_ERROR_MARKERS:
        if marker in lowered:
            return marker
    return None
