"""Authentication probes — OWASP API2:2023 (docs/BUILD_SPEC.md §10).

The live check is deliberately narrow: send the operation the spec says
requires authentication, with no credentials, and see whether the target
answers it anyway. A 2xx is the whole finding — the probe does not read,
keep or report what came back beyond its shape, because the point is the
authorization *decision*, not the data behind it.
"""

from urllib.parse import urlsplit

from app.core.probes.api._support import (
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
from app.core.scope.transport import GatedTransport

# Parameter names that carry key material. Anything in this set appearing in
# a URL (query or path) puts secrets into proxy logs, browser history,
# Referer headers and analytics — API2/API8, and CWE-598.
_SECRET_PARAM_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "access_token",
        "auth",
        "auth_token",
        "authorization",
        "id_token",
        "key",
        "password",
        "pwd",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "sessionid",
        "signature",
        "token",
    }
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class UnauthenticatedAccessProbe:
    """Does an endpoint the spec marks as authenticated answer without one?"""

    id = "api.auth.unauthenticated_access"
    version = "1.0.0"
    name = "Unauthenticated access to authenticated endpoints"

    def applies_to(self, target: ProbeTarget) -> bool:
        return any(operation.requires_auth for operation in target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        tested = 0

        for operation in target.operations:
            if not operation.requires_auth:
                continue
            # Under safe mode only read-shaped methods are exercised: proving
            # that DELETE is unauthenticated by actually deleting something
            # is not a trade this tool makes.
            if target.safe_mode and operation.method not in _SAFE_METHODS:
                continue
            if ctx.halted:
                break

            url = operation_url(target.base_url, operation)
            observation = await try_send(ctx, transport, method=operation.method, url=url)
            if observation is None:
                continue
            tested += 1

            if 200 <= observation.status_code < 300:
                surface = surface_label(operation)
                results.append(
                    ScanResult(
                        id="KERVY-API-001",
                        title="Authenticated endpoint answers unauthenticated requests",
                        category=Category.API_SECURITY,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        endpoint=surface,
                        description=(
                            f"The specification marks {surface} as requiring "
                            f"{', '.join(operation.security_schemes) or 'authentication'}, "
                            "but the endpoint returned a success response to a request "
                            "carrying no credentials at all."
                        ),
                        evidence=clip(
                            f"{operation.method} {url} with no Authorization header "
                            f"-> HTTP {observation.status_code}, "
                            f"{len(observation.body)} byte body"
                        ),
                        impact=(
                            "Anyone who can reach this endpoint gets whatever it exposes, "
                            "without an account. Access control that exists only in the "
                            "specification is not access control."
                        ),
                        remediation=(
                            "Enforce the declared security scheme in the handler or a "
                            "middleware that runs before it, and deny by default so a "
                            "route added later is protected unless it opts out."
                        ),
                        probe_id=self.id,
                        probe_version=self.version,
                        frameworks=("OWASP-API-2023:API2", "CWE-306"),
                        reproduction=(
                            f"Send {operation.method} {url} with no Authorization header.",
                            f"Observe HTTP {observation.status_code} instead of 401 or 403.",
                        ),
                        evidence_bundle=evidence_of(
                            observation,
                            probe_id=self.id,
                            probe_version=self.version,
                            verdict=(
                                f"HTTP {observation.status_code} to a request carrying "
                                "no credentials"
                            ),
                        ),
                    )
                )

        if tested == 0 and self.applies_to(target):
            results.append(
                untested(
                    probe_id=self.id,
                    probe_version=self.version,
                    endpoint=target.base_url,
                    what="Unauthenticated access to authenticated endpoints",
                    reason=(
                        "No authenticated endpoint could be requested: every candidate was "
                        "refused by scope, unreachable, or a write method held back by "
                        "safe mode."
                    ),
                )
            )
        return results


class TransportSecurityProbe:
    """Is the target reached over plaintext HTTP?"""

    id = "api.auth.transport_security"
    version = "1.0.0"
    name = "Transport security"

    def applies_to(self, target: ProbeTarget) -> bool:
        return True

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        # Read from configuration, not from a request: whether the operator
        # reaches this target over plaintext is already established by the
        # base URL, and spending a request to re-learn it would be waste.
        scheme = urlsplit(target.base_url).scheme.lower()
        if scheme != "http":
            return []

        return [
            ScanResult(
                id="KERVY-API-002",
                title="API is served over plaintext HTTP",
                category=Category.API_SECURITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                endpoint=target.base_url,
                description=(
                    "The target's base URL uses http://, so credentials, tokens and "
                    "response data cross the network unencrypted and unauthenticated."
                ),
                evidence=f"base_url = {target.base_url}",
                impact=(
                    "Anyone on the path can read every request and response and modify "
                    "them in flight, including swapping an authorization decision."
                ),
                remediation=(
                    "Serve the API over TLS only, redirect http:// to https://, and send "
                    "Strict-Transport-Security so clients refuse to downgrade."
                ),
                probe_id=self.id,
                probe_version=self.version,
                frameworks=("OWASP-API-2023:API2", "OWASP-API-2023:API8", "CWE-319"),
                reproduction=(
                    f"Note the configured base URL {target.base_url}.",
                    "Observe that it is http:// rather than https://.",
                ),
            )
        ]


class KeyMaterialInUrlProbe:
    """Does the surface carry secrets in the URL rather than a header?"""

    id = "api.auth.key_material_in_url"
    version = "1.0.0"
    name = "Key material in URLs"

    def applies_to(self, target: ProbeTarget) -> bool:
        return bool(target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        results: list[ScanResult] = []

        for operation in target.operations:
            offenders = sorted(
                {
                    parameter.name
                    for parameter in operation.parameters
                    if parameter.location in ("query", "path")
                    and parameter.name.strip().lower().replace("-", "_") in _SECRET_PARAM_NAMES
                }
            )
            if not offenders:
                continue

            surface = surface_label(operation)
            results.append(
                ScanResult(
                    id="KERVY-API-003",
                    title="Credentials are passed in the URL",
                    category=Category.API_SECURITY,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint=surface,
                    description=(
                        f"{surface} accepts {', '.join(offenders)} in the URL. URLs are "
                        "logged by proxies and servers, kept in browser history, and sent "
                        "on in Referer headers, so a secret placed there outlives the "
                        "request."
                    ),
                    evidence=f"Specification declares URL parameter(s): {', '.join(offenders)}",
                    impact=(
                        "Key material ends up in places that are not treated as secret "
                        "stores and are often retained far longer than the credential's "
                        "own lifetime."
                    ),
                    remediation=(
                        "Move the credential into an Authorization header or a cookie, "
                        "reject the URL form, and rotate any key that has already been "
                        "sent this way."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API2", "CWE-598"),
                    reproduction=(
                        f"Read the specification entry for {surface}.",
                        f"Observe the parameter(s) {', '.join(offenders)} declared in the URL.",
                    ),
                )
            )
        return results
