"""Authentication probes — OWASP API2:2023 (docs/BUILD_SPEC.md §10).

The live check is deliberately narrow: send the operation the spec says
requires authentication, with no credentials, and see whether the target
answers it anyway. A 2xx is the whole finding — the probe does not read,
keep or report what came back beyond its shape, because the point is the
authorization *decision*, not the data behind it.
"""

import base64
import json
import re
from urllib.parse import urlsplit

import jwt

from app.core.discovery.openapi import DiscoveredOperation
from app.core.probes.api._support import (
    clip,
    evidence_of,
    operation_url,
    surface_label,
    try_send,
    untested,
)
from app.core.probes.credentials import SyntheticAccount
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


# A JWT's three dot-separated segments are each base64url, which never
# contains `.` — so this cannot false-match across segment boundaries the
# way a looser "contains a dot" check could.
_JWT_SHAPE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unsigned_token(header: dict[str, object], payload: dict[str, object]) -> str:
    """A syntactically valid, *unsigned* JWT, built only from `header` and
    `payload` — never from a signing secret, which this probe never has and
    never needs: a JWT's header and payload are base64, not encrypted, so
    anyone holding a real token can already read both without the key.
    """
    head = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{head}.{body}."


class JwtSignatureBypassProbe:
    """Does the target accept a JWT whose signature was never checked?

    OWASP API2:2023, CWE-347. Three forged variants, each built only from a
    real token's own header and payload — decoded with `verify_signature:
    False`, which needs no key at all: `alg: "none"`; a case-mutated
    `"None"`/`"NONE"` (a classic library bug — some JWT libraries compared
    the algorithm case-insensitively); and the original header, unmodified,
    with the signature segment stripped to empty. If a forged request gets
    the same success a real, signed token already got, the server is not
    actually verifying signatures — it is mistaking the *presence* of a
    token for a *valid* one.
    """

    id = "api.auth.jwt_signature_bypass"
    version = "1.0.0"
    name = "JWT signature is not verified"

    def applies_to(self, target: ProbeTarget) -> bool:
        return any(operation.requires_auth for operation in target.operations)

    async def run(
        self, target: ProbeTarget, ctx: RunContext, transport: GatedTransport
    ) -> list[ScanResult]:
        plan = target.authorization
        usable = plan.usable()
        if not usable:
            return [self._untested(target, "no authorized synthetic account was resolvable")]

        account = usable[0]
        header_value = plan.credentials.headers_for(account).get(account.header_name, "")
        match = _JWT_SHAPE.search(header_value)
        if match is None:
            return [
                self._untested(
                    target,
                    f"account {account.label!r}'s credential is not shaped like a JWT "
                    "(three dot-separated segments) — this check applies only to "
                    "bearer tokens that are",
                )
            ]

        try:
            header = jwt.get_unverified_header(match.group(0))
            payload = jwt.decode(match.group(0), options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            return [self._untested(target, f"the account's token could not be decoded: {exc}")]

        variants: tuple[tuple[str, str], ...] = (
            ('alg: "none"', _unsigned_token({**header, "alg": "none"}, payload)),
            ('alg: "None" (case)', _unsigned_token({**header, "alg": "None"}, payload)),
            ("original header, signature stripped", _unsigned_token(header, payload)),
        )

        results: list[ScanResult] = []
        tested = 0
        for operation in target.operations:
            if not operation.requires_auth:
                continue
            if target.safe_mode and operation.method not in _SAFE_METHODS:
                continue
            if ctx.halted:
                break

            url = operation_url(target.base_url, operation)
            control = await try_send(
                ctx,
                transport,
                method=operation.method,
                url=url,
                headers=plan.credentials.headers_for(account),
            )
            # No control, no conclusion — the same "a 404 here would prove
            # nothing" reasoning the BOLA probe already applies.
            if control is None or not 200 <= control.status_code < 300:
                continue
            tested += 1

            bypassed = await self._try_forgeries(
                ctx, transport, account, operation, url, variants, control.status_code
            )
            if bypassed is not None:
                results.append(bypassed)
                # One confirmed bypass means the authentication layer itself
                # does not check signatures — that is a property of the
                # middleware, not of this one route, so there is nothing
                # left to learn by forging against every other operation.
                break

        if tested == 0 and not results:
            results.append(
                self._untested(
                    target,
                    "no authenticated operation returned a success with the real "
                    "credential, so there is no control to compare a forged token "
                    "against",
                )
            )
        return results

    async def _try_forgeries(
        self,
        ctx: RunContext,
        transport: GatedTransport,
        account: SyntheticAccount,
        operation: DiscoveredOperation,
        url: str,
        variants: tuple[tuple[str, str], ...],
        control_status: int,
    ) -> ScanResult | None:
        for label, forged_token in variants:
            attempt = await try_send(
                ctx,
                transport,
                method=operation.method,
                url=url,
                headers=account.header_for(forged_token),
            )
            if attempt is not None and 200 <= attempt.status_code < 300:
                surface = surface_label(operation)
                return ScanResult(
                    id="KERVY-API-004",
                    title="Endpoint accepts a JWT with an unverified signature",
                    category=Category.API_SECURITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    endpoint=surface,
                    description=(
                        f"{surface} returned the same success for a forged token "
                        f"({label}) that it gave the real, signed one. The server is "
                        "not verifying the JWT's signature, so anyone who can read a "
                        "token's own header and payload — never encrypted, only "
                        "base64-encoded — can forge whatever claims they want."
                    ),
                    evidence=clip(
                        f"{operation.method} {url} with a forged token ({label}) "
                        f"-> HTTP {attempt.status_code}, matching the real token's "
                        f"HTTP {control_status}"
                    ),
                    impact=(
                        "Signature verification is the entire reason a JWT can be "
                        "trusted without a database round trip per request. Without "
                        "it, anyone can mint a token claiming to be any user, any "
                        "role or any scope, by editing plain base64-decoded JSON."
                    ),
                    remediation=(
                        "Verify the signature on every request, using a fixed, "
                        "server-chosen algorithm and key — never one read from the "
                        "token's own `alg` or `kid` header — and reject a token "
                        "whose signature segment is missing or empty."
                    ),
                    probe_id=self.id,
                    probe_version=self.version,
                    frameworks=("OWASP-API-2023:API2", "CWE-347"),
                    reproduction=(
                        "Decode the account's own token's header and payload "
                        "(no secret needed — both are base64, not encrypted).",
                        f"Forge a new token ({label}) from that header and payload.",
                        f"Send {operation.method} {url} with the forged token.",
                        f"Observe HTTP {attempt.status_code}, matching the real "
                        f"token's success.",
                    ),
                    evidence_bundle=evidence_of(
                        attempt,
                        probe_id=self.id,
                        probe_version=self.version,
                        verdict=(
                            f"HTTP {attempt.status_code} to a forged token ({label}), "
                            f"matching the real token's HTTP {control_status}"
                        ),
                    ),
                )
        return None

    def _untested(self, target: ProbeTarget, reason: str) -> ScanResult:
        return untested(
            probe_id=self.id,
            probe_version=self.version,
            endpoint=target.base_url,
            what="JWT signature verification",
            reason=reason[0].upper() + reason[1:] + ".",
        )
