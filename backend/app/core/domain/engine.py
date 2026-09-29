"""The domain/DNS engine: subdomain discovery, then TLS/header checks against
whichever discovered hosts the RoE's `asset_scope` actually authorizes
probing.

Subdomain enumeration (certificate-transparency logs + a small DNS
brute-force wordlist) deliberately does not expand what gets *tested* —
every discovered hostname is recorded as a `DiscoveredSubdomain`, but only
the root domain and hosts matching `DomainTarget.allowed_subdomain_patterns`
are handed to the HTTP/TLS checks below. An empty pattern list means "only
the root domain itself," never "everything found" — the same fail-closed
reading `resolve_domain_scope` already documents for an unstated boundary.
"""

from __future__ import annotations

import fnmatch

from app.core.domain.brute_force import brute_force_subdomains
from app.core.domain.certificate_transparency import query_certificate_transparency
from app.core.domain.contract import DiscoveredSubdomain, DomainTarget, SubdomainSource
from app.core.domain.tls_probe import TlsCertificateInfo, TlsProbeError, probe_tls_certificate
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.dns import DnsResolver, SystemDnsResolver
from app.core.scope.transport import GatedTransport, ScopeBlockedError

ENGINE_ID = "domain.engine"
ENGINE_VERSION = "1.0.0"

_SECURITY_HEADERS = (
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
)

# Simple ordinal comparison over the fixed set of strings Python's `ssl`
# module returns from `SSLSocket.version()` ("SSLv3", "TLSv1", "TLSv1.1",
# "TLSv1.2", "TLSv1.3") — a shorter prefix such as "TLSv1" sorts below
# "TLSv1.2" the same way "TLSv1.1" does, which is the ordering that matters.
_MIN_TLS_VERSION = "TLSv1.2"
_EXPIRY_WARNING_DAYS = 30


class DomainEngine:
    def __init__(
        self,
        *,
        transport: GatedTransport | None = None,
        dns_resolver: DnsResolver | None = None,
    ) -> None:
        self._transport = transport or GatedTransport()
        self._dns_resolver = dns_resolver or SystemDnsResolver()

    async def run(
        self, ctx: RunContext, target: DomainTarget
    ) -> tuple[list[ScanResult], list[DiscoveredSubdomain]]:
        findings: list[ScanResult] = []
        discovered: dict[str, DiscoveredSubdomain] = {}

        try:
            root_ips = tuple(str(ip) for ip in await self._dns_resolver.resolve(target.root_domain))
        except Exception:  # noqa: BLE001 - an unresolvable root domain is a normal outcome
            root_ips = ()
        discovered[target.root_domain] = DiscoveredSubdomain(
            hostname=target.root_domain,
            source=SubdomainSource.SEED,
            resolved_ips=root_ips,
            probed=True,
        )

        ct_hostnames, ct_skip_reason = await query_certificate_transparency(
            ctx, self._transport, target.root_domain
        )
        brute_forced = await brute_force_subdomains(self._dns_resolver, target.root_domain)

        for hostname in sorted(ct_hostnames | set(brute_forced)):
            if hostname == target.root_domain:
                continue
            source = (
                SubdomainSource.DNS_BRUTE_FORCE
                if hostname in brute_forced
                else SubdomainSource.CERTIFICATE_TRANSPARENCY
            )
            discovered[hostname] = DiscoveredSubdomain(
                hostname=hostname,
                source=source,
                resolved_ips=brute_forced.get(hostname, ()),
                probed=_matches_any_pattern(hostname, target.allowed_subdomain_patterns),
            )

        non_root = [item for item in discovered.values() if item.hostname != target.root_domain]
        if non_root:
            findings.append(_subdomain_discovery_finding(target.root_domain, non_root))
        if ct_skip_reason is not None:
            findings.append(_coverage_marker("certificate-transparency lookup", ct_skip_reason))

        for hostname in sorted(item.hostname for item in discovered.values() if item.probed):
            findings.extend(await self._check_host(ctx, hostname))

        return findings, list(discovered.values())

    async def _check_host(self, ctx: RunContext, hostname: str) -> list[ScanResult]:
        results: list[ScanResult] = []
        url = f"https://{hostname}/"
        try:
            observation = await self._transport.send(
                ctx, method="GET", url=url, timeout_seconds=15.0
            )
        except ScopeBlockedError as exc:
            return [_coverage_marker(hostname, f"refused by scope: {exc.decision.reason}")]
        except Exception as exc:  # noqa: BLE001 - an unreachable host is a result, not a crash
            return [_coverage_marker(hostname, f"request failed: {exc}")]

        header_names = {name.lower() for name in observation.headers}
        missing = [name for name in _SECURITY_HEADERS if name not in header_names]
        if missing:
            results.append(_missing_headers_finding(hostname, missing))

        try:
            cert = await probe_tls_certificate(ctx, self._dns_resolver, hostname)
        except TlsProbeError as exc:
            results.append(
                _coverage_marker(hostname, f"TLS certificate could not be inspected: {exc}")
            )
        else:
            tls_finding = _tls_finding(hostname, cert)
            if tls_finding is not None:
                results.append(tls_finding)

        return results


def _matches_any_pattern(hostname: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(hostname, pattern) for pattern in patterns)


def _subdomain_discovery_finding(root_domain: str, items: list[DiscoveredSubdomain]) -> ScanResult:
    ordered = sorted(items, key=lambda item: item.hostname)
    listed = "\n".join(f"{item.hostname}  ({item.source.value})" for item in ordered[:50])
    return ScanResult(
        id="KERVY-DOMAIN-001",
        title=f"{len(items)} subdomain(s) discovered for {root_domain}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.HIGH,
        endpoint="domain/discovery",
        description=(
            "These hostnames were found via certificate-transparency logs and a "
            "built-in DNS wordlist. Discovery never expands what this run tests: only "
            "the root domain and hosts matching asset_scope.allowed_subdomain_patterns "
            "receive the HTTP/TLS checks below."
        ),
        evidence=listed,
        impact="None from this scan — discovery makes no request to these hosts.",
        remediation=(
            "Review the list for anything unexpected. To test one further, add a "
            "matching pattern to asset_scope.allowed_subdomain_patterns, or promote it "
            "to its own authorized target."
        ),
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )


def _coverage_marker(surface: str, reason: str) -> ScanResult:
    return ScanResult(
        id="KERVY-DOMAIN-009",
        title=f"Not tested: {surface}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=f"domain/{surface}",
        description=f"{reason}. This assessment says nothing about {surface}.",
        evidence=reason,
        impact="Unknown — not tested.",
        remediation="Re-run once reachable, or confirm the gap is expected.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )


def _missing_headers_finding(hostname: str, missing: list[str]) -> ScanResult:
    return ScanResult(
        id="KERVY-DOMAIN-002",
        title=f"{hostname} is missing {len(missing)} security header(s)",
        category=Category.INFRASTRUCTURE,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        endpoint=f"domain/{hostname}",
        description=(
            "The response to a plain GET did not include the following security "
            "headers, which harden a browser's handling of the response: " + ", ".join(missing)
        ),
        evidence=", ".join(missing),
        impact=(
            "Missing headers weaken browser-side defense in depth for this host — "
            "e.g. clickjacking (X-Frame-Options), MIME-sniffing "
            "(X-Content-Type-Options), or downgrade attacks (HSTS)."
        ),
        remediation=f"Configure {hostname} to send the missing header(s) listed above.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
        reproduction=(f"GET https://{hostname}/",),
    )


def _tls_finding(hostname: str, cert: TlsCertificateInfo) -> ScanResult | None:
    problems: list[str] = []
    severity = Severity.LOW

    if cert.is_expired:
        problems.append(f"certificate expired {-cert.days_until_expiry} day(s) ago")
        severity = Severity.HIGH
    elif cert.days_until_expiry <= _EXPIRY_WARNING_DAYS:
        problems.append(f"certificate expires in {cert.days_until_expiry} day(s)")
        severity = Severity.MEDIUM

    if cert.protocol_version is not None and cert.protocol_version < _MIN_TLS_VERSION:
        problems.append(f"negotiated {cert.protocol_version}, below the {_MIN_TLS_VERSION} minimum")
        severity = Severity.HIGH

    if not problems:
        return None

    return ScanResult(
        id="KERVY-DOMAIN-003",
        title=f"{hostname} has a TLS configuration issue",
        category=Category.INFRASTRUCTURE,
        severity=severity,
        confidence=Confidence.HIGH,
        endpoint=f"domain/{hostname}",
        description="; ".join(problems),
        evidence=(
            f"subject={cert.subject_common_name}, not_after={cert.not_after.isoformat()}, "
            f"protocol={cert.protocol_version}, cipher={cert.cipher_name}"
        ),
        impact="A weak or expiring certificate degrades transport security for this host.",
        remediation="Renew the certificate and/or disable protocol versions below TLS 1.2.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )
