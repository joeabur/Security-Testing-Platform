"""The domain/DNS engine (pentest module Phase 2).

Mirrors `tests/test_dast.py`'s style: pure in-memory fakes for the resolver
and transport, no real DNS or HTTP. The behaviour under test is the same
"discovery never expands what gets tested" boundary DAST enforces for
crawled links, applied here to subdomains found via certificate-transparency
logs and a DNS wordlist — only the root domain and hosts matching
`allowed_subdomain_patterns` may receive the HTTP/TLS checks.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.brute_force import brute_force_subdomains
from app.core.domain.certificate_transparency import query_certificate_transparency
from app.core.domain.contract import DiscoveredSubdomain, DomainTarget, SubdomainSource
from app.core.domain.engine import DomainEngine
from app.core.domain.service import promote_discovered_subdomains
from app.core.domain.tls_probe import TlsCertificateInfo, TlsProbeError, probe_tls_certificate
from app.core.orchestrator.domain_check import DomainCheck
from app.core.probes.models import Severity
from app.core.scope.models import ScopeDecision
from app.core.scope.transport import Observation, ScopeBlockedError
from app.models.discovered_asset import AssetKind, DiscoveredAsset
from app.models.organization import Organization
from app.models.target import Target, TargetEnvironment, TargetKind
from tests.security.conftest import FakeDnsResolver, make_context

ROOT = "example.test"
CRT_SH_URL = f"https://crt.sh/?q={quote('%.' + ROOT)}&output=json"


class FakeTransport:
    """Serves fixed responses by exact URL and records every request made."""

    def __init__(
        self,
        responses: dict[str, tuple[int, dict[str, str], bytes]],
        *,
        blocked: frozenset[str] = frozenset(),
    ) -> None:
        self._responses = responses
        self._blocked = blocked
        self.requested: list[str] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        url = str(kwargs.get("url"))
        self.requested.append(url)
        if any(fragment in url for fragment in self._blocked):
            raise ScopeBlockedError(
                ScopeDecision(
                    allowed=False, rule="domain_not_allowlisted", reason="blocked in test"
                )
            )
        if url not in self._responses:
            raise RuntimeError(f"unexpected url in test: {url}")
        status, headers, body = self._responses[url]
        return Observation(
            method="GET", url=url, status_code=status, headers=headers, elapsed_ms=1.0, body=body
        )


_ALL_SECURITY_HEADERS = {
    "content-type": "text/html",
    "strict-transport-security": "max-age=63072000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'",
}


# --- certificate_transparency.query_certificate_transparency ---------------


async def test_ct_query_parses_name_value_and_filters_to_the_root_domain() -> None:
    body = (
        b'[{"name_value": "sub1.example.test\\nsub2.example.test"}, '
        b'{"name_value": "*.example.test"}, '
        b'{"name_value": "evil.other.test"}]'
    )
    transport = FakeTransport({CRT_SH_URL: (200, {}, body)})
    hostnames, skip_reason = await query_certificate_transparency(
        make_context(),
        transport,
        ROOT,  # type: ignore[arg-type]
    )

    assert hostnames == {"sub1.example.test", "sub2.example.test"}
    assert skip_reason is None


async def test_ct_query_is_skipped_not_raised_when_scope_refuses_it() -> None:
    transport = FakeTransport({}, blocked=frozenset({"crt.sh"}))
    hostnames, skip_reason = await query_certificate_transparency(
        make_context(),
        transport,
        ROOT,  # type: ignore[arg-type]
    )

    assert hostnames == set()
    assert skip_reason is not None
    assert "refused" in skip_reason


async def test_ct_query_is_skipped_not_raised_on_a_non_200_response() -> None:
    transport = FakeTransport({CRT_SH_URL: (503, {}, b"")})
    hostnames, skip_reason = await query_certificate_transparency(
        make_context(),
        transport,
        ROOT,  # type: ignore[arg-type]
    )

    assert hostnames == set()
    assert skip_reason == "crt.sh responded with 503"


# --- brute_force.brute_force_subdomains -------------------------------------


async def test_brute_force_only_returns_hostnames_that_actually_resolve() -> None:
    resolver = FakeDnsResolver({"www.example.test": ["203.0.113.20"]})
    found = await brute_force_subdomains(resolver, ROOT)  # type: ignore[arg-type]

    assert found == {"www.example.test": ("203.0.113.20",)}


# --- tls_probe.probe_tls_certificate (real logic, no network) --------------


def test_tls_certificate_info_expiry_properties() -> None:
    expired = TlsCertificateInfo(
        subject_common_name="x",
        not_after=datetime.now(UTC) - timedelta(days=5),
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_128_GCM_SHA256",
    )
    assert expired.is_expired

    valid = TlsCertificateInfo(
        subject_common_name="x",
        not_after=datetime.now(UTC) + timedelta(days=90),
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_128_GCM_SHA256",
    )
    assert not valid.is_expired
    assert valid.days_until_expiry >= 89


async def test_tls_probe_fails_closed_when_the_host_does_not_resolve() -> None:
    with pytest.raises(TlsProbeError, match="could not be resolved"):
        await probe_tls_certificate(
            make_context(),
            FakeDnsResolver({}),  # type: ignore[arg-type]
            "missing.example.test",
        )


async def test_tls_probe_fails_closed_on_a_blocked_resolved_address() -> None:
    resolver = FakeDnsResolver({"internal.example.test": ["127.0.0.1"]})
    with pytest.raises(TlsProbeError, match="blocked address"):
        await probe_tls_certificate(
            make_context(),
            resolver,
            "internal.example.test",  # type: ignore[arg-type]
        )


# --- DomainEngine.run --------------------------------------------------------


def _engine(
    transport: FakeTransport,
    resolver: FakeDnsResolver,
    monkeypatch: pytest.MonkeyPatch,
    certs: dict[str, TlsCertificateInfo],
) -> DomainEngine:
    async def fake_probe_tls_certificate(
        ctx: object, dns_resolver: object, hostname: str, **kwargs: object
    ) -> TlsCertificateInfo:
        if hostname not in certs:
            raise TlsProbeError(f"no fake certificate configured for {hostname}")
        return certs[hostname]

    monkeypatch.setattr("app.core.domain.engine.probe_tls_certificate", fake_probe_tls_certificate)
    return DomainEngine(transport=transport, dns_resolver=resolver)  # type: ignore[arg-type]


async def test_engine_discovers_subdomains_but_only_probes_allowed_patterns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ct_body = b'[{"name_value": "www.example.test"}, {"name_value": "hidden.example.test"}]'
    transport = FakeTransport(
        {
            CRT_SH_URL: (200, {}, ct_body),
            f"https://{ROOT}/": (200, {"content-type": "text/html"}, b"root"),
            "https://www.example.test/": (200, dict(_ALL_SECURITY_HEADERS), b"www"),
        }
    )
    resolver = FakeDnsResolver({ROOT: ["203.0.113.5"], "www.example.test": ["203.0.113.20"]})
    certs = {
        ROOT: TlsCertificateInfo(
            subject_common_name=ROOT,
            not_after=datetime.now(UTC) - timedelta(days=1),
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_128_GCM_SHA256",
        ),
        "www.example.test": TlsCertificateInfo(
            subject_common_name="www.example.test",
            not_after=datetime.now(UTC) + timedelta(days=180),
            protocol_version="TLSv1.3",
            cipher_name="TLS_AES_128_GCM_SHA256",
        ),
    }
    engine = _engine(transport, resolver, monkeypatch, certs)
    target = DomainTarget(root_domain=ROOT, allowed_subdomain_patterns=("www.example.test",))

    findings, discovered = await engine.run(make_context(), target)

    by_hostname = {item.hostname: item for item in discovered}
    assert set(by_hostname) == {ROOT, "www.example.test", "hidden.example.test"}
    assert by_hostname[ROOT].probed is True
    assert by_hostname["www.example.test"].probed is True
    # Discovered, but does not match allowed_subdomain_patterns — never probed.
    assert by_hostname["hidden.example.test"].probed is False
    assert "https://hidden.example.test/" not in transport.requested

    finding_ids = [item.id for item in findings]
    assert "AEGIS-DOMAIN-001" in finding_ids  # discovery
    discovery = next(item for item in findings if item.id == "AEGIS-DOMAIN-001")
    assert "hidden.example.test" in discovery.evidence
    assert "www.example.test" in discovery.evidence
    assert discovery.severity is Severity.INFORMATIONAL

    # example.test: missing every security header.
    missing_headers = [
        item
        for item in findings
        if item.id == "AEGIS-DOMAIN-002" and item.endpoint == f"domain/{ROOT}"
    ]
    assert len(missing_headers) == 1
    assert missing_headers[0].severity is Severity.LOW

    # www.example.test sent every header — no finding for it.
    assert not [
        item
        for item in findings
        if item.id == "AEGIS-DOMAIN-002" and item.endpoint == "domain/www.example.test"
    ]

    # example.test: expired certificate -> HIGH. www: fine -> no finding.
    tls_findings = {item.endpoint: item for item in findings if item.id == "AEGIS-DOMAIN-003"}
    assert tls_findings[f"domain/{ROOT}"].severity is Severity.HIGH
    assert "domain/www.example.test" not in tls_findings


async def test_engine_records_a_coverage_marker_for_a_scope_blocked_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeTransport(
        {CRT_SH_URL: (200, {}, b"[]")},
        blocked=frozenset({ROOT}),
    )
    resolver = FakeDnsResolver({ROOT: ["203.0.113.5"]})
    engine = _engine(transport, resolver, monkeypatch, {})
    target = DomainTarget(root_domain=ROOT)

    findings, discovered = await engine.run(make_context(), target)

    assert discovered == [
        DiscoveredSubdomain(
            hostname=ROOT, source=SubdomainSource.SEED, resolved_ips=("203.0.113.5",), probed=True
        )
    ]
    markers = [item for item in findings if item.id == "AEGIS-DOMAIN-009"]
    assert any("refused by scope" in item.evidence for item in markers)


# --- DomainCheck --------------------------------------------------------


async def test_domain_check_reports_an_engine_failure_without_losing_the_run() -> None:
    class _ExplodingEngine:
        async def run(self, ctx: object, target: object) -> tuple[list[object], list[object]]:
            raise RuntimeError("boom")

    check = DomainCheck(target=DomainTarget(root_domain=ROOT), engine=_ExplodingEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert len(results) == 1
    assert results[0].ok is False
    assert check.scan_results[0].id == "AEGIS-DOMAIN-099"


async def test_domain_check_summarizes_findings_and_discoveries() -> None:
    class _StubEngine:
        async def run(self, ctx: object, target: object) -> tuple[list[object], list[object]]:
            return (
                [],
                [DiscoveredSubdomain(hostname=ROOT, source=SubdomainSource.SEED, probed=True)],
            )

    check = DomainCheck(target=DomainTarget(root_domain=ROOT), engine=_StubEngine())  # type: ignore[arg-type]
    results = await check.run(make_context(), transport=object())  # type: ignore[arg-type]

    assert results[0].ok is True
    assert "1 host(s) discovered" in results[0].detail
    assert check.discovered[0].hostname == ROOT


# --- service.promote_discovered_subdomains (DB-backed) ----------------------


async def test_promote_discovered_subdomains_upserts_on_rerun(db_session: AsyncSession) -> None:
    org = Organization(name="Domain Test Org", slug=f"domain-test-org-{uuid.uuid4().hex[:8]}")
    db_session.add(org)
    await db_session.flush()
    target = Target(
        organization_id=org.id,
        name="example.test",
        environment=TargetEnvironment.STAGING,
        kind=TargetKind.DOMAIN,
        base_url=ROOT,
    )
    db_session.add(target)
    await db_session.flush()

    subdomain = DiscoveredSubdomain(
        hostname="www.example.test",
        source=SubdomainSource.DNS_BRUTE_FORCE,
        resolved_ips=("203.0.113.20",),
        probed=True,
    )

    first = await promote_discovered_subdomains(
        db_session, organization_id=org.id, parent_target_id=target.id, subdomains=[subdomain]
    )
    await db_session.commit()
    assert len(first) == 1
    assert first[0].identifier == "www.example.test"
    assert first[0].asset_kind is AssetKind.SUBDOMAIN
    assert first[0].asset_metadata["probed"] is True

    second = await promote_discovered_subdomains(
        db_session, organization_id=org.id, parent_target_id=target.id, subdomains=[subdomain]
    )
    await db_session.commit()
    assert second[0].id == first[0].id

    rows = (
        (
            await db_session.execute(
                select(DiscoveredAsset).where(DiscoveredAsset.parent_target_id == target.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
