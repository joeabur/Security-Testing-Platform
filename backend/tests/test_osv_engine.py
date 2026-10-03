"""The OSV.dev SCA engine (`app/core/appsec/osv/engine.py`):
lockfile discovery, the disclosure-consent gate pip-audit's own engine
already requires, normalization of a query result into a `ScanResult`, and
one true end-to-end test proving the real scope engine — not a stand-in —
gates this traffic to exactly `api.osv.dev`.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from app.core.appsec.osv.client import OsvClient, OsvClientError, PackageQuery
from app.core.appsec.osv.egress import OSV_HOST, osv_egress_context
from app.core.appsec.osv.engine import OsvEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Severity
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport, ScopeBlockedError
from tests.security.conftest import FakeDnsResolver

SCOPE = CodeScope(allowed_paths=("package-lock.json",))


def _workspace(tmp_path: Path, document: dict[str, object]) -> object:
    (tmp_path / "package-lock.json").write_text(json.dumps(document), encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


_LOCKFILE = {
    "lockfileVersion": 3,
    "packages": {"node_modules/braces": {"version": "2.3.2"}},
}


def test_applies_to_is_true_only_with_an_in_scope_lockfile(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _LOCKFILE)
    assert OsvEngine().applies_to(workspace) is True


def test_applies_to_is_false_without_a_lockfile(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.txt",)))
    assert OsvEngine().applies_to(workspace) is False


async def test_lookup_disabled_reports_a_disclosure_gap_not_a_clean_result(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, _LOCKFILE)

    results = await OsvEngine(allow_advisory_lookup=False).run(workspace)

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "disclosure" in results[0].evidence.lower()
    assert OSV_HOST in results[0].evidence


async def test_a_workspace_with_no_lockfile_produces_no_results(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.txt",)))

    results = await OsvEngine(allow_advisory_lookup=True).run(workspace)

    assert results == []


class _FakeClient:
    """Stands in for `OsvClient` at the engine's own seam — same two
    methods, no network, no host."""

    def __init__(
        self, vulnerable: dict[PackageQuery, tuple[str, ...]], details: dict[str, dict]
    ) -> None:
        self._vulnerable = vulnerable
        self._details = details
        self.detail_calls: set[str] = set()

    async def query_vulnerable_ids(
        self, ctx: object, queries: list[PackageQuery]
    ) -> dict[PackageQuery, tuple[str, ...]]:
        return self._vulnerable

    async def get_vulnerability_details(
        self, ctx: object, vuln_ids: set[str]
    ) -> dict[str, dict]:
        self.detail_calls |= vuln_ids
        return self._details


async def test_a_matched_vulnerability_becomes_a_finding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _LOCKFILE)
    query = PackageQuery(name="braces", version="2.3.2", ecosystem="npm")
    client = _FakeClient(
        vulnerable={query: ("GHSA-cwfw-4gq5-mrqx",)},
        details={
            "GHSA-cwfw-4gq5-mrqx": {
                "summary": "Uncontrolled resource consumption in braces",
                "aliases": ["CVE-2024-4068"],
                "affected": [
                    {
                        "package": {"name": "braces", "ecosystem": "npm"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.0.3"}]}],
                    }
                ],
                "database_specific": {"severity": "HIGH"},
            }
        },
    )

    results = await OsvEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "KERVY-SCA-GHSA-cwfw-4gq5-mrqx"
    assert finding.severity is Severity.HIGH
    assert "CVE-2024-4068" in finding.frameworks
    assert "3.0.3" in finding.description
    assert "Reachability was not assessed" in finding.impact
    assert client.detail_calls == {"GHSA-cwfw-4gq5-mrqx"}


async def test_no_vulnerability_found_produces_no_findings(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _LOCKFILE)
    client = _FakeClient(vulnerable={}, details={})

    results = await OsvEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert results == []


async def test_an_id_with_no_detail_record_still_produces_a_finding(tmp_path: Path) -> None:
    """The batch endpoint returned a match but the detail lookup for it was
    never fetched (beyond `MAX_DETAIL_LOOKUPS`, or the lookup itself
    failed for just that id) — the package is still reported as affected,
    using only the id, rather than dropped for an accident of ordering."""
    workspace = _workspace(tmp_path, _LOCKFILE)
    query = PackageQuery(name="braces", version="2.3.2", ecosystem="npm")
    client = _FakeClient(vulnerable={query: ("GHSA-cwfw-4gq5-mrqx",)}, details={})

    results = await OsvEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    assert results[0].severity is Severity.MEDIUM  # no fix info: the conservative default


async def test_an_unverifiable_id_produces_no_finding(tmp_path: Path) -> None:
    """A batch result naming something that is not a real advisory shape is
    dropped, the same rule `pip_audit_engine` applies to its own tool's
    output — never laundered into a finding."""
    workspace = _workspace(tmp_path, _LOCKFILE)
    query = PackageQuery(name="braces", version="2.3.2", ecosystem="npm")
    client = _FakeClient(vulnerable={query: ("not-a-real-advisory-id",)}, details={})

    results = await OsvEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert results == []


class _FailingClient:
    async def query_vulnerable_ids(self, ctx: object, queries: list[PackageQuery]) -> dict:
        raise OsvClientError("osv.dev did not respond")

    async def get_vulnerability_details(self, ctx: object, vuln_ids: set[str]) -> dict:
        raise OsvClientError("unreachable")


async def test_a_failed_query_is_reported_as_a_gap_not_a_clean_result(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _LOCKFILE)

    results = await OsvEngine(allow_advisory_lookup=True, client=_FailingClient()).run(workspace)

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "osv.dev did not respond" in results[0].evidence


# --- end to end: the real scope engine, not a stand-in ----------------------


@respx.mock
async def test_the_real_scope_engine_permits_exactly_osv_dev() -> None:
    route = respx.post(f"https://{OSV_HOST}/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{}]})
    )
    client = OsvClient(
        transport=GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({OSV_HOST: ["203.0.113.50"]})
        )
    )
    ctx = osv_egress_context()

    result = await client.query_vulnerable_ids(
        ctx, [PackageQuery(name="braces", version="3.0.3", ecosystem="npm")]
    )

    assert result == {}
    assert route.called


async def test_the_real_scope_engine_refuses_every_other_host() -> None:
    """The fixed-host containment claim, proven rather than asserted: a
    context built by `osv_egress_context` cannot be used to reach anything
    but `api.osv.dev`, however the client itself were changed."""
    transport = GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({"evil.example.test": ["203.0.113.9"]})
    )
    ctx = osv_egress_context()

    with pytest.raises(ScopeBlockedError):
        await transport.send(ctx, method="GET", url="https://evil.example.test/")
