"""`enrich_findings()` (`app/core/appsec/enrichment/advisory_detail.py`):
dispatch by primary advisory id, dedup of a shared id across findings, a
failed lookup leaving a finding unchanged, empty `frameworks` skipped, the
`MAX_ENRICHMENT_LOOKUPS` bound, and that `severity`/`confidence` never
change. `NvdClient`/`GhsaClient` are monkeypatched at their own public
methods — the same seam `test_osv_engine.py`'s `_FakeClient` stands in for
`OsvClient` at.
"""

from typing import Any

import pytest

from app.core.appsec.enrichment import advisory_detail
from app.core.probes.models import Category, Confidence, ScanResult, Severity


def _result(result_id: str, framework: str | None) -> ScanResult:
    return ScanResult(
        id=result_id,
        title="A finding",
        category=Category.INFRASTRUCTURE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        endpoint="pyproject.toml",
        description="original description",
        evidence="evidence",
        impact="impact",
        remediation="remediation",
        probe_id="osv",
        probe_version="1",
        frameworks=(framework,) if framework else (),
    )


class _FakeNvdClient:
    def __init__(self, cve: dict[str, Any] | None, *, error: bool = False) -> None:
        self._cve = cve
        self._error = error
        self.calls: list[str] = []

    async def get_cve(self, ctx: object, cve_id: str) -> dict[str, Any] | None:
        self.calls.append(cve_id)
        if self._error:
            raise advisory_detail.NvdClientError("boom")
        return self._cve


class _FakeGhsaClient:
    def __init__(self, advisory: dict[str, Any] | None, *, error: bool = False) -> None:
        self._advisory = advisory
        self._error = error
        self.calls: list[str] = []

    async def get_advisory(self, ctx: object, ghsa_id: str) -> dict[str, Any] | None:
        self.calls.append(ghsa_id)
        if self._error:
            raise advisory_detail.GhsaClientError("boom")
        return self._advisory


def _patch_clients(monkeypatch: pytest.MonkeyPatch, nvd: Any, ghsa: Any) -> None:
    monkeypatch.setattr(advisory_detail, "NvdClient", lambda: nvd)
    monkeypatch.setattr(advisory_detail, "GhsaClient", lambda: ghsa)


_CVE = {
    "descriptions": [{"lang": "en", "value": "A critical thing happens."}],
    "metrics": {
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "V"}}
        ]
    },
}
_ADVISORY = {"summary": "A GHSA thing.", "cvss": {"score": 7.5, "vector_string": "V"}}


async def test_a_cve_primary_finding_is_enriched(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clients(monkeypatch, _FakeNvdClient(_CVE), _FakeGhsaClient(None))
    results = await advisory_detail.enrich_findings([_result("r1", "CVE-2024-1234")])

    assert "Direct NVD lookup for CVE-2024-1234" in results[0].description
    assert "9.8" in results[0].description
    assert "A critical thing happens." in results[0].description
    assert "original description" in results[0].description


async def test_a_ghsa_primary_finding_is_enriched(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clients(monkeypatch, _FakeNvdClient(None), _FakeGhsaClient(_ADVISORY))
    results = await advisory_detail.enrich_findings([_result("r1", "GHSA-xxxx-xxxx-xxxx")])

    assert "Direct GHSA lookup for GHSA-xxxx-xxxx-xxxx" in results[0].description
    assert "7.5" in results[0].description
    assert "A GHSA thing." in results[0].description


async def test_severity_and_confidence_never_change(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_clients(monkeypatch, _FakeNvdClient(_CVE), _FakeGhsaClient(None))
    result = _result("r1", "CVE-2024-1234")

    [enriched] = await advisory_detail.enrich_findings([result])

    assert enriched.severity is result.severity
    assert enriched.confidence is result.confidence


async def test_no_frameworks_passes_through_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    nvd, ghsa = _FakeNvdClient(_CVE), _FakeGhsaClient(_ADVISORY)
    _patch_clients(monkeypatch, nvd, ghsa)
    result = _result("r1", None)

    [enriched] = await advisory_detail.enrich_findings([result])

    assert enriched == result
    assert nvd.calls == []
    assert ghsa.calls == []


async def test_an_unverifiable_primary_id_passes_through_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nvd, ghsa = _FakeNvdClient(_CVE), _FakeGhsaClient(_ADVISORY)
    _patch_clients(monkeypatch, nvd, ghsa)
    result = _result("r1", "not-a-real-advisory-id")

    [enriched] = await advisory_detail.enrich_findings([result])

    assert enriched.description == "original description"
    assert nvd.calls == []
    assert ghsa.calls == []


async def test_a_failed_lookup_leaves_the_finding_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_clients(monkeypatch, _FakeNvdClient(None, error=True), _FakeGhsaClient(None))
    result = _result("r1", "CVE-2024-1234")

    [enriched] = await advisory_detail.enrich_findings([result])

    assert enriched.description == "original description"


async def test_a_lookup_with_no_record_leaves_the_finding_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_clients(monkeypatch, _FakeNvdClient(None), _FakeGhsaClient(None))
    result = _result("r1", "CVE-2024-1234")

    [enriched] = await advisory_detail.enrich_findings([result])

    assert enriched.description == "original description"


async def test_a_shared_id_across_findings_is_looked_up_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nvd = _FakeNvdClient(_CVE)
    _patch_clients(monkeypatch, nvd, _FakeGhsaClient(None))
    results = [_result("r1", "CVE-2024-1234"), _result("r2", "CVE-2024-1234")]

    enriched = await advisory_detail.enrich_findings(results)

    assert nvd.calls == ["CVE-2024-1234"]
    assert all("Direct NVD lookup" in r.description for r in enriched)


async def test_lookups_beyond_the_bound_are_not_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    nvd = _FakeNvdClient(_CVE)
    _patch_clients(monkeypatch, nvd, _FakeGhsaClient(None))
    ids = [f"CVE-2024-{i:04d}" for i in range(advisory_detail.MAX_ENRICHMENT_LOOKUPS + 5)]
    results = [_result(f"r{i}", cve_id) for i, cve_id in enumerate(ids)]

    enriched = await advisory_detail.enrich_findings(results)

    assert len(nvd.calls) == advisory_detail.MAX_ENRICHMENT_LOOKUPS
    unenriched = [r for r in enriched if r.description == "original description"]
    assert len(unenriched) == 5
