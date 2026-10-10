"""The Go OSV.dev SCA engine (`app/core/appsec/osv/engine.py`'s
`OsvGoEngine`). Narrower than `test_osv_pypi_engine.py` by design: the
ecosystem-agnostic behavior (disclosure gate, failed query, unverifiable
id, missing detail record) is already exhaustively covered by
`test_osv_engine.py` and `test_osv_pypi_engine.py` against the same
`_OsvEngineBase` — this file only re-proves manifest discovery, that a
matched vulnerability becomes a finding carrying this engine's own
`meta.id` and ecosystem string, and the no-manifest case.
"""

from pathlib import Path

from app.core.appsec.osv.client import PackageQuery
from app.core.appsec.osv.engine import OsvGoEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Severity

SCOPE = CodeScope(allowed_paths=("go.sum",))


def _workspace(tmp_path: Path, content: str) -> object:
    (tmp_path / "go.sum").write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


_GO_SUM = "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"


def test_applies_to_is_true_only_with_an_in_scope_go_sum(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _GO_SUM)
    assert OsvGoEngine().applies_to(workspace) is True


def test_applies_to_is_false_without_a_go_sum(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.go",)))
    assert OsvGoEngine().applies_to(workspace) is False


async def test_a_workspace_with_no_go_sum_produces_no_results(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.go",)))

    results = await OsvGoEngine(allow_advisory_lookup=True).run(workspace)

    assert results == []


class _FakeClient:
    def __init__(self, vulnerable: dict, details: dict) -> None:
        self._vulnerable = vulnerable
        self._details = details

    async def query_vulnerable_ids(self, ctx: object, queries: list[PackageQuery]) -> dict:
        return self._vulnerable

    async def get_vulnerability_details(self, ctx: object, vuln_ids: set[str]) -> dict:
        return self._details


async def test_a_matched_vulnerability_becomes_a_finding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _GO_SUM)
    query = PackageQuery(name="github.com/pkg/errors", version="v0.9.1", ecosystem="Go")
    client = _FakeClient(
        vulnerable={query: ("GHSA-vwqx-pm7j-mmm2",)},
        details={"GHSA-vwqx-pm7j-mmm2": {"aliases": ["CVE-2024-99991"]}},
    )

    results = await OsvGoEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "KERVY-SCA-GHSA-vwqx-pm7j-mmm2"
    assert finding.probe_id == "appsec.sca.osv_go"
    assert "ecosystem: Go" in finding.reproduction[0]
    assert finding.severity is Severity.MEDIUM  # no fix info: the conservative default
    assert "Reachability was not assessed" in finding.impact
