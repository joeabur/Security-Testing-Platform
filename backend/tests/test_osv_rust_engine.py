"""The Rust OSV.dev SCA engine (`app/core/appsec/osv/engine.py`'s
`OsvRustEngine`). Narrower by design — see `test_osv_go_engine.py`'s
module docstring for why.
"""

from pathlib import Path

from app.core.appsec.osv.client import PackageQuery
from app.core.appsec.osv.engine import OsvRustEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Severity

SCOPE = CodeScope(allowed_paths=("Cargo.lock",))
_CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def _workspace(tmp_path: Path, content: str) -> object:
    (tmp_path / "Cargo.lock").write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


_CARGO_LOCK = f'[[package]]\nname = "serde"\nversion = "1.0.195"\nsource = "{_CRATES_IO}"\n'


def test_applies_to_is_true_only_with_an_in_scope_cargo_lock(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _CARGO_LOCK)
    assert OsvRustEngine().applies_to(workspace) is True


def test_applies_to_is_false_without_a_cargo_lock(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.rs",)))
    assert OsvRustEngine().applies_to(workspace) is False


async def test_a_workspace_with_no_cargo_lock_produces_no_results(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.rs",)))

    results = await OsvRustEngine(allow_advisory_lookup=True).run(workspace)

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
    workspace = _workspace(tmp_path, _CARGO_LOCK)
    query = PackageQuery(name="serde", version="1.0.195", ecosystem="crates.io")
    client = _FakeClient(
        vulnerable={query: ("GHSA-vwqx-pm7j-mmm3",)},
        details={"GHSA-vwqx-pm7j-mmm3": {"aliases": ["CVE-2024-99992"]}},
    )

    results = await OsvRustEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "KERVY-SCA-GHSA-vwqx-pm7j-mmm3"
    assert finding.probe_id == "appsec.sca.osv_rust"
    assert "ecosystem: crates.io" in finding.reproduction[0]
    assert finding.severity is Severity.MEDIUM
    assert "Reachability was not assessed" in finding.impact
