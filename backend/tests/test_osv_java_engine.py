"""The Java/Gradle OSV.dev SCA engine (`app/core/appsec/osv/engine.py`'s
`OsvJavaEngine`). Narrower by design — see `test_osv_go_engine.py`'s
module docstring for why.
"""

from pathlib import Path

from app.core.appsec.osv.client import PackageQuery
from app.core.appsec.osv.engine import OsvJavaEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Severity

SCOPE = CodeScope(allowed_paths=("gradle.lockfile",))


def _workspace(tmp_path: Path, content: str) -> object:
    (tmp_path / "gradle.lockfile").write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


_LOCKFILE = "com.google.guava:guava:31.1-jre=compileClasspath\n"


def test_applies_to_is_true_only_with_an_in_scope_lockfile(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _LOCKFILE)
    assert OsvJavaEngine().applies_to(workspace) is True


def test_applies_to_is_false_without_a_lockfile(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.java",)))
    assert OsvJavaEngine().applies_to(workspace) is False


async def test_a_workspace_with_no_lockfile_produces_no_results(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.java",)))

    results = await OsvJavaEngine(allow_advisory_lookup=True).run(workspace)

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
    workspace = _workspace(tmp_path, _LOCKFILE)
    query = PackageQuery(name="com.google.guava:guava", version="31.1-jre", ecosystem="Maven")
    client = _FakeClient(
        vulnerable={query: ("GHSA-vwqx-pm7j-mmm4",)},
        details={"GHSA-vwqx-pm7j-mmm4": {"aliases": ["CVE-2024-99993"]}},
    )

    results = await OsvJavaEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "KERVY-SCA-GHSA-vwqx-pm7j-mmm4"
    assert finding.probe_id == "appsec.sca.osv_java"
    assert "ecosystem: Maven" in finding.reproduction[0]
    assert finding.severity is Severity.MEDIUM
    assert "Reachability was not assessed" in finding.impact
