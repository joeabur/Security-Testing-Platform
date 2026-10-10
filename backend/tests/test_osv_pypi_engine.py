"""The PyPI OSV.dev SCA engine (`app/core/appsec/osv/engine.py`'s
`OsvPypiEngine`): manifest discovery, the disclosure-consent gate every
advisory-lookup engine on this platform requires, normalization of a query
result into a `ScanResult`, and reachability decoration — the one thing
this ecosystem's engine can do that the npm engine cannot, since
`python_imports.py` only understands Python import/call syntax.
"""

from pathlib import Path

from app.core.appsec.osv.client import OsvClientError, PackageQuery
from app.core.appsec.osv.egress import OSV_HOST
from app.core.appsec.osv.engine import OsvPypiEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Severity

SCOPE = CodeScope(allowed_paths=("requirements.txt", "*.py"))


def _workspace(tmp_path: Path, files: dict[str, str]) -> object:
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


def test_applies_to_is_true_only_with_an_in_scope_requirements_file(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})
    assert OsvPypiEngine().applies_to(workspace) is True


def test_applies_to_is_false_without_a_requirements_file(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.py",)))
    assert OsvPypiEngine().applies_to(workspace) is False


async def test_lookup_disabled_reports_a_disclosure_gap_not_a_clean_result(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})

    results = await OsvPypiEngine(allow_advisory_lookup=False).run(workspace)

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "disclosure" in results[0].evidence.lower()
    assert "PyPI" in results[0].title
    assert OSV_HOST in results[0].evidence


async def test_a_workspace_with_no_requirements_file_produces_no_results(
    tmp_path: Path,
) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.py",)))

    results = await OsvPypiEngine(allow_advisory_lookup=True).run(workspace)

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

    async def get_vulnerability_details(self, ctx: object, vuln_ids: set[str]) -> dict[str, dict]:
        self.detail_calls |= vuln_ids
        return self._details


async def test_a_matched_vulnerability_becomes_a_finding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})
    query = PackageQuery(name="jinja2", version="2.10", ecosystem="pypi")
    client = _FakeClient(
        vulnerable={query: ("GHSA-462w-v97r-4m45",)},
        details={
            "GHSA-462w-v97r-4m45": {
                "summary": "Side Template Injection in Jinja2",
                "aliases": ["CVE-2019-10906"],
                "affected": [
                    {
                        "package": {"name": "jinja2", "ecosystem": "PyPI"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}],
                    }
                ],
                "database_specific": {"severity": "HIGH"},
            }
        },
    )

    results = await OsvPypiEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    finding = results[0]
    assert finding.id == "KERVY-SCA-GHSA-462w-v97r-4m45"
    assert finding.severity is Severity.HIGH
    assert "CVE-2019-10906" in finding.frameworks
    assert "2.10.1" in finding.description
    assert "Reachability was not assessed" in finding.impact
    assert client.detail_calls == {"GHSA-462w-v97r-4m45"}


async def test_reachability_evidence_decorates_the_finding_when_a_workspace_has_code(
    tmp_path: Path,
) -> None:
    """The one real difference from the npm engine: a `Workspace` with
    Python source lets this engine replace the generic disclaimer with
    concrete import evidence, the same way `pip_audit_engine.py` already
    does for its own findings."""
    workspace = _workspace(
        tmp_path,
        {
            "requirements.txt": "jinja2==2.10\n",
            "app.py": "from jinja2 import Template\n",
        },
    )
    query = PackageQuery(name="jinja2", version="2.10", ecosystem="pypi")
    client = _FakeClient(
        vulnerable={query: ("GHSA-462w-v97r-4m45",)},
        details={"GHSA-462w-v97r-4m45": {"aliases": ["CVE-2019-10906"]}},
    )

    results = await OsvPypiEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    assert "Statically imported" in results[0].impact
    assert "app.py:1" in results[0].impact
    assert "Reachability was not assessed" not in results[0].impact


async def test_no_vulnerability_found_produces_no_findings(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})
    client = _FakeClient(vulnerable={}, details={})

    results = await OsvPypiEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert results == []


async def test_an_id_with_no_detail_record_still_produces_a_finding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})
    query = PackageQuery(name="jinja2", version="2.10", ecosystem="pypi")
    client = _FakeClient(vulnerable={query: ("GHSA-462w-v97r-4m45",)}, details={})

    results = await OsvPypiEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert len(results) == 1
    assert results[0].severity is Severity.MEDIUM  # no fix info: the conservative default


async def test_an_unverifiable_id_produces_no_finding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})
    query = PackageQuery(name="jinja2", version="2.10", ecosystem="pypi")
    client = _FakeClient(vulnerable={query: ("not-a-real-advisory-id",)}, details={})

    results = await OsvPypiEngine(allow_advisory_lookup=True, client=client).run(workspace)

    assert results == []


class _FailingClient:
    async def query_vulnerable_ids(self, ctx: object, queries: list[PackageQuery]) -> dict:
        raise OsvClientError("osv.dev did not respond")

    async def get_vulnerability_details(self, ctx: object, vuln_ids: set[str]) -> dict:
        raise OsvClientError("unreachable")


async def test_a_failed_query_is_reported_as_a_gap_not_a_clean_result(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})

    results = await OsvPypiEngine(allow_advisory_lookup=True, client=_FailingClient()).run(
        workspace
    )

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "osv.dev did not respond" in results[0].evidence
