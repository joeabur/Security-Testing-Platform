"""Reachability wired into the pip-audit SCA engine
(`app/core/appsec/sca/pip_audit_engine.py`'s `_normalize`): the blanket
"reachability was not assessed" disclaimer becomes concrete evidence once
a workspace is available to check against.
"""

from pathlib import Path

from app.core.appsec.sca.pip_audit_engine import PipAuditEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace

_PAYLOAD = {
    "dependencies": [
        {
            "name": "jinja2",
            "version": "2.10",
            "vulns": [
                {
                    "id": "GHSA-462w-v97r-4m45",
                    "aliases": ["CVE-2019-10906"],
                    "fix_versions": ["2.10.1"],
                }
            ],
        }
    ]
}


def _workspace(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.py", "requirements.txt")))


def test_without_a_workspace_the_original_disclaimer_is_kept() -> None:
    """Backward compatible: existing call sites that pass no workspace
    (and existing tests) see unchanged behaviour."""
    findings = PipAuditEngine()._normalize(_PAYLOAD, "requirements.txt")

    assert "Reachability was not assessed" in findings[0].impact


def test_an_imported_package_gets_concrete_evidence_instead(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        {"requirements.txt": "jinja2==2.10\n", "app.py": "from jinja2 import Template\n"},
    )

    findings = PipAuditEngine()._normalize(_PAYLOAD, "requirements.txt", workspace)

    assert "Statically imported" in findings[0].impact
    assert "app.py:1" in findings[0].impact
    assert "Reachability was not assessed" not in findings[0].impact


def test_an_unimported_package_states_the_absence_without_claiming_proof(
    tmp_path: Path,
) -> None:
    workspace = _workspace(
        tmp_path,
        {"requirements.txt": "jinja2==2.10\n", "app.py": "import os\n"},
    )

    findings = PipAuditEngine()._normalize(_PAYLOAD, "requirements.txt", workspace)

    assert "No static import" in findings[0].impact
    assert "not proof of" in findings[0].impact


def test_a_workspace_with_no_python_files_falls_back_to_the_disclaimer(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, {"requirements.txt": "jinja2==2.10\n"})

    findings = PipAuditEngine()._normalize(_PAYLOAD, "requirements.txt", workspace)

    assert "Reachability was not assessed" in findings[0].impact


def test_an_imported_and_called_package_gets_the_strongest_evidence(
    tmp_path: Path,
) -> None:
    workspace = _workspace(
        tmp_path,
        {
            "requirements.txt": "jinja2==2.10\n",
            "app.py": "from jinja2 import Template\nTemplate(x)\n",
        },
    )

    findings = PipAuditEngine()._normalize(_PAYLOAD, "requirements.txt", workspace)

    assert "and called" in findings[0].impact
    assert "app.py:2" in findings[0].impact
    assert "both imported and called" in findings[0].impact
    # Distinguishable from the plain-IMPORTED text used when no call is found.
    assert "no call to a name from that module was found" not in findings[0].impact
