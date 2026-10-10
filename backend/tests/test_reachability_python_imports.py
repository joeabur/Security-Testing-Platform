"""Import-level reachability for Python dependencies
(`app/core/appsec/reachability/python_imports.py`).
"""

from pathlib import Path

from app.core.appsec.reachability.python_imports import ReachabilityVerdict, assess
from app.core.appsec.workspace import CodeScope, resolve_workspace

SCOPE = CodeScope(allowed_paths=("*.py",))


def _workspace(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


def test_a_plain_import_statement_is_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "import requests\n"})

    result = assess(workspace, "requests")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.sites[0].path == "app.py"
    assert result.sites[0].line == 1
    assert "requests" in result.sites[0].statement


def test_a_from_import_statement_is_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "from jinja2 import Template\n"})

    result = assess(workspace, "jinja2")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert "Template" in result.sites[0].statement


def test_a_submodule_import_matches_the_top_level_package(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "from jinja2.loaders import FileSystemLoader\n"})

    result = assess(workspace, "jinja2")

    assert result.verdict is ReachabilityVerdict.IMPORTED


def test_an_aliased_import_is_still_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "import numpy as np\n"})

    result = assess(workspace, "numpy")

    assert result.verdict is ReachabilityVerdict.IMPORTED


def test_a_package_with_no_import_anywhere_is_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "import os\nimport sys\n"})

    result = assess(workspace, "requests")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND
    assert result.sites == ()


def test_a_relative_import_is_never_matched_against_a_distribution(tmp_path: Path) -> None:
    """`from . import helpers` names a module inside this same project, not
    a third-party distribution that happens to share a name — matching it
    would be a false positive, not evidence."""
    workspace = _workspace(tmp_path, {"app/__init__.py": "", "app/main.py": "from . import app\n"})

    result = assess(workspace, "app")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND


def test_a_mention_in_a_comment_or_string_is_not_an_import(tmp_path: Path) -> None:
    """AST-based detection, not textual — the same false-positive concern
    `identifiers.py` raises about invented findings elsewhere."""
    workspace = _workspace(
        tmp_path, {"app.py": '# TODO: stop using requests\nurl = "requests-are-fun"\n'}
    )

    result = assess(workspace, "requests")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND


def test_no_python_files_in_scope_is_not_assessed_not_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"README.md": "hello"})

    result = assess(workspace, "requests")

    assert result.verdict is ReachabilityVerdict.NOT_ASSESSED


def test_a_syntax_error_in_one_file_does_not_stop_the_others(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        {"broken.py": "def f(:\n", "ok.py": "import requests\n"},
    )

    result = assess(workspace, "requests")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.sites[0].path == "ok.py"


def test_a_known_distribution_import_name_mismatch_is_resolved(tmp_path: Path) -> None:
    """PyYAML installs as `import yaml` — the curated override table, not
    the default hyphen-to-underscore normalization, is what finds this."""
    workspace = _workspace(tmp_path, {"app.py": "import yaml\n"})

    result = assess(workspace, "PyYAML")

    assert result.verdict is ReachabilityVerdict.IMPORTED


def test_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {f"mod{i}.py": "import requests\n" for i in range(10)}
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "requests")

    from app.core.appsec.reachability.python_imports import MAX_SITES_REPORTED

    assert len(result.sites) == MAX_SITES_REPORTED


def test_an_imported_and_called_symbol_is_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "import yaml\nyaml.safe_load(x)\n"})

    result = assess(workspace, "yaml")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert result.call_sites[0].path == "app.py"
    assert result.call_sites[0].line == 2
    assert "yaml.safe_load" in result.call_sites[0].statement


def test_a_direct_call_of_a_from_imported_name_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.py": "from yaml import safe_load\nsafe_load(x)\n"}
    )

    result = assess(workspace, "yaml")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "safe_load" in result.call_sites[0].statement


def test_an_aliased_import_call_is_matched_by_the_alias(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "import yaml as y\ny.safe_load(x)\n"})

    result = assess(workspace, "yaml")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "y.safe_load" in result.call_sites[0].statement


def test_an_import_with_no_call_usage_stays_imported(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.py": "import yaml\n"})

    result = assess(workspace, "yaml")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_star_import_cannot_be_matched_to_a_call(tmp_path: Path) -> None:
    """Documents the third named limitation: `from yaml import *` binds no
    trackable name, so even an obvious call stays at the coarser `IMPORTED`
    verdict rather than a false `IMPORTED_AND_CALLED`."""
    workspace = _workspace(tmp_path, {"app.py": "from yaml import *\nsafe_load(x)\n"})

    result = assess(workspace, "yaml")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_shadowing_local_variable_is_still_counted_as_called(tmp_path: Path) -> None:
    """Documents the fourth named limitation as a known, accepted false
    positive rather than leaving it silently uncovered: a plain AST walk
    has no scope model, so a local variable shadowing the module's bound
    name is indistinguishable from a real call to the import."""
    workspace = _workspace(
        tmp_path,
        {
            "app.py": (
                "import yaml\n"
                "def f():\n"
                "    yaml = 'not the module'\n"
                "    yaml.safe_load(x)\n"
            )
        },
    )

    result = assess(workspace, "yaml")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_call_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {f"mod{i}.py": "import yaml\nyaml.safe_load(x)\n" for i in range(10)}
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "yaml")

    from app.core.appsec.reachability.python_imports import MAX_SITES_REPORTED

    assert len(result.call_sites) == MAX_SITES_REPORTED
