"""Import-level and symbol-usage reachability for Go dependencies
(`app/core/appsec/reachability/go_imports.py`).
"""

from pathlib import Path

from app.core.appsec.reachability.go_imports import (
    MAX_SITES_REPORTED,
    ReachabilityVerdict,
    assess,
)
from app.core.appsec.workspace import CodeScope, resolve_workspace

SCOPE = CodeScope(allowed_paths=("*.go",))


def _workspace(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


def test_a_single_line_import_and_call_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"main.go": 'import "github.com/pkg/errors"\nerrors.New("x")\n'}
    )

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert result.sites[0].path == "main.go"
    assert result.sites[0].line == 1
    assert "errors.New" in result.call_sites[0].statement


def test_a_grouped_import_block_is_found(tmp_path: Path) -> None:
    """Go's dominant import style — a parenthesized block, not
    single-line — needs block-aware scanning, not a pure per-line regex."""
    workspace = _workspace(
        tmp_path,
        {
            "main.go": (
                'import (\n\t"fmt"\n\terr "github.com/pkg/errors"\n)\n'
                'err.New("x")\n'
            )
        },
    )

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert result.sites[0].line == 3
    assert "err.New" in result.call_sites[0].statement


def test_a_blank_import_has_no_bound_name(tmp_path: Path) -> None:
    """Side-effect only — correctly stays IMPORTED, not a gap."""
    workspace = _workspace(tmp_path, {"main.go": 'import _ "github.com/pkg/errors"\n'})

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_dot_import_cannot_be_matched_to_a_call(tmp_path: Path) -> None:
    """Documents the third named limitation: a dot import injects every
    exported name directly into scope, so a later bare call cannot be
    attributed back to this package — a false negative, not a crash."""
    workspace = _workspace(
        tmp_path, {"main.go": 'import . "github.com/pkg/errors"\nNew("x")\n'}
    )

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_submodule_import_matches_the_module_path(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        {
            "main.go": (
                'import "github.com/stretchr/testify/assert"\n'
                "assert.Equal(t, 1, 2)\n"
            )
        },
    )

    result = assess(workspace, "github.com/stretchr/testify")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_semantic_import_versioning_suffix_is_stripped(tmp_path: Path) -> None:
    """Go modules' own `/vN` major-version suffix is a defined rule, not
    a per-host guess — stripped before taking the last path segment."""
    workspace = _workspace(
        tmp_path, {"main.go": 'import "github.com/foo/bar/v2"\nbar.Do()\n'}
    )

    result = assess(workspace, "github.com/foo/bar/v2")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_dotted_version_suffix_mismatch_degrades_the_call_layer(tmp_path: Path) -> None:
    """Documents the second named limitation live: `gopkg.in/yaml.v3`'s
    real package is `yaml`, not `yaml.v3` — a documented exception this
    heuristic does not chase. The import site is still found correctly
    (module-path matching doesn't depend on the guessed name), but the
    call-usage layer misses the call and degrades to plain IMPORTED."""
    workspace = _workspace(
        tmp_path, {"main.go": 'import "gopkg.in/yaml.v3"\nyaml.Marshal(x)\n'}
    )

    result = assess(workspace, "gopkg.in/yaml.v3")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_package_with_no_import_anywhere_is_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"main.go": 'import "fmt"\n'})

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND
    assert result.sites == ()


def test_a_shadowing_local_variable_is_still_counted_as_called(tmp_path: Path) -> None:
    """Documents the fourth named limitation as a known, accepted false
    positive: a line-level regex scan has no scope model."""
    workspace = _workspace(
        tmp_path,
        {
            "main.go": (
                'import "github.com/pkg/errors"\n'
                "func f() {\n"
                '\terrors := "not the package"\n'
                "\terrors.New(x)\n"
                "}\n"
            )
        },
    )

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_no_go_files_in_scope_is_not_assessed_not_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"README.md": "hello"})

    result = assess(workspace, "github.com/pkg/errors")

    assert result.verdict is ReachabilityVerdict.NOT_ASSESSED


def test_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {f"mod{i}.go": 'import "github.com/pkg/errors"\n' for i in range(10)}
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "github.com/pkg/errors")

    assert len(result.sites) == MAX_SITES_REPORTED


def test_call_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {
        f"mod{i}.go": 'import "github.com/pkg/errors"\nerrors.New("x")\n' for i in range(10)
    }
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "github.com/pkg/errors")

    assert len(result.call_sites) == MAX_SITES_REPORTED
