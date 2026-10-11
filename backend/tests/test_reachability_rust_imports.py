"""Import-level and symbol-usage reachability for Rust dependencies
(`app/core/appsec/reachability/rust_imports.py`).
"""

from pathlib import Path

from app.core.appsec.reachability.rust_imports import (
    MAX_SITES_REPORTED,
    ReachabilityVerdict,
    assess,
)
from app.core.appsec.workspace import CodeScope, resolve_workspace

SCOPE = CodeScope(allowed_paths=("*.rs",))


def _workspace(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


def test_a_hyphenated_crate_name_is_resolved_via_the_underscore_mapping(
    tmp_path: Path,
) -> None:
    """Cargo's own deterministic rule: `serde-json` in Cargo.lock is
    `serde_json` in Rust source — not a heuristic, confirmed from the
    Rust reference."""
    workspace = _workspace(tmp_path, {"main.rs": "use serde_json::Value;\n"})

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.sites[0].path == "main.rs"
    assert result.sites[0].line == 1


def test_a_named_import_and_call_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"main.rs": "use serde_json::from_str;\nfrom_str(x);\n"}
    )

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "from_str(x)" in result.call_sites[0].statement


def test_a_braced_import_with_aliasing_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        {"main.rs": "use serde_json::{Value, from_str as parse};\nparse(x);\n"},
    )

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "parse(x)" in result.call_sites[0].statement


def test_a_qualified_call_with_no_use_statement_at_all_is_found(tmp_path: Path) -> None:
    """The Rust-specific case: a fully-qualified call compiles with no
    `use` statement, since a declared dependency's crate root is always
    addressable."""
    workspace = _workspace(tmp_path, {"main.rs": "fn f() {\n    serde_json::to_string(x);\n}\n"})

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "serde_json::to_string" in result.call_sites[0].statement


def test_a_bare_crate_use_with_a_later_qualified_call_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"main.rs": "use serde_json;\nserde_json::to_string(x);\n"}
    )

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_glob_import_cannot_be_matched_to_a_named_call(tmp_path: Path) -> None:
    """Documents the second named limitation: a glob import binds no
    specific trackable name beyond the crate root itself, so a named item
    reached only through the glob is invisible to the call-usage check —
    degrades to plain IMPORTED, a false negative."""
    workspace = _workspace(tmp_path, {"main.rs": "use serde_json::*;\nfrom_str(x);\n"})

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_package_with_no_import_anywhere_is_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"main.rs": "use std::io;\n"})

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND
    assert result.sites == ()


def test_a_shadowing_local_variable_is_still_counted_as_called(tmp_path: Path) -> None:
    """Documents the third named limitation as a known, accepted false
    positive: a line-level regex scan has no scope model."""
    workspace = _workspace(
        tmp_path,
        {
            "main.rs": (
                "use serde_json::Value;\n"
                "fn f() {\n"
                '    let serde_json = "not the crate";\n'
                "    serde_json::to_string(x);\n"
                "}\n"
            )
        },
    )

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_no_rust_files_in_scope_is_not_assessed_not_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"README.md": "hello"})

    result = assess(workspace, "serde-json")

    assert result.verdict is ReachabilityVerdict.NOT_ASSESSED


def test_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {f"mod{i}.rs": "use serde_json::Value;\n" for i in range(10)}
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "serde-json")

    assert len(result.sites) == MAX_SITES_REPORTED


def test_call_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {
        f"mod{i}.rs": "use serde_json::from_str;\nfrom_str(x);\n" for i in range(10)
    }
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "serde-json")

    assert len(result.call_sites) == MAX_SITES_REPORTED
