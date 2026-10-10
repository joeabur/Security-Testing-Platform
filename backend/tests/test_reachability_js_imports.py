"""Import-level and symbol-usage reachability for npm (JavaScript/
TypeScript) dependencies (`app/core/appsec/reachability/js_imports.py`).
"""

from pathlib import Path

from app.core.appsec.reachability.js_imports import MAX_SITES_REPORTED, ReachabilityVerdict, assess
from app.core.appsec.workspace import CodeScope, resolve_workspace

SCOPE = CodeScope(allowed_paths=("*.js", "*.jsx", "*.ts", "*.tsx"))


def _workspace(tmp_path: Path, files: dict[str, str]):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return resolve_workspace(tmp_path, SCOPE)


def test_a_default_es_import_is_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.js": 'import lodash from "lodash";\n'})

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.sites[0].path == "app.js"
    assert result.sites[0].line == 1
    assert "lodash" in result.sites[0].statement


def test_a_named_and_aliased_import_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": 'import { debounce as d } from "lodash";\nd(fn);\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "d(fn)" in result.call_sites[0].statement


def test_a_namespace_import_call_is_matched(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": 'import * as _ from "lodash";\n_.debounce(fn);\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "_.debounce" in result.call_sites[0].statement


def test_a_side_effect_only_import_has_no_bound_name(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.js": 'import "lodash";\n'})

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_commonjs_require_with_binding_and_call_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": 'const lodash = require("lodash");\nlodash.debounce(fn);\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "lodash.debounce" in result.call_sites[0].statement


def test_commonjs_destructured_and_aliased_require_is_found(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": 'const { debounce: d } = require("lodash");\nd(fn);\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED
    assert "d(fn)" in result.call_sites[0].statement


def test_a_bare_require_has_no_bound_name(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.js": 'require("lodash");\n'})

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_scoped_package_import_is_matched(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": 'import core from "@babel/core";\ncore.transform(x);\n'}
    )

    result = assess(workspace, "@babel/core")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_submodule_import_matches_the_base_package(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": 'import debounce from "lodash/debounce";\ndebounce(fn);\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_scoped_submodule_import_matches_the_base_package(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.ts": 'import { parse } from "@babel/core/lib/parse";\nparse(x);\n'}
    )

    result = assess(workspace, "@babel/core")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_package_with_no_import_anywhere_is_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"app.js": 'import fs from "fs";\n'})

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND
    assert result.sites == ()


def test_a_type_only_import_is_excluded_entirely(tmp_path: Path) -> None:
    """A type-only import erases at compile time — recording it as
    "imported" would be a false claim about runtime reachability, so it
    is not recorded as a site at all (not merely downgraded)."""
    workspace = _workspace(tmp_path, {"app.ts": 'import type { Foo } from "lodash";\n'})

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND


def test_a_dynamic_import_is_recorded_but_not_matched_to_a_call(tmp_path: Path) -> None:
    """Documents the second named limitation: a dynamic `import()`'s
    binding isn't reliably extractable at line-regex granularity, so this
    degrades to the coarser `IMPORTED` verdict rather than a false
    `IMPORTED_AND_CALLED`."""
    workspace = _workspace(
        tmp_path, {"app.js": 'const mod = await import("lodash");\nmod.debounce(fn);\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED
    assert result.call_sites == ()


def test_a_shadowing_local_variable_is_still_counted_as_called(tmp_path: Path) -> None:
    """Documents the third named limitation as a known, accepted false
    positive: a line-level regex scan has no scope model, so a local
    variable sharing the module's bound name is indistinguishable from a
    real call to the import."""
    workspace = _workspace(
        tmp_path,
        {
            "app.js": (
                'import lodash from "lodash";\n'
                "function f() {\n"
                '  const lodash = "not the module";\n'
                "  lodash.debounce(fn);\n"
                "}\n"
            )
        },
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED


def test_a_mention_in_a_comment_or_string_is_not_an_import(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path, {"app.js": '// TODO: stop using lodash\nconst url = "lodash-is-fun";\n'}
    )

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.NOT_FOUND


def test_no_js_files_in_scope_is_not_assessed_not_not_found(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, {"README.md": "hello"})

    result = assess(workspace, "lodash")

    assert result.verdict is ReachabilityVerdict.NOT_ASSESSED


def test_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {f"mod{i}.js": 'import lodash from "lodash";\n' for i in range(10)}
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "lodash")

    assert len(result.sites) == MAX_SITES_REPORTED


def test_call_sites_are_bounded_to_the_reported_maximum(tmp_path: Path) -> None:
    files = {
        f"mod{i}.js": 'import lodash from "lodash";\nlodash.debounce(fn);\n' for i in range(10)
    }
    workspace = _workspace(tmp_path, files)

    result = assess(workspace, "lodash")

    assert len(result.call_sites) == MAX_SITES_REPORTED
