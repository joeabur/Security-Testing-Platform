"""Import-level and symbol-usage reachability for npm (JavaScript/
TypeScript) dependencies — the same two bounded questions
`python_imports.py` answers for Python, now for the one other ecosystem
this platform's reachability work covers: does any in-scope JS/TS file
statically import this package at all, and, if so, does that same file
also *call* something bound by that import.

**Regex/line-based, not a real parse — and that is the whole reason this
exists rather than a JS/TS AST library.** No JavaScript/TypeScript parser
(esprima, acorn, tree-sitter, `@babel/parser`, or similar) is a dependency
anywhere in this Python backend, and adding one for this alone would be
out of proportion — the same reasoning that keeps every other manifest
parser in this codebase (`npm_lockfile.py`, `pypi_requirements.py`,
`go_sum.py`, `cargo_lock.py`, `gradle_lockfile.py`) hand-written and
bounded rather than reaching for a parser library. This module scans each
file line by line with a small set of regular expressions covering the
common `import`/`require` shapes, in exchange for real limitations named
below — not hidden behind a false appearance of full parsing.

**Three named limitations, not hidden ones.**

1. **This is a line-level regex scan, not a real parse.** A multi-line
   import statement (`import {\n  a,\n  b,\n} from "pkg"`), a dynamic
   import whose specifier is a template literal rather than a plain
   string (`` import(`./${name}`) ``), or import-like text that happens to
   appear inside a comment or a string literal, can be missed or
   misread. This is the same class of bounded-walk limitation
   `python_imports.py`'s own docstring already states for itself — doubled
   here, since there is no AST underneath at all.
2. **A dynamic `import("pkg")` call is recorded as an import site but
   never tracked for call-usage.** Its binding, if any (`const mod =
   await import("pkg")`), is not reliably extractable at line-regex
   granularity, so a package reached only this way degrades to the
   coarser `IMPORTED` verdict rather than `IMPORTED_AND_CALLED` — a false
   negative, the same category as `python_imports.py`'s dynamic-import
   limitation.
3. **A local variable or parameter that happens to share a bound import's
   name is not distinguished from the real import** — identical to
   `python_imports.py`'s own fourth limitation, and doubly true here since
   there is no scope model, nor an AST to build one from.

**One deliberate exclusion, not a limitation.** A TypeScript `import type
{...}` / `import type X from "..."` statement is not recorded as an
import site at all. A type-only import erases completely at compile time
and has no runtime presence — reporting it as "imported" would be a false
claim about reachability, not merely an incomplete one.
"""

import re
from pathlib import Path

from app.core.appsec.workspace import Workspace

from .shapes import (
    CallSite,
    ImportSite,
    ReachabilityAssessment,
    ReachabilityVerdict,
    impact_text_from_assessment,
)

#: Evidence stays readable; a dependency imported from forty places does
#: not need all forty listed to prove the point. Same bound as
#: `python_imports.py`'s `MAX_SITES_REPORTED` — per-module tuning, not
#: shared state, so duplicated rather than imported.
MAX_SITES_REPORTED = 5
#: Bounded so a very large checkout cannot turn one dependency's
#: assessment into an unbounded scan.
MAX_FILES_SCANNED = 5000

_JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

_IMPORT_TYPE = re.compile(r"^\s*import\s+type\b")
_STATIC_IMPORT = re.compile(r'^\s*import\s+(.+?)\s+from\s+["\']([^"\']+)["\']')
_SIDE_EFFECT_IMPORT = re.compile(r'^\s*import\s+["\']([^"\']+)["\']')
_DYNAMIC_IMPORT = re.compile(r'\bimport\(\s*["\']([^"\']+)["\']\s*\)')
_REQUIRE_WITH_BINDING = re.compile(
    r'(?:const|let|var)\s+(.+?)\s*=\s*require\(\s*["\']([^"\']+)["\']\s*\)'
)
_BARE_REQUIRE = re.compile(r'\brequire\(\s*["\']([^"\']+)["\']\s*\)')

_AS_ALIAS = re.compile(r"^(\w+)\s+as\s+(\w+)$")
_COLON_ALIAS = re.compile(r"^(\w+)\s*:\s*(\w+)$")


def _base_package(specifier: str) -> str:
    """The npm package a module specifier belongs to: the first path
    segment for an unscoped package (`lodash/debounce` -> `lodash`), the
    first two for a scoped one (`@babel/core/lib/x` -> `@babel/core`).
    `npm_lockfile_packages()` already returns the package name in exactly
    this shape, so no name-mapping table is needed the way Python's
    distribution-name-vs-import-name mismatch needs one.
    """
    parts = specifier.split("/")
    return "/".join(parts[:2]) if specifier.startswith("@") else parts[0]


def _named_bindings(inner: str) -> set[str]:
    # "a, b as c" -> {"a", "c"} (import-brace alias keyword: "as")
    names: set[str] = set()
    for part in inner.split(","):
        part = part.strip()
        if not part:
            continue
        match = _AS_ALIAS.match(part)
        names.add(match.group(2) if match else part)
    return names


def _destructured_bindings(inner: str) -> set[str]:
    # "a, b: c" -> {"a", "c"} (require-destructure alias keyword: ":")
    names: set[str] = set()
    for part in inner.split(","):
        part = part.strip()
        if not part:
            continue
        match = _COLON_ALIAS.match(part)
        names.add(match.group(2) if match else part)
    return names


def _import_clause_bindings(clause: str) -> set[str]:
    """Handles: "X" / "* as X" / "{ a, b as c }" / "X, { a }"."""
    names: set[str] = set()
    brace = re.search(r"\{([^}]*)\}", clause)
    if brace:
        names |= _named_bindings(brace.group(1))
        clause = clause[: brace.start()] + clause[brace.end() :]
    remainder = clause.strip().strip(",").strip()
    if remainder:
        namespace = re.match(r"^\*\s*as\s+(\w+)$", remainder)
        if namespace:
            names.add(namespace.group(1))
        elif re.match(r"^\w+$", remainder):
            names.add(remainder)
    return names


def _require_lhs_bindings(lhs: str) -> set[str]:
    """Handles: "X" / "{ a, b: c }"."""
    lhs = lhs.strip()
    brace = re.search(r"\{([^}]*)\}", lhs)
    if brace:
        return _destructured_bindings(brace.group(1))
    return {lhs} if re.match(r"^\w+$", lhs) else set()


def assess(workspace: Workspace, package_name: str) -> ReachabilityAssessment:
    """Whether any in-scope JS/TS file statically imports/requires
    `package_name`, and, if so, whether a call to a name bound by that
    import was also found in the same file."""
    if not package_name.strip():
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "no package name to resolve"
        )

    js_files = [path for path in workspace.files if path.suffix in _JS_SUFFIXES]
    if not js_files:
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "no JS/TS files in scope"
        )

    sites: list[ImportSite] = []
    call_sites: list[CallSite] = []
    for path in js_files[:MAX_FILES_SCANNED]:
        lines = _read_lines(path)
        if lines is None:
            continue
        relative = str(path.relative_to(workspace.root))
        file_sites, bound_names = _import_sites_and_bindings(lines, relative, package_name)
        if not file_sites:
            continue
        sites.extend(file_sites)
        if bound_names:
            call_sites.extend(_call_sites_in_file(lines, relative, bound_names))

    if sites:
        sites = sites[:MAX_SITES_REPORTED]
        if call_sites:
            call_sites = call_sites[:MAX_SITES_REPORTED]
            return ReachabilityAssessment(
                ReachabilityVerdict.IMPORTED_AND_CALLED,
                tuple(sites),
                f"found {len(sites)} static import site(s) and {len(call_sites)} call site(s)",
                call_sites=tuple(call_sites),
            )
        return ReachabilityAssessment(
            ReachabilityVerdict.IMPORTED,
            tuple(sites),
            f"found {len(sites)} static import site(s), no call site found",
        )
    return ReachabilityAssessment(
        ReachabilityVerdict.NOT_FOUND, (), "no static import found in the files scanned"
    )


def _read_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        # A file this engine cannot read is not evidence either way — it
        # is skipped, the same as a tool-unavailable gap elsewhere in this
        # codebase, rather than treated as a definitive "not imported".
        return None


def _import_sites_and_bindings(
    lines: list[str], relative: str, package_name: str
) -> tuple[list[ImportSite], set[str]]:
    sites: list[ImportSite] = []
    bound_names: set[str] = set()
    for lineno, line in enumerate(lines, start=1):
        if _IMPORT_TYPE.match(line):
            # Type-only imports erase at compile time — see the module
            # docstring's "deliberate exclusion" note. Not recorded at all.
            continue

        static = _STATIC_IMPORT.match(line)
        if static:
            clause, specifier = static.groups()
            if _base_package(specifier) == package_name:
                sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))
                bound_names |= _import_clause_bindings(clause)
            continue

        side_effect = _SIDE_EFFECT_IMPORT.match(line)
        if side_effect:
            specifier = side_effect.group(1)
            if _base_package(specifier) == package_name:
                sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))
            continue

        dynamic = _DYNAMIC_IMPORT.search(line)
        if dynamic:
            specifier = dynamic.group(1)
            if _base_package(specifier) == package_name:
                sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))
                # Deliberately not added to bound_names — see limitation 2.
            continue

        require_binding = _REQUIRE_WITH_BINDING.search(line)
        if require_binding:
            lhs, specifier = require_binding.groups()
            if _base_package(specifier) == package_name:
                sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))
                bound_names |= _require_lhs_bindings(lhs)
            continue

        bare_require = _BARE_REQUIRE.search(line)
        if bare_require:
            specifier = bare_require.group(1)
            if _base_package(specifier) == package_name:
                sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))

    return sites, bound_names


def _call_sites_in_file(
    lines: list[str], relative: str, bound_names: set[str]
) -> list[CallSite]:
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(name) for name in bound_names) + r")(?:\.\w+)?\s*\("
    )
    found: list[CallSite] = []
    for lineno, line in enumerate(lines, start=1):
        if pattern.search(line):
            found.append(CallSite(path=relative, line=lineno, statement=line.strip()))
    return found


def reachability_impact_text(workspace: Workspace, package_name: str) -> str | None:
    """Replaces the blanket "reachability was not assessed" disclaimer
    with what `assess()` actually found. See
    `shapes.impact_text_from_assessment` for the shared wording.
    """
    return impact_text_from_assessment(assess(workspace, package_name))
