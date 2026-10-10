"""Import-level and symbol-usage reachability for Python dependencies.

**What this answers, and what it deliberately does not.** Every SCA finding
on this platform has carried the same stated caveat since Phase 14:
"Reachability was not assessed. A vulnerable version being present does
not establish that the affected code path is used by this application."
This module answers two bounded questions, in order: does any in-scope
Python file *statically import* this package at all, and, if so, does that
same file also *call* something bound by that import. Both are real,
checkable evidence — a package nothing imports cannot have its vulnerable
code path exercised by this application, and an import with a call nearby
is stronger evidence of actual use than the import alone.

It is not the deeper question. Tracing from a call site down to the
specific vulnerable function, across module boundaries, through decorators
and dynamic dispatch, with real type/points-to resolution to resolve which
`obj.method()` dispatch actually runs — true call-graph reachability — is a
substantially larger project (interprocedural analysis, a real call graph,
data-flow to the vulnerable sink) and is not attempted here. No finding
from this module ever claims *which* function was called or that it is
*the* vulnerable one — only that some call to a name bound by the suspect
import exists in the same file as that import. This is the import- and
symbol-usage layer beneath that deeper question, not a replacement for it,
and the finding text says so rather than implying more than was checked.

**Four named limitations, not hidden ones.**

1. **Dynamic imports are invisible to this.** `importlib.import_module(name)`,
   a module name built from a variable, a plugin loaded by entry point —
   none of these are a literal `import`/`from ... import` statement an AST
   walk can see. A package reachable only this way will read `NOT_FOUND`
   here even though it genuinely is used. That is a false negative, stated
   rather than guessed around.
2. **A PyPI distribution's name and its Python import name often differ**
   (`PyYAML` installs as `import yaml`; `Pillow` as `import PIL`). This
   checks the distribution name itself, normalized by PyPI's own hyphen/dot
   convention, plus a small curated table of well-known mismatches — the
   same "one hand-curated list, explicitly not a live feed" idiom
   `appsec/supplychain/malware.py` already uses. A distribution whose real
   import name is not in that table and does not match the normalized
   distribution name will also read `NOT_FOUND` incorrectly.
3. **A star import (`from yaml import *`) cannot be matched to a call.**
   There is no bound name to track from `*` — the import site is still
   recorded, but the call-usage check can never confirm a call for a
   star-imported package, even when one plainly exists in the same file.
   This degrades to the coarser `IMPORTED` verdict, a false negative like
   limitation 1, not a false positive.
4. **A local variable, parameter, or loop target that happens to share a
   module's bound name is not distinguished from the real import.** Nothing
   here builds a scope model — a plain AST walk sees `yaml.safe_load(...)`
   identically whether `yaml` is the module imported at the top of the file
   or a local variable shadowing it inside a function below. This is a
   false *positive*, unlike the other three, and it is rare in practice
   (shadowing a module name is itself an anti-pattern most linters already
   flag) — but it is real, not hypothetical, and is named here rather than
   chased with a scope-resolution pass that would reopen the "substantially
   larger project" above.

The first three limitations are why a `NOT_FOUND` or `IMPORTED` verdict is
worded as an absence of evidence, never as proof of unreachability or
non-use. The fourth is why an `IMPORTED_AND_CALLED` verdict is worded as "a
call was found", never as "the vulnerable function was called."
"""

import ast
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from app.core.appsec.workspace import Workspace

#: Evidence stays readable; a dependency imported from forty places does
#: not need all forty listed to prove the point.
MAX_SITES_REPORTED = 5
#: Bounded so a very large checkout cannot turn one dependency's assessment
#: into an unbounded parse loop.
MAX_FILES_SCANNED = 5000

# Well-known PyPI distribution -> actual top-level import module mismatches.
# Not exhaustive, not a live feed — see the module docstring's second
# limitation. Values are the top-level module only, since that is all the
# matching below ever inspects.
_IMPORT_NAME_OVERRIDES: dict[str, str] = {
    "pyyaml": "yaml",
    "pillow": "pil",
    "beautifulsoup4": "bs4",
    "python-dateutil": "dateutil",
    "pyjwt": "jwt",
    "pycryptodome": "crypto",
    "protobuf": "google",
    "msgpack-python": "msgpack",
    "pyopenssl": "openssl",
    "python-dotenv": "dotenv",
    "grpcio": "grpc",
    "opencv-python": "cv2",
    "scikit-learn": "sklearn",
    "python-jose": "jose",
    "google-cloud-storage": "google",
}


class ReachabilityVerdict(StrEnum):
    #: A static import of this package was found, and a call to a name
    #: bound by that import was also found in the same file.
    IMPORTED_AND_CALLED = "imported_and_called"
    #: A static import of this package was found in at least one in-scope
    #: file, but no call to a name it bound was found anywhere in scope.
    IMPORTED = "imported"
    #: Python files were scanned and no static import was found.
    NOT_FOUND = "not_found"
    #: Nothing to scan (no Python files in scope) or the package name could
    #: not be resolved to a candidate import name at all.
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class ImportSite:
    path: str
    line: int
    statement: str


@dataclass(frozen=True)
class CallSite:
    path: str
    line: int
    statement: str


@dataclass(frozen=True)
class ReachabilityAssessment:
    verdict: ReachabilityVerdict
    sites: tuple[ImportSite, ...]
    detail: str
    #: Empty unless `verdict` is `IMPORTED_AND_CALLED`.
    call_sites: tuple[CallSite, ...] = ()


def _candidate_import_name(distribution_name: str) -> str:
    normalized = distribution_name.strip().lower()
    override = _IMPORT_NAME_OVERRIDES.get(normalized)
    if override:
        return override
    # PyPI's own convention: a distribution's import name is usually its
    # own name with hyphens and dots folded to underscores.
    return normalized.replace("-", "_").replace(".", "_")


def assess(workspace: Workspace, distribution_name: str) -> ReachabilityAssessment:
    """Whether any in-scope Python file statically imports `distribution_name`,
    and, if so, whether a call to a name bound by that import was also found
    in the same file."""
    candidate = _candidate_import_name(distribution_name)
    if not candidate:
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "could not resolve a candidate import name"
        )

    python_files = [path for path in workspace.files if path.suffix == ".py"]
    if not python_files:
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "no Python files in scope"
        )

    sites: list[ImportSite] = []
    call_sites: list[CallSite] = []
    for path in python_files[:MAX_FILES_SCANNED]:
        tree = _parse_file(path)
        if tree is None:
            continue
        relative = str(path.relative_to(workspace.root))
        file_sites, bound_names = _import_sites_and_bindings(tree, relative, candidate)
        if not file_sites:
            continue
        sites.extend(file_sites)
        if bound_names:
            call_sites.extend(_call_sites_in_file(tree, relative, bound_names))

    if sites:
        sites = sites[:MAX_SITES_REPORTED]
        if call_sites:
            call_sites = call_sites[:MAX_SITES_REPORTED]
            return ReachabilityAssessment(
                ReachabilityVerdict.IMPORTED_AND_CALLED,
                tuple(sites),
                f"found {len(sites)} static import site(s) and "
                f"{len(call_sites)} call site(s)",
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


def _parse_file(path: Path) -> ast.Module | None:
    try:
        source = path.read_text(encoding="utf-8")
        return ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        # A file this engine cannot parse is not evidence either way — it
        # is skipped, the same as a tool-unavailable gap elsewhere in this
        # codebase, rather than treated as a definitive "not imported".
        return None


def _import_sites_and_bindings(
    tree: ast.Module, relative: str, candidate: str
) -> tuple[list[ImportSite], set[str]]:
    sites: list[ImportSite] = []
    bound_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                if top_level.lower() == candidate:
                    sites.append(
                        ImportSite(
                            path=relative, line=node.lineno, statement=f"import {alias.name}"
                        )
                    )
                    bound_names.add(alias.asname or top_level)
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
            and node.module.split(".")[0].lower() == candidate
        ):
            names = ", ".join(alias.name for alias in node.names)
            sites.append(
                ImportSite(
                    path=relative,
                    line=node.lineno,
                    statement=f"from {node.module} import {names}",
                )
            )
            for alias in node.names:
                # A star import binds no name this module can track — see
                # the module docstring's third limitation.
                if alias.name == "*":
                    continue
                bound_names.add(alias.asname or alias.name)
    return sites, bound_names


def _call_sites_in_file(
    tree: ast.Module, relative: str, bound_names: set[str]
) -> list[CallSite]:
    found: list[CallSite] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        bound_name: str | None = None
        if isinstance(func, ast.Name):
            bound_name = func.id
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            bound_name = func.value.id
        if bound_name is not None and bound_name in bound_names:
            found.append(
                CallSite(path=relative, line=node.lineno, statement=f"{ast.unparse(func)}(...)")
            )
    return found


def reachability_impact_text(workspace: Workspace, package_name: str) -> str | None:
    """Replaces the blanket "reachability was not assessed" disclaimer with
    what `assess()` actually found — concrete evidence when there is any, or
    `None` to fall back to the original disclaimer when the check could not
    be run at all. Shared by every SCA engine that has a `Workspace` to check
    against (`pip_audit_engine.py`, the PyPI-ecosystem `OsvEngine`) — this is
    the one place that turns a `ReachabilityAssessment` into finding text, so
    the wording stays identical regardless of which advisory source found
    the vulnerable package.
    """
    result = assess(workspace, package_name)
    if result.verdict is ReachabilityVerdict.IMPORTED_AND_CALLED:
        site = result.sites[0]
        call = result.call_sites[0]
        return (
            f"Statically imported: {site.path}:{site.line} ({site.statement}), and "
            f"called: {call.path}:{call.line} ({call.statement}). This confirms the "
            "package is both imported and called by this application's own code; it "
            "does not confirm the specific vulnerable function is the one called — "
            "that deeper, call-graph-level question is not assessed."
        )
    if result.verdict is ReachabilityVerdict.IMPORTED:
        site = result.sites[0]
        return (
            f"Statically imported: {site.path}:{site.line} ({site.statement}). "
            "This confirms the package is imported by this application's own code; "
            "no call to a name from that module was found in the files scanned. It "
            "does not confirm the specific vulnerable function is reached — that "
            "deeper, call-graph-level question is not assessed."
        )
    if result.verdict is ReachabilityVerdict.NOT_FOUND:
        return (
            "No static import of this package was found in the files scanned, which "
            "suggests it may be an unused transitive dependency. This is not proof of "
            "unreachability: a dynamic import, or an import name this check's "
            "distribution-to-module mapping does not cover, would also read this way."
        )
    return None
