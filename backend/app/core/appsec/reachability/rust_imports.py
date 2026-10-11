"""Import-level and symbol-usage reachability for Rust dependencies — the
same two bounded questions `python_imports.py`/`js_imports.py`/
`go_imports.py` answer for their ecosystems, adapted to the one real
structural difference Rust has: a declared dependency's crate root is
always addressable by its fully-qualified path (`serde_json::to_string(x)`
compiles with no `use` statement at all), so "imported" and "called" can
be the same textual event here in a way they never are in Python/JS/Go.

**Regex/line-based, not a real parse** — same reasoning as every sibling
reachability module: no Rust parser is a dependency anywhere in this
Python backend, and adding one for this alone would be out of proportion.

**The crate-name-to-path mapping is deterministic, not a heuristic.**
Cargo's own build rule replaces every hyphen in a package name with an
underscore when generating the name Rust source refers to it by (`serde-
json` in `Cargo.lock` is `serde_json` in a `use` path or a qualified
call) — confirmed from the Rust reference, not assumed. This is why this
module has no Python/Go-style name-mismatch limitation: the mapping
always holds.

**Three named limitations, not hidden ones.**

1. **Line-based, not a real parse.** A multi-line `use` statement, or
   import-like text inside a comment or string, can be missed or
   misread.
2. **A glob import (`use pkg::*;`) binds no specific trackable name
   beyond the crate root itself.** A named item reached only through the
   glob (`foo()` where `foo` came from `pkg::*`) is invisible to the
   call-usage check — a false negative. A direct qualified call
   (`pkg::foo()`) is unaffected, since the crate root is always a seeded
   bound name regardless of any `use` statement.
3. **A local variable or parameter that happens to share a bound name is
   not distinguished from the real import or crate reference** —
   identical to every other reachability module's own named limitation,
   with no scope model to tell them apart.
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

#: Evidence stays readable. Same bound as every sibling reachability
#: module's `MAX_SITES_REPORTED` — per-module tuning, not shared state.
MAX_SITES_REPORTED = 5
#: Bounded so a very large checkout cannot turn one dependency's
#: assessment into an unbounded scan.
MAX_FILES_SCANNED = 5000

_USE_STATEMENT = re.compile(r"^\s*(?:pub\s+)?use\s+(.+?);")
_TOP_LEVEL_AS = re.compile(r"^(.+?)\s+as\s+(\w+)$")
_ITEM_AS = re.compile(r"^(?:[\w:]+::)?(\w+)\s+as\s+(\w+)$")


def _rust_path_name(crate_name: str) -> str:
    """Cargo's own deterministic mapping: hyphens become underscores."""
    return crate_name.replace("-", "_")


def _use_path_bindings(path: str, candidate: str) -> set[str]:
    """What a `use` path (the text between `use` and the trailing `;`)
    binds locally — handles a top-level `as` alias, brace
    destructuring (with per-item `as` and `self`), a trailing glob
    (binds nothing extra — limitation 2), and a plain dotted path."""
    top_alias = _TOP_LEVEL_AS.match(path)
    if top_alias and "{" not in top_alias.group(1):
        return {top_alias.group(2)}

    brace = re.search(r"\{([^}]*)\}", path)
    if brace:
        names: set[str] = set()
        for part in brace.group(1).split(","):
            part = part.strip()
            if not part or part == "*":
                continue
            if part == "self":
                names.add(candidate)
                continue
            item_alias = _ITEM_AS.match(part)
            names.add(item_alias.group(2) if item_alias else part.split("::")[-1])
        return names

    if path.endswith("::*"):
        return set()  # glob import — no trackable specific name, limitation 2

    return {path.split("::")[-1]}


def assess(workspace: Workspace, package_name: str) -> ReachabilityAssessment:
    """Whether any in-scope Rust file statically imports/references
    `package_name`, and, if so, whether a call to a name bound by that
    import (or to the crate root itself, directly) was also found in the
    same file."""
    if not package_name.strip():
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "no package name to resolve"
        )

    candidate = _rust_path_name(package_name)
    rust_files = [path for path in workspace.files if path.suffix == ".rs"]
    if not rust_files:
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "no Rust files in scope"
        )

    sites: list[ImportSite] = []
    call_sites: list[CallSite] = []
    for path in rust_files[:MAX_FILES_SCANNED]:
        lines = _read_lines(path)
        if lines is None:
            continue
        relative = str(path.relative_to(workspace.root))
        file_sites, bound_names = _import_sites_and_bindings(lines, relative, candidate)
        if not file_sites:
            continue
        sites.extend(file_sites)
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
        return None


def _import_sites_and_bindings(
    lines: list[str], relative: str, candidate: str
) -> tuple[list[ImportSite], set[str]]:
    sites: list[ImportSite] = []
    # The crate root is always a valid bound name once declared as a
    # dependency — a fully-qualified call needs no `use` statement at all.
    bound_names: set[str] = {candidate}
    qualified_mention = re.compile(r"\b" + re.escape(candidate) + r"::")

    for lineno, line in enumerate(lines, start=1):
        use_match = _USE_STATEMENT.match(line)
        if use_match:
            path = use_match.group(1).strip()
            if path == candidate or path.startswith(candidate + "::"):
                sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))
                bound_names |= _use_path_bindings(path, candidate)
            continue
        if qualified_mention.search(line):
            sites.append(ImportSite(path=relative, line=lineno, statement=line.strip()))

    return sites, bound_names


def _call_sites_in_file(lines: list[str], relative: str, bound_names: set[str]) -> list[CallSite]:
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(name) for name in bound_names) + r")(?:::\w+|\.\w+)?\s*\("
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
