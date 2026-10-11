"""Import-level and symbol-usage reachability for Go dependencies — the
same two bounded questions `python_imports.py`/`js_imports.py` answer for
their ecosystems: does any in-scope Go file statically import this module
at all, and, if so, does that same file also *call* something bound by
that import.

**Regex/line-based, not a real parse** — the same reasoning
`js_imports.py`'s own docstring gives: no Go parser is a dependency
anywhere in this Python backend, and adding one for this alone would be
out of proportion. Go's dominant import style is a *grouped block*
(`import (\n\t"fmt"\n\talias "path"\n)`), not single-line, so this module
walks lines with a small amount of block-tracking state rather than a
pure per-line regex — still bounded, still not a real parse.

**Four named limitations, not hidden ones.**

1. **Line-based, not a real parse.** A build-tag-conditional import
   block, or import-like text inside a comment or string, can be missed
   or misread.
2. **The import path's last segment is only a *convention* for a Go
   package's real name, not a guarantee.** Go's own blog states this
   plainly, and names the best-known exception itself:
   `gopkg.in/yaml.v3`'s real package is `yaml`, not `yaml.v3` — a dotted
   version suffix this heuristic does not chase (only the slash-separated
   `/v2`, `/v3` semantic-import-versioning suffix is stripped, since that
   one *is* a defined Go modules rule, not a per-host guess). The
   *import site* is still found correctly either way, since that match is
   on the module path prefix, not the guessed name — but the *call-usage*
   layer, which has to guess the real bound identifier to look for, misses
   the call and degrades `IMPORTED_AND_CALLED` down to plain `IMPORTED`.
   A false negative on the deeper question, the same category as
   `python_imports.py`'s distribution-name-mismatch limitation.
3. **Blank (`import _ "pkg"`) and dot (`import . "pkg"`) imports bind no
   trackable name.** A blank import is genuinely side-effect-only, so
   staying at `IMPORTED` is correct, not a gap. A dot import injects every
   exported name directly into the file's scope — a later bare call
   through one of those names cannot be attributed back to this package,
   a real false negative.
4. **A local variable or parameter that happens to share a bound
   import's name is not distinguished from the real import** — identical
   to every other reachability module's own named limitation, with no
   scope model to tell them apart.
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

_GROUP_START = re.compile(r"^\s*import\s*\(\s*$")
_GROUP_END = re.compile(r"^\s*\)\s*$")
_SINGLE_IMPORT = re.compile(r"^\s*import\s+(.+)$")
_IMPORT_SPEC = re.compile(r'^(?:(\w+|_|\.)\s+)?"([^"]+)"')


def _default_pkg_name(path: str) -> str:
    """The best-effort package name for an import path with no explicit
    alias — the last path segment, with a Go modules `/vN`
    semantic-import-versioning suffix stripped first. See the module
    docstring's second limitation for the known exception class this
    does not cover.
    """
    segments = path.split("/")
    last = segments[-1]
    if re.fullmatch(r"v\d+", last) and len(segments) > 1:
        last = segments[-2]
    return last


def _module_match(path: str, module_path: str) -> bool:
    return path == module_path or path.startswith(module_path + "/")


def assess(workspace: Workspace, module_path: str) -> ReachabilityAssessment:
    """Whether any in-scope Go file statically imports `module_path`, and,
    if so, whether a call to a name bound by that import was also found
    in the same file."""
    if not module_path.strip():
        return ReachabilityAssessment(
            ReachabilityVerdict.NOT_ASSESSED, (), "no module path to resolve"
        )

    go_files = [path for path in workspace.files if path.suffix == ".go"]
    if not go_files:
        return ReachabilityAssessment(ReachabilityVerdict.NOT_ASSESSED, (), "no Go files in scope")

    sites: list[ImportSite] = []
    call_sites: list[CallSite] = []
    for path in go_files[:MAX_FILES_SCANNED]:
        lines = _read_lines(path)
        if lines is None:
            continue
        relative = str(path.relative_to(workspace.root))
        file_sites, bound_names = _import_sites_and_bindings(lines, relative, module_path)
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
        return None


def _import_sites_and_bindings(
    lines: list[str], relative: str, module_path: str
) -> tuple[list[ImportSite], set[str]]:
    sites: list[ImportSite] = []
    bound_names: set[str] = set()
    i, n = 0, len(lines)
    while i < n:
        if _GROUP_START.match(lines[i]):
            i += 1
            while i < n and not _GROUP_END.match(lines[i]):
                _process_import_line(lines[i], i + 1, relative, module_path, sites, bound_names)
                i += 1
            # i now sits on the closing ")" (or ran off the end of the
            # file for a malformed block); the trailing i += 1 below
            # advances past it either way.
        else:
            single = _SINGLE_IMPORT.match(lines[i])
            if single:
                _process_import_line(
                    single.group(1), i + 1, relative, module_path, sites, bound_names
                )
        i += 1
    return sites, bound_names


def _process_import_line(
    content: str,
    lineno: int,
    relative: str,
    module_path: str,
    sites: list[ImportSite],
    bound_names: set[str],
) -> None:
    spec = _IMPORT_SPEC.match(content.strip())
    if not spec:
        return
    alias, path = spec.groups()
    if not _module_match(path, module_path):
        return
    sites.append(ImportSite(path=relative, line=lineno, statement=content.strip()))
    if alias == "_":
        return  # blank import: side-effect only, no bound name
    if alias == ".":
        return  # dot import: no *trackable* bound name — limitation 3
    bound_names.add(alias or _default_pkg_name(path))


def _call_sites_in_file(lines: list[str], relative: str, bound_names: set[str]) -> list[CallSite]:
    # Go packages are never directly callable — only member access.
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(name) for name in bound_names) + r")\.\w+\s*\("
    )
    found: list[CallSite] = []
    for lineno, line in enumerate(lines, start=1):
        if pattern.search(line):
            found.append(CallSite(path=relative, line=lineno, statement=line.strip()))
    return found


def reachability_impact_text(workspace: Workspace, module_path: str) -> str | None:
    """Replaces the blanket "reachability was not assessed" disclaimer
    with what `assess()` actually found. See
    `shapes.impact_text_from_assessment` for the shared wording.
    """
    return impact_text_from_assessment(assess(workspace, module_path))
