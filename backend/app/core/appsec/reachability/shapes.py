"""Language-agnostic reachability shapes, shared by every per-ecosystem
reachability module (`python_imports.py`, `js_imports.py`, and any later
addition). Nothing here is tied to a specific language's import syntax —
each module below only ever deals in paths, line numbers, and statement
text — so this is the one place a `ReachabilityAssessment` is turned into
finding text, keeping the wording identical regardless of which language's
checker or which advisory source found the vulnerable package.
"""

from dataclasses import dataclass
from enum import StrEnum


class ReachabilityVerdict(StrEnum):
    #: A static import of this package was found, and a call to a name
    #: bound by that import was also found in the same file.
    IMPORTED_AND_CALLED = "imported_and_called"
    #: A static import of this package was found in at least one in-scope
    #: file, but no call to a name it bound was found anywhere in scope.
    IMPORTED = "imported"
    #: Source files were scanned and no static import was found.
    NOT_FOUND = "not_found"
    #: Nothing to scan (no source files of this language in scope) or the
    #: package name could not be resolved to a candidate import name at all.
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


def impact_text_from_assessment(result: ReachabilityAssessment) -> str | None:
    """Replaces the blanket "reachability was not assessed" disclaimer with
    what a language-specific `assess()` actually found — concrete evidence
    when there is any, or `None` to fall back to the original disclaimer
    when the check could not be run at all.
    """
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
