"""Import-level reachability for Python dependencies.

**What this answers, and what it deliberately does not.** Every SCA finding
on this platform has carried the same stated caveat since Phase 14:
"Reachability was not assessed. A vulnerable version being present does
not establish that the affected code path is used by this application."
This module answers the first, bounded half of that question — does any
in-scope Python file *statically import* this package at all — which is
real, checkable evidence: a package nothing imports cannot have its
vulnerable code path exercised by this application, however vulnerable the
package itself is.

It is not the deeper question. *Symbol*-level or call-graph reachability —
tracing from an import through actual call sites down to the specific
vulnerable function, across module boundaries, through decorators and
dynamic dispatch — is a substantially larger project (interprocedural
analysis, a real call graph, data-flow to the vulnerable sink) and is not
attempted here. This is the import-detection layer beneath that, not a
replacement for it, and the finding text says so rather than implying more
than was checked.

**Two further, named limitations, not hidden ones.**

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

Both limitations are why a `NOT_FOUND` verdict is worded as "no static
import was found", never as "this dependency is unreachable" — the first
is what was actually checked.
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
    #: A static import of this package was found in at least one in-scope file.
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
class ReachabilityAssessment:
    verdict: ReachabilityVerdict
    sites: tuple[ImportSite, ...]
    detail: str


def _candidate_import_name(distribution_name: str) -> str:
    normalized = distribution_name.strip().lower()
    override = _IMPORT_NAME_OVERRIDES.get(normalized)
    if override:
        return override
    # PyPI's own convention: a distribution's import name is usually its
    # own name with hyphens and dots folded to underscores.
    return normalized.replace("-", "_").replace(".", "_")


def assess(workspace: Workspace, distribution_name: str) -> ReachabilityAssessment:
    """Whether any in-scope Python file statically imports `distribution_name`."""
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
    for path in python_files[:MAX_FILES_SCANNED]:
        if len(sites) >= MAX_SITES_REPORTED:
            break
        sites.extend(_sites_in_file(path, workspace.root, candidate))

    if sites:
        sites = sites[:MAX_SITES_REPORTED]
        return ReachabilityAssessment(
            ReachabilityVerdict.IMPORTED,
            tuple(sites),
            f"found {len(sites)} static import site(s)",
        )
    return ReachabilityAssessment(
        ReachabilityVerdict.NOT_FOUND, (), "no static import found in the files scanned"
    )


def _sites_in_file(path: Path, root: Path, candidate: str) -> list[ImportSite]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        # A file this engine cannot parse is not evidence either way — it
        # is skipped, the same as a tool-unavailable gap elsewhere in this
        # codebase, rather than treated as a definitive "not imported".
        return []

    found: list[ImportSite] = []
    relative = str(path.relative_to(root))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0].lower() == candidate:
                    found.append(
                        ImportSite(
                            path=relative, line=node.lineno, statement=f"import {alias.name}"
                        )
                    )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
            and node.module.split(".")[0].lower() == candidate
        ):
            names = ", ".join(alias.name for alias in node.names)
            found.append(
                ImportSite(
                    path=relative,
                    line=node.lineno,
                    statement=f"from {node.module} import {names}",
                )
            )
    return found
