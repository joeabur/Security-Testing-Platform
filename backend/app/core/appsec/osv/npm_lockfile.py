"""Resolved (name, version) pairs from an npm lockfile.

This is the one piece of manifest parsing this engine does itself, rather
than delegating to a tool, because the package it feeds — `osv.dev`'s own
query shape — only needs a name and a resolved version, and npm's lockfile
already carries exactly that for every package it installed.

Two lockfile shapes are handled, both real and both still produced by
supported npm versions:

* **`lockfileVersion` 2 or 3** — a flat `packages` map keyed by install path
  (`"node_modules/foo"`, or nested as `"node_modules/foo/node_modules/bar"`
  for a version conflict). The name is read from the key, not from
  `packages[key].name`, because scoped packages (`@scope/name`) and nested
  installs make the two disagree in exactly the cases that matter.
* **`lockfileVersion` 1** — a recursive `dependencies` tree, each entry
  keyed by name with its own nested `dependencies`.

A lockfile missing both keys (a malformed or pre-v1 file) yields no
packages rather than raising — the engine then has nothing to query, which
is the same "narrowed coverage, stated plainly" outcome every other
manifest gap in this codebase produces.
"""

import json
from pathlib import Path
from typing import Any

#: A lockfile with more resolved packages than this is not walked further.
#: Bounded so a pathological or hostile lockfile cannot turn parsing into an
#: unbounded loop — no real project's lockfile approaches this.
MAX_PACKAGES = 5000


def _from_packages_map(packages: dict[str, Any]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            # "" is the project's own root entry, not a dependency.
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            # A `link: true` workspace reference or a git/local dependency
            # with no resolved registry version — nothing OSV can match.
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        if not name:
            continue
        found.append((name, version))
        if len(found) >= MAX_PACKAGES:
            break
    return found


def _from_dependencies_tree(dependencies: dict[str, Any]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []

    def walk(tree: dict[str, Any]) -> None:
        for name, entry in tree.items():
            if len(found) >= MAX_PACKAGES:
                return
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and version:
                found.append((name, version))
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)

    walk(dependencies)
    return found[:MAX_PACKAGES]


def npm_lockfile_packages(path: Path) -> list[tuple[str, str]]:
    """`[(name, resolved_version), ...]`, deduplicated, for one lockfile.

    Deduplicated rather than left as one entry per install path: a package
    pinned at the same version in both the top level and a nested
    `node_modules` is one OSV query, not two, and the batch endpoint should
    not be billed twice for it.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(document, dict):
        return []

    packages = document.get("packages")
    if isinstance(packages, dict):
        found = _from_packages_map(packages)
    else:
        dependencies = document.get("dependencies")
        found = _from_dependencies_tree(dependencies) if isinstance(dependencies, dict) else []

    return sorted(set(found))
