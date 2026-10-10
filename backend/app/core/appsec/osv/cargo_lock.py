"""Resolved (name, version) pairs from a Rust `Cargo.lock` file.

This is the one piece of manifest parsing this engine does itself, rather
than delegating to a tool, for the same reason `npm_lockfile.py` and
`pypi_requirements.py` do: `osv.dev`'s own query shape only needs a name
and a resolved version, and `Cargo.lock` already carries exactly that for
every crate `cargo` resolved.

`Cargo.lock` is TOML, parsed with the standard library's `tomllib` —
**no new dependency**, since this project already requires Python ≥3.12
(`backend/pyproject.toml`), well above the 3.11 floor `tomllib` shipped in.

The top-level `package` array of tables carries one entry per resolved
crate: `name`, `version`, and (for anything that isn't the workspace's own
root crate) a `source` string. **Only a crate whose `source` names the
standard crates.io registry is queried.** A crate with no `source` field
at all is the workspace's own root package (or a path dependency within
it) — there is nothing published to match against. A crate sourced from
git or a path dependency, or from an alternate private registry, has no
crates.io-registry identity either, and querying it against `osv.dev`'s
`crates.io` ecosystem under its bare name would risk matching an unrelated
public crate that merely shares the name. This is the same "no single
resolved identity to query" reasoning `pypi_requirements.py` already
applies to unpinned/VCS Python requirements — stated here as a named
limitation, not silently assumed away.
"""

import tomllib
from pathlib import Path
from typing import Any

#: A Cargo.lock with more resolved crates than this is not walked further
#: — same bound and reasoning as `npm_lockfile.py`'s `MAX_PACKAGES`.
MAX_PACKAGES = 5000

_CRATES_IO_SOURCE_PREFIX = "registry+https://github.com/rust-lang/crates.io-index"


def cargo_lock_packages(path: Path) -> list[tuple[str, str]]:
    """`[(name, version), ...]`, deduplicated, for one `Cargo.lock` file.
    Only crates.io-registry-sourced crates are returned — see the module
    docstring for what is skipped and why.
    """
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return []

    packages = document.get("package")
    if not isinstance(packages, list):
        return []

    found: list[tuple[str, str]] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name, version, source = _fields(entry)
        if not name or not version or not source:
            continue
        if not source.startswith(_CRATES_IO_SOURCE_PREFIX):
            continue
        found.append((name, version))
        if len(found) >= MAX_PACKAGES:
            break

    return sorted(set(found))


def _fields(entry: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    name = entry.get("name")
    version = entry.get("version")
    source = entry.get("source")
    return (
        name if isinstance(name, str) else None,
        version if isinstance(version, str) else None,
        source if isinstance(source, str) else None,
    )
