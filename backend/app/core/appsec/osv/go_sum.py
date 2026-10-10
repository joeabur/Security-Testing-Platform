"""Resolved (module, version) pairs from a Go `go.sum` file.

This is the one piece of manifest parsing this engine does itself, rather
than delegating to a tool, for the same reason `npm_lockfile.py` and
`pypi_requirements.py` do: `osv.dev`'s own query shape only needs a name
and a resolved version, and `go.sum` already carries exactly that for
every module `go build`/`go mod` resolved.

Each real line is three whitespace-separated fields: `<module> <version>
<hash>`. Every resolved module gets **two** lines — one hashing the full
module tree, and one with `/go.mod` appended to the version, hashing only
that module's own `go.mod` file (so the go command can check a dependency
graph without downloading every source tree). Both lines name the same
resolved `(module, version)`, so the `/go.mod` suffix is stripped from the
version field before recording it — the final `sorted(set(...))` then
naturally collapses the pair into one entry rather than querying osv.dev
for the same module twice.

Module names are used exactly as written: Go's module paths are
case-sensitive and matched as-is by `osv.dev`'s `Go` ecosystem, unlike
PyPI's normalized names. A version may be an ordinary semantic version or
a pseudo-version (`v0.0.0-20191109021931-daa7c04131f5`, generated when no
release tag exists) — either is passed through unchanged, since this
module does no version interpretation of its own.
"""

from pathlib import Path

#: A go.sum with more resolved modules than this is not walked further —
#: same bound and reasoning as `npm_lockfile.py`'s `MAX_PACKAGES`.
MAX_PACKAGES = 5000


def go_sum_packages(path: Path) -> list[tuple[str, str]]:
    """`[(module, version), ...]`, deduplicated, for one `go.sum` file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        module, version, _hash = fields
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        found.append((module, version))
        if len(found) >= MAX_PACKAGES:
            break

    return sorted(set(found))
