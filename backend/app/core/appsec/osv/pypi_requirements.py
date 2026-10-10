"""Resolved (name, version) pairs from a Python requirements file.

This is the one piece of manifest parsing this engine does itself, rather
than delegating to a tool, for the same reason `npm_lockfile.py` does:
`osv.dev`'s own query shape only needs a name and a resolved version, and a
requirements file carries that for every line that pins one exactly.

**Only an exact pin (`name==version`) is usable.** A range (`name>=1.0`), an
unpinned name, a VCS/URL direct reference (`name @ git+https://...`), or a
local/editable install has no single resolved version to query without
actually running a dependency resolver — which is what `pip-audit` does, via
a real environment, and this direct-to-`osv.dev` path deliberately does not
have. Such lines are skipped, not guessed at: this is a false-negative
source (an unpinned vulnerable package is not reported by this engine), the
same "named, not hidden" limitation `npm_lockfile.py`'s own docstring
states for `link:`/git dependencies, and it is why this engine is a second,
additional source alongside `pip-audit` rather than a replacement for it —
`pip-audit`'s own resolution still covers what this cannot.

Also handled, since real `pip-compile`/`pip freeze --all` output contains
them routinely: inline `#` comments, blank lines, environment markers
(`; python_version >= "3.8"`), extras (`name[extra]==1.2.3`), backslash
line continuations, and `--hash=sha256:...` continuation lines from
`pip-compile --generate-hashes` output. Any line starting with `-` (`-r`,
`-e`, `--index-url`, `--hash=`, etc.) is a pip option, never a requirement,
and is skipped outright.

Package names are normalized per PEP 503 (lowercased, runs of `-`/`_`/`.`
collapsed to a single `-`) before being returned, since `osv.dev`'s PyPI
ecosystem matches on the normalized name, not whatever casing/separator a
requirements file happened to use.
"""

import re
from pathlib import Path

#: A requirements file with more pinned packages than this is not walked
#: further — same bound and reasoning as `npm_lockfile.py`'s `MAX_PACKAGES`.
MAX_PACKAGES = 5000

_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)"  # name
    r"\s*(?:\[[^\]]*\])?\s*"  # optional [extras]
    r"==\s*"
    r"([A-Za-z0-9][A-Za-z0-9._+!-]*)"  # exact version
)


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _strip_comment(line: str) -> str:
    # A `#` is a comment only when it starts the line or is preceded by
    # whitespace — the same rule pip's own requirements parser follows, so
    # a package name containing `#` (none do) is never mistaken for one.
    return re.sub(r"(?:^|\s)#.*$", "", line)


def pypi_requirements_packages(path: Path) -> list[tuple[str, str]]:
    """`[(normalized_name, version), ...]`, deduplicated, for one
    requirements file. Only exactly-pinned lines are returned — see the
    module docstring for what is skipped and why.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    found: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).rstrip("\\").strip()
        if not line or line.startswith("-"):
            continue
        match = _PIN.match(line)
        if not match:
            continue
        name, version = match.groups()
        found.append((_normalize_name(name), version))
        if len(found) >= MAX_PACKAGES:
            break

    return sorted(set(found))
