"""Resolved (`group:artifact`, version) pairs from a Gradle single-file
lockfile (`gradle.lockfile` / `buildscript-gradle.lockfile`).

This is the one piece of manifest parsing this engine does itself, rather
than delegating to a tool, for the same reason `npm_lockfile.py` and
`pypi_requirements.py` do: `osv.dev`'s own query shape only needs a name
and a resolved version, and Gradle's lockfile already carries exactly
that for every dependency `gradle --write-locks` resolved.

Each real line is `group:artifact:version=configuration1,configuration2`
— the configuration list is dropped; this module only needs the GAV
coordinate it locks. Two line shapes carry no coordinate and are skipped:
a leading `#` comment (the generated header, which also warns that manual
edits can break the build), and the `empty=configuration` sentinel line
Gradle writes for a configuration that locked no dependencies at all.

The queried package `name` is `f"{group}:{artifact}"` — `osv.dev`'s own
`Maven` ecosystem package-name convention, matching Maven coordinates.

**Maven's own `pom.xml` is deliberately not parsed by anything in this
codebase.** A `pom.xml` dependency's version is routinely a property
reference (`${some.version}`), inherited from a parent POM, or imported
from a BOM (`<dependencyManagement>`) — none of which resolve to a single
concrete version without actually running Maven's own dependency
resolution, the same class of limitation that already keeps
`pyproject.toml` out of `pypi_requirements.py`'s scope. Gradle's lockfile
is the one JVM-ecosystem manifest format that already carries a
fully-resolved version per line, the same property `go.sum`/`Cargo.lock`/
`package-lock.json` each have for their own ecosystems — so Java/JVM
coverage here is scoped to Gradle projects with lock files enabled, not
every `pom.xml`-based Maven project.
"""

from pathlib import Path

#: A lockfile with more locked coordinates than this is not walked further
#: — same bound and reasoning as `npm_lockfile.py`'s `MAX_PACKAGES`.
MAX_PACKAGES = 5000


def gradle_lockfile_packages(path: Path) -> list[tuple[str, str]]:
    """`[("group:artifact", version), ...]`, deduplicated, for one Gradle
    lockfile."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    found: list[tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        gav, _, _configurations = line.partition("=")
        if gav == "empty":
            continue
        parts = gav.split(":")
        if len(parts) != 3:
            continue
        group, artifact, version = parts
        if not group or not artifact or not version:
            continue
        found.append((f"{group}:{artifact}", version))
        if len(found) >= MAX_PACKAGES:
            break

    return sorted(set(found))
