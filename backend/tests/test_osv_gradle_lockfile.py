"""Parsing a Gradle single-file lockfile into ("group:artifact", version)
pairs for OSV to query (`app/core/appsec/osv/gradle_lockfile.py`).
"""

from pathlib import Path

from app.core.appsec.osv.gradle_lockfile import gradle_lockfile_packages


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "gradle.lockfile"
    path.write_text(content, encoding="utf-8")
    return path


def test_a_locked_coordinate_is_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "org.springframework:spring-beans:5.0.5.RELEASE=compileClasspath,runtimeClasspath\n",
    )

    assert gradle_lockfile_packages(path) == [
        ("org.springframework:spring-beans", "5.0.5.RELEASE")
    ]


def test_the_generated_header_comment_is_skipped(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "# This is a Gradle generated file for dependency locking.\n"
        "# Manual edits can break the build and are not advised.\n"
        "com.google.guava:guava:31.1-jre=compileClasspath\n",
    )

    assert gradle_lockfile_packages(path) == [("com.google.guava:guava", "31.1-jre")]


def test_the_empty_sentinel_line_is_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, "empty=annotationProcessor\n")

    assert gradle_lockfile_packages(path) == []


def test_the_same_coordinate_across_configurations_is_reported_once(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "org.springframework:spring-beans:5.0.5.RELEASE=compileClasspath\n"
        "org.springframework:spring-beans:5.0.5.RELEASE=testCompileClasspath\n",
    )

    assert gradle_lockfile_packages(path) == [
        ("org.springframework:spring-beans", "5.0.5.RELEASE")
    ]


def test_a_malformed_line_is_skipped_rather_than_raising(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "not-a-valid-coordinate\n"
        "com.google.guava:guava:31.1-jre=compileClasspath\n",
    )

    assert gradle_lockfile_packages(path) == [("com.google.guava:guava", "31.1-jre")]


def test_an_empty_lockfile_yields_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path, "\n\n")

    assert gradle_lockfile_packages(path) == []


def test_a_missing_file_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    assert gradle_lockfile_packages(tmp_path / "does-not-exist.lockfile") == []
