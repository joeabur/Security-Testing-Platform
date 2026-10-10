"""Parsing a Python requirements file into (name, version) pairs for OSV
to query (`app/core/appsec/osv/pypi_requirements.py`).
"""

from pathlib import Path

from app.core.appsec.osv.pypi_requirements import pypi_requirements_packages


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(content, encoding="utf-8")
    return path


def test_an_exact_pin_is_parsed(tmp_path: Path) -> None:
    path = _write(tmp_path, "requests==2.31.0\n")

    assert pypi_requirements_packages(path) == [("requests", "2.31.0")]


def test_extras_are_stripped_from_the_name(tmp_path: Path) -> None:
    path = _write(tmp_path, "Flask[async]==3.0.0\n")

    assert pypi_requirements_packages(path) == [("flask", "3.0.0")]


def test_an_environment_marker_does_not_break_the_pin(tmp_path: Path) -> None:
    path = _write(tmp_path, 'requests==2.31.0 ; python_version >= "3.8"\n')

    assert pypi_requirements_packages(path) == [("requests", "2.31.0")]


def test_an_inline_comment_is_stripped(tmp_path: Path) -> None:
    path = _write(tmp_path, "requests==2.31.0  # pinned for CVE reasons\n")

    assert pypi_requirements_packages(path) == [("requests", "2.31.0")]


def test_a_whole_line_comment_is_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, "# this is a comment\nrequests==2.31.0\n")

    assert pypi_requirements_packages(path) == [("requests", "2.31.0")]


def test_a_hash_continuation_line_is_skipped(tmp_path: Path) -> None:
    """`pip-compile --generate-hashes` output: the pin line ends with a
    backslash continuation, and each `--hash=...` line that follows is a
    pip option, not a second requirement."""
    path = _write(
        tmp_path,
        "certifi==2024.2.2 \\\n"
        "    --hash=sha256:abc123 \\\n"
        "    --hash=sha256:def456\n",
    )

    assert pypi_requirements_packages(path) == [("certifi", "2024.2.2")]


def test_an_editable_install_is_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, "-e .\nrequests==2.31.0\n")

    assert pypi_requirements_packages(path) == [("requests", "2.31.0")]


def test_an_include_directive_is_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, "-r other.txt\nrequests==2.31.0\n")

    assert pypi_requirements_packages(path) == [("requests", "2.31.0")]


def test_a_vcs_direct_reference_is_skipped(tmp_path: Path) -> None:
    """No `==` pin, and no resolver here to turn a git ref into a resolved
    version — this is the named limitation, not a crash."""
    path = _write(tmp_path, "django @ git+https://github.com/django/django.git\n")

    assert pypi_requirements_packages(path) == []


def test_an_unpinned_range_is_skipped(tmp_path: Path) -> None:
    """A range has no single resolved version to query without an actual
    resolver, which this direct-to-osv.dev path does not have."""
    path = _write(tmp_path, "numpy>=1.20,<2.0\n")

    assert pypi_requirements_packages(path) == []


def test_name_normalization_collapses_case_and_separators(tmp_path: Path) -> None:
    """osv.dev's PyPI ecosystem matches on the PEP 503 normalized name, not
    whatever casing/separator a requirements file happened to use."""
    path = _write(tmp_path, "Django_Rest.Framework==3.14.0\n")

    assert pypi_requirements_packages(path) == [("django-rest-framework", "3.14.0")]


def test_duplicate_name_and_version_is_reported_once(tmp_path: Path) -> None:
    path = _write(tmp_path, "Django==4.2.0\ndjango==4.2.0\n")

    assert pypi_requirements_packages(path) == [("django", "4.2.0")]


def test_a_blank_requirements_file_yields_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path, "\n\n")

    assert pypi_requirements_packages(path) == []


def test_a_missing_file_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    assert pypi_requirements_packages(tmp_path / "does-not-exist.txt") == []
