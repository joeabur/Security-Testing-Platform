"""Parsing a Rust `Cargo.lock` file into (name, version) pairs for OSV to
query (`app/core/appsec/osv/cargo_lock.py`).
"""

from pathlib import Path

from app.core.appsec.osv.cargo_lock import cargo_lock_packages

_CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "Cargo.lock"
    path.write_text(content, encoding="utf-8")
    return path


def test_a_crates_io_sourced_package_is_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        f'[[package]]\nname = "serde"\nversion = "1.0.195"\nsource = "{_CRATES_IO}"\n',
    )

    assert cargo_lock_packages(path) == [("serde", "1.0.195")]


def test_the_workspace_root_package_with_no_source_is_skipped(tmp_path: Path) -> None:
    path = _write(tmp_path, '[[package]]\nname = "myapp"\nversion = "0.1.0"\n')

    assert cargo_lock_packages(path) == []


def test_a_git_sourced_package_is_skipped(tmp_path: Path) -> None:
    """No crates.io-registry identity to query — the same "no single
    resolved identity" limitation `pypi_requirements.py` names for VCS
    requirements."""
    path = _write(
        tmp_path,
        '[[package]]\nname = "my-git-dep"\nversion = "0.5.0"\n'
        'source = "git+https://github.com/example/my-git-dep.git#abcdef"\n',
    )

    assert cargo_lock_packages(path) == []


def test_an_alternate_registry_source_is_skipped(tmp_path: Path) -> None:
    """Only the standard crates.io registry source is trusted — a private
    registry's bare package name could collide with an unrelated public
    crate on crates.io."""
    path = _write(
        tmp_path,
        '[[package]]\nname = "internal-lib"\nversion = "2.0.0"\n'
        'source = "registry+https://my-company.example/private-index"\n',
    )

    assert cargo_lock_packages(path) == []


def test_duplicate_name_and_version_is_reported_once(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        f'[[package]]\nname = "serde"\nversion = "1.0.195"\nsource = "{_CRATES_IO}"\n\n'
        f'[[package]]\nname = "serde"\nversion = "1.0.195"\nsource = "{_CRATES_IO}"\n',
    )

    assert cargo_lock_packages(path) == [("serde", "1.0.195")]


def test_a_lockfile_with_no_package_array_yields_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path, "version = 3\n")

    assert cargo_lock_packages(path) == []


def test_malformed_toml_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    path = _write(tmp_path, "this is not [valid toml\n")

    assert cargo_lock_packages(path) == []


def test_a_missing_file_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    assert cargo_lock_packages(tmp_path / "does-not-exist.lock") == []
