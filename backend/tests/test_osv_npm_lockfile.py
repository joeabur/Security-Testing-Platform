"""Parsing an npm lockfile into (name, version) pairs for OSV to query
(`app/core/appsec/osv/npm_lockfile.py`).
"""

import json
from pathlib import Path

from app.core.appsec.osv.npm_lockfile import npm_lockfile_packages


def _write(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_lockfile_v3_packages_map_is_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root-project", "version": "1.0.0"},
                "node_modules/braces": {"version": "3.0.3"},
                "node_modules/chokidar": {"version": "3.6.0"},
            },
        },
    )

    packages = npm_lockfile_packages(path)

    assert ("braces", "3.0.3") in packages
    assert ("chokidar", "3.6.0") in packages
    # The root project itself is not a dependency to query.
    assert not any(name == "root-project" for name, _ in packages)


def test_scoped_packages_keep_their_scope(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/@babel/core": {"version": "7.24.0"}},
        },
    )

    packages = npm_lockfile_packages(path)

    assert packages == [("@babel/core", "7.24.0")]


def test_nested_node_modules_resolves_to_the_inner_package_name(tmp_path: Path) -> None:
    """A version-conflict install path like
    `node_modules/eslint-config-next/node_modules/fast-glob` names the
    *inner* package (`fast-glob`), not the outer one — splitting on the
    last `node_modules/` rather than the first is what gets this right."""
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/eslint-config-next/node_modules/fast-glob": {"version": "2.2.7"}
            },
        },
    )

    packages = npm_lockfile_packages(path)

    assert packages == [("fast-glob", "2.2.7")]


def test_entries_without_a_resolved_version_are_skipped(tmp_path: Path) -> None:
    """A `link: true` workspace reference or a git dependency has no
    registry version OSV could match against."""
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/local-workspace": {"link": True},
                "node_modules/from-git": {"resolved": "git+https://example.test/repo.git"},
                "node_modules/real": {"version": "1.2.3"},
            },
        },
    )

    packages = npm_lockfile_packages(path)

    assert packages == [("real", "1.2.3")]


def test_duplicate_name_and_version_is_reported_once(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/braces": {"version": "3.0.3"},
                "node_modules/foo/node_modules/braces": {"version": "3.0.3"},
            },
        },
    )

    packages = npm_lockfile_packages(path)

    assert packages == [("braces", "3.0.3")]


def test_lockfile_v1_dependency_tree_is_walked_recursively(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 1,
            "dependencies": {
                "braces": {
                    "version": "3.0.3",
                    "dependencies": {"fill-range": {"version": "7.0.1"}},
                }
            },
        },
    )

    packages = npm_lockfile_packages(path)

    assert ("braces", "3.0.3") in packages
    assert ("fill-range", "7.0.1") in packages


def test_a_lockfile_with_neither_shape_yields_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path, {"lockfileVersion": 3})

    assert npm_lockfile_packages(path) == []


def test_malformed_json_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    path = tmp_path / "package-lock.json"
    path.write_text("{not json", encoding="utf-8")

    assert npm_lockfile_packages(path) == []


def test_a_missing_file_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    assert npm_lockfile_packages(tmp_path / "does-not-exist.json") == []


def test_a_non_object_document_yields_nothing(tmp_path: Path) -> None:
    path = tmp_path / "package-lock.json"
    path.write_text("[]", encoding="utf-8")

    assert npm_lockfile_packages(path) == []
