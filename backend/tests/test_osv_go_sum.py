"""Parsing a Go `go.sum` file into (module, version) pairs for OSV to
query (`app/core/appsec/osv/go_sum.py`).
"""

from pathlib import Path

from app.core.appsec.osv.go_sum import go_sum_packages


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "go.sum"
    path.write_text(content, encoding="utf-8")
    return path


def test_a_resolved_module_is_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
    )

    assert go_sum_packages(path) == [("github.com/pkg/errors", "v0.9.1")]


def test_the_go_mod_suffix_line_is_deduplicated_with_its_pair(tmp_path: Path) -> None:
    """Every resolved module gets two lines — a full-tree hash and a
    `/go.mod`-suffixed hash — naming the same resolved (module, version).
    Stripping the suffix before dedup means this is one query, not two."""
    path = _write(
        tmp_path,
        "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
        "github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=\n",
    )

    assert go_sum_packages(path) == [("github.com/pkg/errors", "v0.9.1")]


def test_a_pseudo_version_is_passed_through_unchanged(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "golang.org/x/text v0.0.0-20191109021931-daa7c04131f5 h1:abc=\n",
    )

    assert go_sum_packages(path) == [
        ("golang.org/x/text", "v0.0.0-20191109021931-daa7c04131f5")
    ]


def test_a_malformed_line_is_skipped_rather_than_raising(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "this line has too few fields\n"
        "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n",
    )

    assert go_sum_packages(path) == [("github.com/pkg/errors", "v0.9.1")]


def test_an_empty_go_sum_yields_nothing(tmp_path: Path) -> None:
    path = _write(tmp_path, "\n\n")

    assert go_sum_packages(path) == []


def test_a_missing_file_yields_nothing_rather_than_raising(tmp_path: Path) -> None:
    assert go_sum_packages(tmp_path / "does-not-exist.sum") == []
