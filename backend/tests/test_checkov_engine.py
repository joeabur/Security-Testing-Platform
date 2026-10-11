"""`CheckovEngine` had no dedicated test file: its only coverage anywhere in
the suite was `test_appsec_engines.py` asserting that it ran and produced
`ok` results against the main lab repo, never what it actually finds.

That gap is why `docs/supply-chain.md` and `docs/roadmap.md` both carried a
stale claim ("a floating base image tag is not reported") that a direct,
live run of `checkov` against a one-line Dockerfile disproves: Checkov's own
built-in `CKV_DOCKER_7` ("Ensure the base image uses a non latest version
tag") already fires for `FROM python:latest` and for a bare `FROM python`,
and is already surfaced end-to-end through `CheckovEngine.parse()` as
`KERVY-IAC-CKV_DOCKER_7` — nothing needed building, the claim just needed
checking. These tests are the regression proof, so the next person does not
have to re-discover this by hand.
"""

from pathlib import Path

from app.core.appsec.iac.checkov_engine import CheckovEngine
from app.core.appsec.workspace import CodeScope, resolve_workspace
from app.core.probes.models import Confidence, ScanResult, Severity


def _workspace(tmp_path: Path, dockerfile: str):
    (tmp_path / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    return resolve_workspace(tmp_path, CodeScope(allowed_paths=("Dockerfile",)))


def _ids(results: list[ScanResult]) -> set[str]:
    return {result.id for result in results}


async def test_a_floating_latest_tag_is_reported(tmp_path: Path) -> None:
    """The exact claim `docs/supply-chain.md` made and this disproves."""
    results = await CheckovEngine().run(_workspace(tmp_path, "FROM python:latest\n"))
    assert "KERVY-IAC-CKV_DOCKER_7" in _ids(results)


async def test_a_bare_from_with_no_tag_is_also_reported(tmp_path: Path) -> None:
    """Docker itself treats a bare `FROM python` as `FROM python:latest` —
    just as floating, and Checkov's own check treats it the same way."""
    results = await CheckovEngine().run(_workspace(tmp_path, "FROM python\n"))
    assert "KERVY-IAC-CKV_DOCKER_7" in _ids(results)


async def test_a_pinned_version_tag_is_not_reported(tmp_path: Path) -> None:
    results = await CheckovEngine().run(_workspace(tmp_path, "FROM python:3.12-slim\n"))
    assert "KERVY-IAC-CKV_DOCKER_7" not in _ids(results)


async def test_a_digest_pin_is_not_reported_as_floating(tmp_path: Path) -> None:
    """A digest pin is the opposite of floating — fully reproducible — and
    `docs/supply-chain.md` must not claim this case is a gap either."""
    results = await CheckovEngine().run(_workspace(tmp_path, f"FROM python@sha256:{'1' * 64}\n"))
    assert "KERVY-IAC-CKV_DOCKER_7" not in _ids(results)


def test_a_dockerfile_only_check_normalizes_without_a_severity_or_code_block(
    tmp_path: Path,
) -> None:
    """`CKV_DOCKER_7`'s own payload shape, captured live: no `severity`, and
    `code_block` is `null` rather than a list — both handled, not assumed."""
    payload = {
        "check_type": "dockerfile",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_7",
                    "check_name": "Ensure the base image uses a non latest version tag",
                    "code_block": None,
                    "file_path": "/Dockerfile",
                    "file_line_range": [1, 1],
                    "resource": "/Dockerfile.FROM",
                    "severity": None,
                    "guideline": None,
                }
            ]
        },
    }
    (tmp_path / "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("Dockerfile",)))

    results = CheckovEngine().parse(payload, workspace)

    assert [result.id for result in results] == ["KERVY-IAC-CKV_DOCKER_7"]
    finding = results[0]
    assert finding.endpoint == "Dockerfile:1"
    # No severity data from checkov's free tier falls back to the engine's
    # own documented default rather than crashing on `None`.
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.HIGH


def test_a_finding_outside_the_code_scope_is_dropped(tmp_path: Path) -> None:
    """Checkov is pointed at the whole workspace root, so it can see a file
    the code scope excluded — dropping that result is what keeps the scope
    boundary authoritative even when the tool itself does not honour it."""
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_7",
                    "check_name": "Ensure the base image uses a non latest version tag",
                    "file_path": "/outside/Dockerfile",
                    "resource": "/outside/Dockerfile.FROM",
                }
            ]
        }
    }
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("Dockerfile",)))

    assert CheckovEngine().parse(payload, workspace) == []
