"""A run against a repository target, end to end through the worker.

Uses a local `file:` repository built from the vulnerable lab fixture, so
the clone path, the scope resolution, the engines, the persistence and the
checkout cleanup are all the real ones.
"""

import subprocess
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.workers.tasks import execute_assessment_run

FIXTURE = Path(__file__).parent / "lab" / "repos" / "vulnerable"

ROE = {
    "allowed_domains": ["ai.example.test"],
    "excluded_domains": [],
    "allowed_ip_ranges": [],
    "allowed_paths": [],
    "excluded_paths": [],
    "allowed_methods": ["GET", "POST"],
    "forbidden_headers": [],
    "budgets": {
        "max_requests": 50,
        "max_concurrency": 2,
        "requests_per_second": 5.0,
        "max_tokens_sent": 10000,
        "max_tokens_received": 10000,
        "max_estimated_cost_usd": 1.0,
        "max_wall_clock_minutes": 10,
    },
    "safe_mode": True,
}


def _checkout_dirs() -> set[Path]:
    return set(Path(tempfile.gettempdir()).glob("kervy-checkout-*"))


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "stub-task-id"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


@pytest.fixture
def local_origin(tmp_path: Path) -> Path:
    """A git repository built from the vulnerable fixture."""
    origin = tmp_path / "origin"
    subprocess.run(["cp", "-r", str(FIXTURE), str(origin)], check=True)
    for command in (
        ["git", "init", "--quiet", "-b", "main"],
        ["git", "config", "user.email", "lab@example.test"],
        ["git", "config", "user.name", "Lab"],
        ["git", "add", "."],
        ["git", "commit", "--quiet", "-m", "fixture"],
    ):
        subprocess.run(command, cwd=origin, check=True, capture_output=True)
    return origin


async def _setup(
    client: AsyncClient, password: str, repo_ref: str, *, hosts: list[str] | None = None
) -> tuple[str, str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={"email": "scanowner@example.test", "full_name": "Scan Owner", "password": password},
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post("/api/v1/organizations", json={"name": "Scan Org"}, headers=headers)
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "App repository",
                "environment": "staging",
                "kind": "api",
                "base_url": "https://ai.example.test",
            },
            headers=headers,
        )
    ).json()["id"]

    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    now = datetime.now(UTC)
    await client.put(f"{base}/rules-of-engagement", json=ROE, headers=headers)
    await client.post(
        f"{base}/authorization",
        json={
            "authorized_by_name": "Scan Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "SCAN-1",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=6)).isoformat(),
        },
        headers=headers,
    )
    response = await client.put(
        f"{base}/code",
        json={
            "repo_ref": repo_ref,
            "languages": ["python"],
            "build_manifest_paths": ["requirements.txt"],
            "code_scope": {
                "allowed_paths": ["src/**", "infra/**", "requirements.txt"],
                "excluded_paths": [],
                "allowed_repo_hosts": hosts if hosts is not None else [],
            },
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return org_id, target_id, headers


async def _run(client: AsyncClient, org_id: str, target_id: str, headers: dict[str, str]) -> str:
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]
    await execute_assessment_run(uuid.UUID(run_id))
    return run_id


async def test_a_run_clones_scans_and_stores_code_findings(
    client: AsyncClient, strong_password: str, local_origin: Path
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, f"file://{local_origin}")
    run_id = await _run(client, org_id, target_id, headers)

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    codes = {result["result_code"] for result in results}

    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    assert {"KERVY-SAST-B602", "KERVY-SECRET-AWS_ACCESS_KEY_ID", "KERVY-IAC-CKV_AWS_20"} <= codes, (
        run["halted_reason"],
        run["checks_completed"],
        run["checks_total"],
        sorted(codes),
    )
    # The committed key is reported without its value, all the way through
    # the worker, the database and the API.
    assert "AKIAIOSFODNN7EXAMPLE" not in str(results)

    secret = next(r for r in results if r["result_code"] == "KERVY-SECRET-AWS_ACCESS_KEY_ID")
    assert secret["fingerprint"].startswith("sha256:")


async def test_the_checkout_is_removed_when_the_run_finishes(
    client: AsyncClient, strong_password: str, local_origin: Path
) -> None:
    """A working copy of a client's repository is what must not be left on a
    worker — it is the material the secret scan just found credentials in."""
    before = _checkout_dirs()

    org_id, target_id, headers = await _setup(client, strong_password, f"file://{local_origin}")
    await _run(client, org_id, target_id, headers)

    assert _checkout_dirs() == before


async def test_a_repository_host_that_is_not_allowlisted_skips_code_scanning(
    client: AsyncClient, strong_password: str
) -> None:
    """The run still completes — the other engines are unaffected — and the
    event log says why the code engines did not run, rather than the report
    silently omitting the pillar."""
    org_id, target_id, headers = await _setup(
        client, strong_password, "https://evil.test/example/app.git", hosts=["github.com"]
    )
    run_id = await _run(client, org_id, target_id, headers)

    events = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/events", headers=headers)
    ).json()
    skipped = [e for e in events if "Code scanning skipped" in e["message"]]

    assert skipped, [e["message"] for e in events]
    assert "allowed_repo_hosts" in skipped[0]["message"]

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    assert not [r for r in results if r["probe_id"].startswith("appsec.")]
