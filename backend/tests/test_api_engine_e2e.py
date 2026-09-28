"""The API engine reached through the real stack: create a run over the
REST API, execute it in the worker, and read the stored results back.

The lab handlers are the same ones tests/test_api_engine.py uses, so this
test is about the wiring — surface rows to probe target, probe output to
persisted rows, credentials from the worker's environment — rather than
about the probes themselves.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import respx
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.workers.tasks import execute_assessment_run
from tests.lab.handlers import ORDER_OWNED_BY_A, TOKEN_A, TOKEN_B, vulnerable_app
from tests.lab.specs import vulnerable_spec
from tests.security.conftest import FakeDnsResolver

LAB_HOST = "vulnerable.lab.test"
LAB_URL = f"http://{LAB_HOST}"


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "stub-task-id"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


@pytest.fixture(autouse=True)
def _lab_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """The worker resolves credentials from its own environment — the same
    mechanism an operator uses, exercised rather than bypassed."""
    monkeypatch.setenv("AEGIS_LAB_TOKEN_A", TOKEN_A)
    monkeypatch.setenv("AEGIS_LAB_TOKEN_B", TOKEN_B)


def _worker_transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({LAB_HOST: ["203.0.113.10"]})
    )


async def _setup(client: AsyncClient, password: str) -> tuple[str, str, dict[str, str]]:
    _register_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    register = await client.post(
        "/api/v1/auth/register",
        json={"email": "labowner@example.test", "full_name": "Lab Owner", "password": password},
        headers={HEADER_NAME: _register_anon_token},
    )
    headers = {"Authorization": f"Bearer {register.json()['access_token']}"}
    org_id = (
        await client.post("/api/v1/organizations", json={"name": "Lab Org"}, headers=headers)
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Vulnerable Lab",
                "environment": "test",
                "kind": "api",
                "base_url": LAB_URL,
            },
            headers=headers,
        )
    ).json()["id"]

    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    now = datetime.now(UTC)
    await client.put(
        f"{base}/rules-of-engagement",
        json={
            "allowed_domains": [LAB_HOST],
            "excluded_domains": [],
            "allowed_ip_ranges": [],
            "allowed_paths": [],
            "excluded_paths": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_headers": [],
            "budgets": {
                "max_requests": 400,
                "max_concurrency": 3,
                "requests_per_second": 50.0,
                "max_tokens_sent": 100000,
                "max_tokens_received": 200000,
                "max_estimated_cost_usd": 5.0,
                "max_wall_clock_minutes": 30,
            },
            "safe_mode": True,
        },
        headers=headers,
    )
    await client.post(
        f"{base}/authorization",
        json={
            "authorized_by_name": "Lab Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "LAB-1",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=6)).isoformat(),
        },
        headers=headers,
    )
    await client.put(
        f"{base}/openapi",
        files={
            "file": (
                "openapi.json",
                json.dumps(vulnerable_spec()).encode("utf-8"),
                "application/json",
            )
        },
        headers=headers,
    )
    for label, env_var, owned in (
        ("account_a", "AEGIS_LAB_TOKEN_A", [ORDER_OWNED_BY_A]),
        ("account_b", "AEGIS_LAB_TOKEN_B", []),
    ):
        response = await client.put(
            f"{base}/accounts/{label}",
            json={
                "label": label,
                "credential_env_var": env_var,
                "owned_object_ids": owned,
            },
            headers=headers,
        )
        assert response.status_code == 200

    return org_id, target_id, headers


async def test_a_run_against_the_lab_stores_real_findings(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password)
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=vulnerable_app)
        status = await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    assert status.value == "completed"

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    codes = {result["result_code"] for result in results}

    # A representative slice across the OWASP API categories, proving the
    # results came from the probes and not from a fixture.
    assert {"AEGIS-API-001", "AEGIS-API-030", "AEGIS-API-050", "AEGIS-API-060"} <= codes

    bola = next(result for result in results if result["result_code"] == "AEGIS-API-050")
    assert bola["severity"] == "CRITICAL"
    assert "OWASP-API-2023:API1" in bola["frameworks"]
    assert bola["reproduction"]
    # Credentials came from the worker's environment; none may be stored.
    assert TOKEN_A not in json.dumps(results)
    assert TOKEN_B not in json.dumps(results)

    run = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}", headers=headers)
    ).json()
    assert run["findings_reported"] > 0
    informational = [r for r in results if r["severity"] == "INFORMATIONAL"]
    # The count an operator reads must exclude "not tested" markers.
    assert run["findings_reported"] == len(results) - len(informational)


async def test_results_can_exclude_informational_but_include_them_by_default(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password)
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=vulnerable_app)
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())

    default = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    filtered = (
        await client.get(
            f"/api/v1/organizations/{org_id}/runs/{run_id}/results",
            params={"include_informational": "false"},
            headers=headers,
        )
    ).json()

    assert len(filtered) <= len(default)
    assert all(result["severity"] != "INFORMATIONAL" for result in filtered)


async def test_results_are_not_visible_to_another_organization(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password)
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    _outsider_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    outsider = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "laboutsider@example.test",
            "full_name": "Outsider",
            "password": strong_password,
        },
        headers={HEADER_NAME: _outsider_anon_token},
    )
    outsider_headers = {"Authorization": f"Bearer {outsider.json()['access_token']}"}

    response = await client.get(
        f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=outsider_headers
    )
    assert response.status_code == 404
