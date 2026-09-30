"""A real assessment against the demo lab, over real HTTP
(docs/BUILD_SPEC.md §19, §24, §26 Phase 12).

Every other end-to-end test in this suite mocks the transport with respx. This
one does not: the lab runs under uvicorn on a real socket, the scope engine
resolves its hostname through the real resolver, and `GatedTransport` opens a
real connection. It is the only test that exercises the whole path, which is
why §19 says the lab "doubles as the integration-test fixture".

It runs on loopback, which the scope engine blocks by default — so the target's
Rules of Engagement have to list `127.0.0.0/8` (and `::1/128`, since
`localhost` may resolve to either family depending on the host) explicitly.
That is not a workaround: it is the same opt-in an operator makes to scan the
lab on its internal Docker network, and it is worth exercising, because "the
operator deliberately allowed a private range" is a path with real
consequences.

Marked `lab_e2e` so it can be selected on its own (`pytest -m lab_e2e`), which
is what `.github/workflows/lab-e2e.yml` does.
"""

import asyncio
import json
import pathlib
import sys
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.workers.tasks import execute_assessment_run

LAB_ROOT = pathlib.Path(__file__).resolve().parents[2] / "demo-target"
if str(LAB_ROOT) not in sys.path:
    sys.path.insert(0, str(LAB_ROOT))

from lab.collaborator.app import create_app as collaborator_app  # noqa: E402
from lab.content_server.app import CARRIER_MARKER  # noqa: E402
from lab.content_server.app import create_app as content_app  # noqa: E402
from lab.data import FAKE_AWS_KEY  # noqa: E402
from lab.vulnerable_ai_app.app import create_app as vulnerable_app  # noqa: E402

pytestmark = pytest.mark.lab_e2e

# Loopback, and a host name rather than an address: the scope engine matches on
# the hostname and then resolves it, so a test that used a bare IP would skip
# half of what it is meant to exercise.
LAB_HOST = "localhost"
APP_PORT = 8481
CONTENT_PORT = 8482
COLLABORATOR_PORT = 8483


class _Server:
    """A uvicorn server on a real socket, started and stopped per session."""

    def __init__(self, app_factory, port: int) -> None:
        self._config = uvicorn.Config(
            app_factory(), host="127.0.0.1", port=port, log_level="warning"
        )
        self._server = uvicorn.Server(self._config)
        self._task: asyncio.Task[None] | None = None
        self.port = port

    async def start(self) -> None:
        self._task = asyncio.create_task(self._server.serve())
        for _ in range(100):
            if self._server.started:
                return
            await asyncio.sleep(0.05)
        raise RuntimeError(f"lab service on port {self.port} did not start")

    async def stop(self) -> None:
        self._server.should_exit = True
        if self._task is not None:
            await asyncio.wait_for(self._task, timeout=10)


@pytest.fixture(scope="module")
async def lab() -> AsyncGenerator[dict[str, str], None]:
    servers = [
        _Server(vulnerable_app, APP_PORT),
        _Server(content_app, CONTENT_PORT),
        _Server(collaborator_app, COLLABORATOR_PORT),
    ]
    for server in servers:
        await server.start()
    try:
        yield {
            "app": f"http://{LAB_HOST}:{APP_PORT}",
            "content": f"http://{LAB_HOST}:{CONTENT_PORT}",
            "collaborator": f"http://{LAB_HOST}:{COLLABORATOR_PORT}",
        }
    finally:
        for server in servers:
            await server.stop()


LAB_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Kervy Lab", "version": "0.1.0"},
    "paths": {
        "/api/orders/{order_id}": {
            "get": {
                "operationId": "getOrder",
                "security": [{"bearer": []}],
                "parameters": [
                    {
                        "name": "order_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/search": {
            "get": {
                "operationId": "search",
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/api/users": {
            "post": {
                "operationId": "createUser",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "email": {"type": "string"},
                                    "role": {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
}


async def _configure(client: AsyncClient, password: str, base_url: str) -> tuple[str, str, dict]:
    suffix = uuid.uuid4().hex[:8]
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"labowner-{suffix}@example.test",
            "full_name": "Lab Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Lab Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Demo lab",
                "environment": "test",
                "kind": "llm_app",
                "base_url": base_url,
            },
            headers=headers,
        )
    ).json()["id"]

    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    now = datetime.now(UTC)
    roe = await client.put(
        f"{base}/rules-of-engagement",
        json={
            "allowed_domains": [LAB_HOST],
            "excluded_domains": [],
            # The deliberate opt-in. Without it the scope engine refuses every
            # request to the lab, which is the default and the right default.
            # Both families: "localhost" can resolve to either, and the
            # runner's resolution order isn't something this test controls.
            "allowed_ip_ranges": ["127.0.0.0/8", "::1/128"],
            "allowed_paths": [],
            "excluded_paths": [],
            "allowed_methods": ["GET", "POST"],
            "forbidden_headers": [],
            "budgets": {
                "max_requests": 600,
                "max_concurrency": 4,
                "requests_per_second": 200.0,
                "max_tokens_sent": 200000,
                "max_tokens_received": 200000,
                "max_estimated_cost_usd": 5.0,
                "max_wall_clock_minutes": 10,
            },
            "safe_mode": True,
        },
        headers=headers,
    )
    assert roe.status_code in (200, 201), roe.text

    granted = await client.post(
        f"{base}/authorization",
        json={
            "authorized_by_name": "Lab Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "LAB-E2E",
            "valid_from": (now - timedelta(hours=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(),
        },
        headers=headers,
    )
    assert granted.status_code in (200, 201), granted.text

    await client.put(
        f"{base}/adapter",
        json={"adapter_kind": "chat_http", "adapter_config": {"endpoint": "/api/chat"}},
        headers=headers,
    )
    spec = await client.put(
        f"{base}/openapi",
        files={
            "file": (
                "openapi.json",
                json.dumps(LAB_SPEC).encode("utf-8"),
                "application/json",
            )
        },
        headers=headers,
    )
    assert spec.status_code in (200, 201), spec.text

    # The lab's static tokens, supplied the way a real engagement supplies
    # credentials: by environment-variable *name*, never by value in the
    # database. `ord-7001` belongs to globex, which is what makes reading it
    # with the acme token the BOLA finding.
    for label, variable, owned in (
        ("acme_user", "KERVY_LAB_ACME_TOKEN", ["ord-5001"]),
        ("globex_user", "KERVY_LAB_GLOBEX_TOKEN", ["ord-7001"]),
    ):
        account = await client.put(
            f"{base}/accounts/{label}",
            json={
                "label": label,
                "credential_env_var": variable,
                "owned_object_ids": owned,
                "is_privileged": False,
            },
            headers=headers,
        )
        assert account.status_code in (200, 201), account.text

    return org_id, target_id, headers


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "lab-e2e-task"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


async def test_the_lab_is_reachable_over_real_http(lab: dict[str, str]) -> None:
    """Before asserting anything about findings: the lab is actually serving.

    A failure here means the fixture is broken, not the scanner, and telling
    those apart at the top of the file saves an hour.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        for name, url in lab.items():
            response = await client.get(f"{url}/health")
            assert response.status_code == 200, name


async def test_a_real_assessment_against_the_lab_finds_its_seeded_flaws(
    client: AsyncClient, strong_password: str, lab: dict[str, str]
) -> None:
    """The §26 Phase 12 criterion: a real end-to-end assessment, asserted on.

    No respx. The requests below leave the process, cross a socket, and come
    back — through the scope engine, counted against a budget, with evidence
    sealed on the way out.
    """
    org_id, target_id, headers = await _configure(client, strong_password, lab["app"])

    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True, "profile": "full"},
            headers=headers,
        )
    ).json()["id"]

    status = await execute_assessment_run(
        uuid.UUID(run_id), transport=GatedTransport(engine=ScopeEngine())
    )
    assert status.value == "completed", status

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    codes = {item["result_code"] for item in results}

    # The seeded flaws the engines should surface against this lab. Named
    # individually so a regression says which one stopped being found.
    # Not asserted: KERVY-API-001. The lab *does* require authentication on
    # `/api/orders/{id}` — it returns 401 without a token. Its flaw is that it
    # then skips the ownership check, which is BOLA, not missing auth.
    assert "KERVY-API-050" in codes, "BOLA: another tenant's order served to an acme token"
    assert "KERVY-API-010" in codes, "missing security headers"
    assert "KERVY-API-011" in codes, "reflected CORS with credentials"
    assert "KERVY-API-013" in codes, "reachable /.env"
    assert "KERVY-API-020" in codes, "no advertised rate limit"
    assert any(code.startswith("KERVY-AI-0") for code in codes), "no AI finding at all"

    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    assert findings, "the run produced no findings"
    # Nothing the lab leaks should reach a finding unredacted.
    assert FAKE_AWS_KEY not in json.dumps(findings)


async def test_the_run_produces_a_downloadable_sarif_report(
    client: AsyncClient, strong_password: str, lab: dict[str, str]
) -> None:
    """§26 Phase 12 wants `lab-e2e.yml` to upload SARIF, so the shape it uploads
    is asserted here rather than discovered in CI."""
    org_id, target_id, headers = await _configure(client, strong_password, lab["app"])
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]
    await execute_assessment_run(uuid.UUID(run_id), transport=GatedTransport(engine=ScopeEngine()))

    report = await client.get(
        f"/api/v1/organizations/{org_id}/runs/{run_id}/report",
        params={"report_format": "sarif"},
        headers=headers,
    )
    assert report.status_code == 200
    document = json.loads(report.text)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"]


async def test_the_scope_engine_refuses_the_lab_without_the_deliberate_opt_in(
    client: AsyncClient, strong_password: str, lab: dict[str, str]
) -> None:
    """The counterpart to the opt-in above, and the more important half.

    With `allowed_ip_ranges` left empty, every request to the lab is refused
    because loopback is a blocked range. A run in that state must produce no
    findings — not a partial scan, and certainly not a clean bill of health it
    then reports as a pass.
    """
    org_id, target_id, headers = await _configure(client, strong_password, lab["app"])

    base = f"/api/v1/organizations/{org_id}/targets/{target_id}"
    current = (await client.get(f"{base}/rules-of-engagement", headers=headers)).json()
    current["allowed_ip_ranges"] = []
    tightened = await client.put(f"{base}/rules-of-engagement", json=current, headers=headers)
    assert tightened.status_code in (200, 201), tightened.text

    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]
    await execute_assessment_run(uuid.UUID(run_id), transport=GatedTransport(engine=ScopeEngine()))

    results = (
        await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/results", headers=headers)
    ).json()
    # These two read the target's configuration and its specification; neither
    # sends a request, so their presence is not evidence that anything reached
    # the lab. Everything else requires an observation.
    analysis_only = {"KERVY-API-002", "KERVY-API-003", "KERVY-API-030", "KERVY-API-031"}
    observed = [
        item
        for item in results
        if item["severity"] != "INFORMATIONAL" and item["result_code"] not in analysis_only
    ]

    assert observed == [], (
        "the scope engine let requests through to a blocked range: "
        f"{[item['result_code'] for item in observed]}"
    )
    # And nothing carries evidence, because nothing was observed.
    assert all(item["evidence_ref"] is None for item in results)
    # And the run says why it found nothing, rather than looking like a pass.
    assert any("Not tested" in item["title"] for item in results)


async def test_a_carrier_from_the_content_server_reaches_the_assistant(
    lab: dict[str, str],
) -> None:
    """Indirect injection over real HTTP: the carrier is fetched from one
    service and obeyed by another."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        carrier = (await client.get(f"{lab['content']}/carriers/html-comment")).text
        reply = await client.post(f"{lab['app']}/api/chat", json={"message": carrier})

    assert reply.json()["reply"] == CARRIER_MARKER


async def test_the_collaborator_records_an_out_of_band_hit(lab: dict[str, str]) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.delete(f"{lab['collaborator']}/hits")
        await client.get(
            f"{lab['collaborator']}/oob/exfil",
            params={"token": "canary"},  # pragma: allowlist secret
        )
        hits = (await client.get(f"{lab['collaborator']}/hits")).json()

    assert hits["count"] == 1
    assert "canary" in hits["hits"][0]["query"]
