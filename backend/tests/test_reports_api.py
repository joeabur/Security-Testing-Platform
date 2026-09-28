"""Report and evidence download through the real stack (docs/BUILD_SPEC.md
§13, §14, and §26 Phase 8's "reports downloadable and access-controlled").

The run here is a real one against the AI lab fixture, so what is downloaded
is a report over findings the engine actually produced and evidence a probe
actually observed — not a hand-built document that happens to render.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import respx
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.models.audit import AuditEvent
from app.workers.tasks import execute_assessment_run
from tests.lab.ai_handlers import vulnerable_chat
from tests.security.conftest import FakeDnsResolver

LAB_HOST = "report-lab.test"
LAB_URL = f"https://{LAB_HOST}"


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    class _AsyncResult:
        id = "stub-task-id"

    from app.core.runs import service as runs_service

    monkeypatch.setattr(runs_service.celery_app, "send_task", lambda *a, **k: _AsyncResult())


def _worker_transport() -> GatedTransport:
    return GatedTransport(
        engine=ScopeEngine(), dns_resolver=FakeDnsResolver({LAB_HOST: ["203.0.113.30"]})
    )


async def _setup(
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"repowner{suffix}@example.test",
            "full_name": "Report Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Report Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Reported assistant",
                "environment": "staging",
                "kind": "llm_app",
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
            "excluded_domains": ["payments.example.test"],
            "allowed_ip_ranges": [],
            "allowed_paths": [],
            "excluded_paths": ["/admin"],
            "allowed_methods": ["GET", "POST"],
            "forbidden_headers": [],
            "budgets": {
                "max_requests": 400,
                "max_concurrency": 2,
                "requests_per_second": 50.0,
                "max_tokens_sent": 100000,
                "max_tokens_received": 100000,
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
            "authorized_by_name": "Report Owner",
            "authorized_by_role": "CISO",
            "authorized_by_email": "ciso@example.test",
            "reference": "REP-7",
            "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=6)).isoformat(),
        },
        headers=headers,
    )
    await client.put(
        f"{base}/adapter",
        json={"adapter_kind": "chat_http", "adapter_config": {"endpoint": "/api/chat"}},
        headers=headers,
    )
    return org_id, target_id, headers


async def _run(client: AsyncClient, org_id: str, target_id: str, headers: dict[str, str]) -> str:
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]
    with respx.mock(assert_all_called=False) as router:
        router.route(host=LAB_HOST).mock(side_effect=vulnerable_chat)
        await execute_assessment_run(uuid.UUID(run_id), transport=_worker_transport())
    return run_id


# --- reports -------------------------------------------------------------


async def test_a_report_is_downloadable_in_every_format(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "a")
    run_id = await _run(client, org_id, target_id, headers)
    base = f"/api/v1/organizations/{org_id}/runs/{run_id}/report"

    markdown = await client.get(f"{base}?report_format=markdown", headers=headers)
    assert markdown.status_code == 200
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert "attachment" in markdown.headers["content-disposition"]
    assert "REP-7" in markdown.text

    canonical = await client.get(f"{base}?report_format=json", headers=headers)
    assert canonical.status_code == 200
    payload = json.loads(canonical.text)
    assert payload["schema"] == "aegis.report/v1"
    assert payload["authorization"]["reference"] == "REP-7"
    assert payload["findings"]

    sarif = await client.get(f"{base}?report_format=sarif", headers=headers)
    assert sarif.headers["content-type"].startswith("application/sarif+json")
    assert json.loads(sarif.text)["version"] == "2.1.0"

    for fmt, prefix in [("html", "text/html"), ("csv", "text/csv"), ("pdf", "application/pdf")]:
        response = await client.get(f"{base}?report_format={fmt}", headers=headers)
        assert response.status_code in {200, 501}, fmt
        if response.status_code == 200:
            assert response.headers["content-type"].startswith(prefix)


async def test_the_report_carries_the_digests_pinned_at_run_start(
    client: AsyncClient, strong_password: str
) -> None:
    """The record of what was permitted has to be the version the run used,
    not whatever the target says today."""
    org_id, target_id, headers = await _setup(client, strong_password, "b")
    run_id = await _run(client, org_id, target_id, headers)

    payload = json.loads(
        (
            await client.get(
                f"/api/v1/organizations/{org_id}/runs/{run_id}/report?report_format=json",
                headers=headers,
            )
        ).text
    )
    assert payload["authorization"]["digest"].startswith("sha256:")
    assert payload["authorization"]["roe_digest"].startswith("sha256:")
    assert payload["authorization"]["excluded_domains"] == ["payments.example.test"]
    assert payload["methodology"]["decision_rule"]
    assert payload["coverage"]["not_tested"]


async def test_every_template_renders_for_a_real_run(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "c")
    run_id = await _run(client, org_id, target_id, headers)
    base = f"/api/v1/organizations/{org_id}/runs/{run_id}/report"

    for template in ("technical", "executive", "developer", "compliance"):
        response = await client.get(f"{base}?template={template}", headers=headers)
        assert response.status_code == 200, template
        assert "REP-7" in response.text, template
    executive = await client.get(f"{base}?template=executive", headers=headers)
    assert "AEGIS-AI-" not in executive.text


async def test_a_report_is_refused_before_the_run_has_executed(
    client: AsyncClient, strong_password: str
) -> None:
    """A document full of zeroes from a queued run reads like a clean result."""
    org_id, target_id, headers = await _setup(client, strong_password, "d")
    run_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/runs",
            json={"target_id": target_id, "authorization_confirmed": True},
            headers=headers,
        )
    ).json()["id"]

    response = await client.get(
        f"/api/v1/organizations/{org_id}/runs/{run_id}/report", headers=headers
    )
    assert response.status_code == 409
    assert "nothing to report" in response.json()["error"]["message"]


async def test_a_report_download_is_audited(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "e")
    run_id = await _run(client, org_id, target_id, headers)
    await client.get(
        f"/api/v1/organizations/{org_id}/runs/{run_id}/report?report_format=csv", headers=headers
    )

    events = (
        (await db_session.execute(select(AuditEvent).where(AuditEvent.action == "report.download")))
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].metadata_json["format"] == "csv"
    assert events[0].resource_id == run_id


async def test_another_organizations_member_cannot_reach_the_report(
    client: AsyncClient, strong_password: str
) -> None:
    """Not 403 — 404. A stranger has no business learning the run exists."""
    org_id, target_id, headers = await _setup(client, strong_password, "f")
    run_id = await _run(client, org_id, target_id, headers)
    _, _, outsider = await _setup(client, strong_password, "g")

    response = await client.get(
        f"/api/v1/organizations/{org_id}/runs/{run_id}/report", headers=outsider
    )
    assert response.status_code == 404


async def test_an_anonymous_caller_gets_nothing(client: AsyncClient, strong_password: str) -> None:
    """§13: no public report or evidence URLs by default."""
    org_id, target_id, headers = await _setup(client, strong_password, "h")
    run_id = await _run(client, org_id, target_id, headers)

    # Registering set a session cookie on the shared client. Clearing it is
    # what makes the next three requests genuinely unauthenticated — without
    # this the test would pass on the cookie and prove nothing.
    client.cookies.clear()

    for path in ("report", "evidence", "evidence/verify"):
        response = await client.get(f"/api/v1/organizations/{org_id}/runs/{run_id}/{path}")
        assert response.status_code == 401, path


# --- evidence ------------------------------------------------------------


async def test_the_run_wrote_verifiable_evidence_a_member_can_download(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "i")
    run_id = await _run(client, org_id, target_id, headers)
    base = f"/api/v1/organizations/{org_id}/runs/{run_id}/evidence"

    manifest = (await client.get(base, headers=headers)).json()
    assert manifest, "the run produced findings but stored no evidence"
    assert manifest[0]["previous"] == "sha256:" + "0" * 64
    assert all(entry["digest"].startswith("sha256:") for entry in manifest)

    verification = (await client.get(f"{base}/verify", headers=headers)).json()
    assert verification == {"ok": True, "entries": len(manifest), "problems": []}

    # Both engines write evidence now, so the manifest mixes API-probe
    # exchanges with AI-probe turns. Every entry has to be downloadable, and
    # none of them may carry the credential the lab discloses.
    bodies = []
    for entry in manifest:
        bundle = await client.get(f"{base}/{entry['digest']}", headers=headers)
        assert bundle.status_code == 200, entry["digest"]
        body = json.loads(bundle.text)
        assert body["probe_id"] == entry["probe_id"]
        assert body["request"]["method"]
        assert "sk-proj-" not in bundle.text
        bodies.append(body)

    # The marker-based ones carry this run's canary, which is what makes their
    # detection checkable rather than asserted.
    assert [body for body in bodies if body["canaries"]]


async def test_a_finding_points_at_the_evidence_that_supports_it(
    client: AsyncClient, strong_password: str
) -> None:
    """A report that cites evidence has to cite evidence that exists."""
    org_id, target_id, headers = await _setup(client, strong_password, "j")
    run_id = await _run(client, org_id, target_id, headers)

    findings = (
        await client.get(f"/api/v1/organizations/{org_id}/findings", headers=headers)
    ).json()
    referenced = [f["evidence_ref"] for f in findings if f["evidence_ref"]]
    assert referenced, "no finding carried an evidence reference"

    for digest in set(referenced):
        response = await client.get(
            f"/api/v1/organizations/{org_id}/runs/{run_id}/evidence/{digest}", headers=headers
        )
        assert response.status_code == 200, digest


async def test_an_evidence_download_is_audited(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, "k")
    run_id = await _run(client, org_id, target_id, headers)
    base = f"/api/v1/organizations/{org_id}/runs/{run_id}/evidence"
    digest = (await client.get(base, headers=headers)).json()[0]["digest"]

    await client.get(f"{base}/{digest}", headers=headers)

    events = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.action == "evidence.download")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].resource_id == digest


async def test_a_digest_that_is_not_a_digest_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    """Nothing that could climb out of the bundles directory reaches the
    filesystem, whatever the store would have done with it."""
    org_id, target_id, headers = await _setup(client, strong_password, "l")
    run_id = await _run(client, org_id, target_id, headers)
    base = f"/api/v1/organizations/{org_id}/runs/{run_id}/evidence"

    for bad in ("..%2f..%2fmanifest", "sha256:zzzz", "not-a-digest"):
        response = await client.get(f"{base}/{bad}", headers=headers)
        assert response.status_code in {404, 422}, bad

    missing = "sha256:" + "f" * 64
    assert (await client.get(f"{base}/{missing}", headers=headers)).status_code == 404


async def test_a_viewer_can_read_a_report_but_not_the_raw_evidence(
    client: AsyncClient, strong_password: str
) -> None:
    """Evidence is redacted, but it is still the rawest material held. A
    read-only reporting account has no need for the exchange itself."""
    org_id, target_id, headers = await _setup(client, strong_password, "m")
    run_id = await _run(client, org_id, target_id, headers)

    _viewer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    viewer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "reportviewer@example.test",
            "full_name": "Report Viewer",
            "password": strong_password,
        },
        headers={HEADER_NAME: _viewer_anon_token},
    )
    viewer_headers = {"Authorization": f"Bearer {viewer.json()['access_token']}"}
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "reportviewer@example.test", "role": "viewer"},
        headers=headers,
    )

    base = f"/api/v1/organizations/{org_id}/runs/{run_id}"
    assert (await client.get(f"{base}/report", headers=viewer_headers)).status_code == 200
    manifest = (await client.get(f"{base}/evidence", headers=viewer_headers)).json()
    assert manifest

    digest = manifest[0]["digest"]
    denied = await client.get(f"{base}/evidence/{digest}", headers=viewer_headers)
    assert denied.status_code == 403
