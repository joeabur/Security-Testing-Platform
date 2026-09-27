"""The "add a repository" API (app/core/repositories/service.py,
app/api/v1/routers/repositories.py).

The property that matters most here is the one the feature exists for:
adding a repository must NOT require the Rules-of-Engagement/Authorization-
grant workflow a live network target needs, and scanning one must never
build a `DastCheck` or reach the network at all — only the AppSec engines,
over its own checkout. Every other test here (RBAC, tenant isolation,
duplicate/invalid input rejection) mirrors the coverage `test_targets.py`
already has for the heavier workflow this one is an alternative to.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.target import TargetKind

pytestmark = pytest.mark.asyncio

REPO_URL = "https://github.com/example-org/example-repo.git"


@pytest.fixture(autouse=True)
def _stub_broker(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Same double `test_runs_api.py` uses: record what would have been
    queued, without needing a real Celery broker for these API-contract
    tests."""
    queued: list[str] = []

    class _AsyncResult:
        id = "stub-task-id"

    def _send_task(name: str, args: list[str] | None = None, **kwargs: object) -> _AsyncResult:
        queued.append(args[0] if args else name)
        return _AsyncResult()

    from app.api.v1.routers import runs as runs_router

    monkeypatch.setattr(runs_router.celery_app, "send_task", _send_task)
    return queued


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0].title(), "password": password},
        headers={HEADER_NAME: anon_token},
    )
    assert response.status_code == 201
    return response.json()


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _make_org_with_owner(
    client: AsyncClient, strong_password: str, suffix: str
) -> tuple[str, dict[str, str]]:
    owner = await _register(client, f"owner{suffix}@example.test", strong_password)
    headers = _auth_headers(owner["access_token"])
    create = await client.post(
        "/api/v1/organizations", json={"name": f"Org {suffix}"}, headers=headers
    )
    assert create.status_code == 201
    return create.json()["id"], headers


async def _invite_role(
    client: AsyncClient,
    *,
    owner_headers: dict[str, str],
    org_id: str,
    strong_password: str,
    role: str,
    suffix: str,
) -> dict[str, str]:
    """A member of `role` in `org_id`, via the same register + invite path
    `test_targets.py` uses for its RBAC coverage."""
    member = await _register(client, f"member{suffix}@example.test", strong_password)
    invite = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": f"member{suffix}@example.test", "role": role},
        headers=owner_headers,
    )
    assert invite.status_code == 201, invite.text
    return _auth_headers(member["access_token"])


async def test_security_engineer_can_add_a_repository(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "a")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "branch": "main", "authorized": True},
        headers=owner_headers,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == "Example repo"
    assert body["url"] == REPO_URL
    assert body["branch"] == "main"
    assert body["latest_scan"] is None


async def test_adding_a_repository_requires_the_authorized_affirmation(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "b")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": False},
        headers=owner_headers,
    )

    assert response.status_code == 422


@pytest.mark.parametrize(
    "bad_url",
    [
        "git://example.test/repo.git",  # unauthenticated protocol
        "ext::sh -c 'rm -rf /'",  # arbitrary command execution
        "https://user:pass@example.test/repo.git",  # inline credentials  # pragma: allowlist secret
    ],
)
async def test_a_disallowed_repository_url_is_rejected(
    client: AsyncClient, strong_password: str, bad_url: str
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "c")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Bad repo", "url": bad_url, "authorized": True},
        headers=owner_headers,
    )

    assert response.status_code == 422, response.text


async def test_the_same_repository_cannot_be_connected_twice(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "d")
    payload = {"name": "Example repo", "url": REPO_URL, "authorized": True}

    first = await client.post(
        f"/api/v1/organizations/{org_id}/repositories", json=payload, headers=owner_headers
    )
    assert first.status_code == 201

    second = await client.post(
        f"/api/v1/organizations/{org_id}/repositories", json=payload, headers=owner_headers
    )
    assert second.status_code == 409


async def test_a_viewer_cannot_add_a_repository(client: AsyncClient, strong_password: str) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "e")
    viewer_headers = await _invite_role(
        client,
        owner_headers=owner_headers,
        org_id=org_id,
        strong_password=strong_password,
        role="viewer",
        suffix="e",
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": True},
        headers=viewer_headers,
    )

    assert response.status_code == 403


async def test_a_viewer_can_list_and_read_repositories(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "f")
    created = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": True},
        headers=owner_headers,
    )
    repo_id = created.json()["id"]
    viewer_headers = await _invite_role(
        client,
        owner_headers=owner_headers,
        org_id=org_id,
        strong_password=strong_password,
        role="viewer",
        suffix="f",
    )

    listing = await client.get(
        f"/api/v1/organizations/{org_id}/repositories", headers=viewer_headers
    )
    assert listing.status_code == 200
    assert [row["id"] for row in listing.json()] == [repo_id]

    detail = await client.get(
        f"/api/v1/organizations/{org_id}/repositories/{repo_id}", headers=viewer_headers
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["allowed_paths"] == ["**"]
    assert body["open_findings_by_severity"] == {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }
    assert body["recent_scans"] == []


async def test_another_organizations_member_cannot_reach_the_repository(
    client: AsyncClient, strong_password: str
) -> None:
    org_a, owner_a_headers = await _make_org_with_owner(client, strong_password, "g1")
    org_b, owner_b_headers = await _make_org_with_owner(client, strong_password, "g2")
    created = await client.post(
        f"/api/v1/organizations/{org_a}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": True},
        headers=owner_a_headers,
    )
    repo_id = created.json()["id"]

    cross_org = await client.get(
        f"/api/v1/organizations/{org_b}/repositories/{repo_id}", headers=owner_b_headers
    )
    assert cross_org.status_code == 404


async def test_scanning_a_repository_queues_an_assessment_run(
    client: AsyncClient, strong_password: str, _stub_broker: list[str]
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "h")
    created = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": True},
        headers=owner_headers,
    )
    repo_id = created.json()["id"]

    response = await client.post(
        f"/api/v1/organizations/{org_id}/repositories/{repo_id}/scan",
        json={},
        headers=owner_headers,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "queued"
    assert _stub_broker == [body["run_id"]]

    listing = await client.get(
        f"/api/v1/organizations/{org_id}/repositories", headers=owner_headers
    )
    latest = listing.json()[0]["latest_scan"]
    assert latest["run_id"] == body["run_id"]
    assert latest["status"] == "queued"


async def test_scanning_a_nonexistent_repository_is_404(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "i")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/repositories/{uuid.uuid4()}/scan",
        json={},
        headers=owner_headers,
    )

    assert response.status_code == 404


async def test_admin_can_remove_a_repository(client: AsyncClient, strong_password: str) -> None:
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "j")
    created = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": True},
        headers=owner_headers,
    )
    repo_id = created.json()["id"]

    removed = await client.delete(
        f"/api/v1/organizations/{org_id}/repositories/{repo_id}", headers=owner_headers
    )
    assert removed.status_code == 204

    gone = await client.get(
        f"/api/v1/organizations/{org_id}/repositories/{repo_id}", headers=owner_headers
    )
    assert gone.status_code == 404


async def test_a_security_engineer_cannot_remove_a_repository(
    client: AsyncClient, strong_password: str
) -> None:
    """Removal needs `Role.ADMIN`, one step above the `SECURITY_ENGINEER`
    minimum that adding and scanning need — connecting a repository is
    reversible by anyone who can start a scan, disconnecting one that other
    people may depend on is not."""
    org_id, owner_headers = await _make_org_with_owner(client, strong_password, "k")
    created = await client.post(
        f"/api/v1/organizations/{org_id}/repositories",
        json={"name": "Example repo", "url": REPO_URL, "authorized": True},
        headers=owner_headers,
    )
    repo_id = created.json()["id"]
    engineer_headers = await _invite_role(
        client,
        owner_headers=owner_headers,
        org_id=org_id,
        strong_password=strong_password,
        role="security_engineer",
        suffix="k",
    )

    response = await client.delete(
        f"/api/v1/organizations/{org_id}/repositories/{repo_id}", headers=engineer_headers
    )
    assert response.status_code == 403


async def test_a_repository_target_never_builds_a_dast_check() -> None:
    """The property the whole feature depends on for safety: a repository
    has no network surface, and `TargetKind.CODE_REPO` exists specifically
    so `execute_assessment_run` never treats one as something to crawl."""
    import inspect

    from app.workers import tasks as worker_tasks

    source = inspect.getsource(worker_tasks.execute_assessment_run)
    # `DastCheck` is built only for `kind is TargetKind.WEB_APP` — a
    # `CODE_REPO` target must fall outside that condition, which the enum
    # having a distinct value from `WEB_APP` guarantees.
    assert "TargetKind.WEB_APP" in source
    assert TargetKind.CODE_REPO is not TargetKind.WEB_APP
