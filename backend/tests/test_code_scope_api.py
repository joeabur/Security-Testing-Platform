"""Declaring a target's code surface (docs/BUILD_SPEC.md §4.5; Addendum §3)."""

from pathlib import Path

import pytest
from httpx import AsyncClient

from app.core.appsec.workspace import CodeScopeError
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.orchestrator.context_builder import build_workspace

ROE = {
    "allowed_domains": ["ai.example.test"],
    "excluded_domains": [],
    "allowed_ip_ranges": [],
    "allowed_paths": [],
    "excluded_paths": [],
    "allowed_methods": ["GET", "POST"],
    "forbidden_headers": [],
    "budgets": {
        "max_requests": 100,
        "max_concurrency": 2,
        "requests_per_second": 5.0,
        "max_tokens_sent": 10000,
        "max_tokens_received": 10000,
        "max_estimated_cost_usd": 1.0,
        "max_wall_clock_minutes": 10,
    },
    "safe_mode": True,
}

CODE = {
    "repo_ref": "git+https://github.com/example/app.git#main",
    "languages": ["python"],
    "build_manifest_paths": ["requirements.txt"],
    "code_scope": {"allowed_paths": ["src/**"], "excluded_paths": ["src/vendor/**"]},
}


async def _target(client: AsyncClient, password: str, suffix: str, *, with_roe: bool = True):
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"codeowner{suffix}@example.test",
            "full_name": "Code Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    header = f"Bearer {owner.json()['access_token']}"
    headers = {"Authorization": header}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Code Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "App repo",
                "environment": "staging",
                "kind": "api",
                "base_url": "https://ai.example.test",
            },
            headers=headers,
        )
    ).json()["id"]
    if with_roe:
        await client.put(
            f"/api/v1/organizations/{org_id}/targets/{target_id}/rules-of-engagement",
            json=ROE,
            headers=headers,
        )
    return org_id, target_id, headers


async def test_code_scope_is_declared_and_read_back(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _target(client, strong_password, "a")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/code", json=CODE, headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["code_repo_ref"] == CODE["repo_ref"]
    assert body["code_languages"] == ["python"]
    assert body["code_build_manifest_paths"] == ["requirements.txt"]


async def test_allow_advisory_lookup_is_stored_in_code_scope(
    client: AsyncClient, strong_password: str, db_session
) -> None:
    """A separate consent from the paths/hosts above: whether the AppSec
    engines may send verified advisory ids to osv.dev/NVD/GHSA. Reached
    through the real persisted `code_scope` dict, since `TargetRead` does
    not surface it directly."""
    import uuid as _uuid

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.target import Target

    org_id, target_id, headers = await _target(client, strong_password, "f")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/code",
        json={**CODE, "code_scope": {**CODE["code_scope"], "allow_advisory_lookup": True}},
        headers=headers,
    )

    assert response.status_code == 200
    target = (
        await db_session.execute(
            select(Target)
            .where(Target.id == _uuid.UUID(target_id))
            .options(selectinload(Target.rules_of_engagement))
        )
    ).scalar_one()
    assert target.rules_of_engagement.code_scope["allow_advisory_lookup"] is True


async def test_allow_advisory_lookup_defaults_to_false(
    client: AsyncClient, strong_password: str, db_session
) -> None:
    import uuid as _uuid

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.target import Target

    org_id, target_id, headers = await _target(client, strong_password, "g")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/code", json=CODE, headers=headers
    )

    assert response.status_code == 200
    target = (
        await db_session.execute(
            select(Target)
            .where(Target.id == _uuid.UUID(target_id))
            .options(selectinload(Target.rules_of_engagement))
        )
    ).scalar_one()
    assert target.rules_of_engagement.code_scope["allow_advisory_lookup"] is False


async def test_an_empty_allowlist_is_rejected_at_the_api_boundary(
    client: AsyncClient, strong_password: str
) -> None:
    """An unstated scope is not a permissive one, and the refusal happens
    before anything is stored."""
    org_id, target_id, headers = await _target(client, strong_password, "b")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/code",
        json={**CODE, "code_scope": {"allowed_paths": []}},
        headers=headers,
    )

    assert response.status_code == 422


async def test_code_scope_requires_rules_of_engagement_first(
    client: AsyncClient, strong_password: str
) -> None:
    """The scope is part of the engagement, so it cannot exist without one."""
    org_id, target_id, headers = await _target(client, strong_password, "c", with_roe=False)

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/code", json=CODE, headers=headers
    )

    assert response.status_code == 409
    assert "Rules of Engagement" in response.json()["error"]["message"]


async def test_only_admins_may_point_an_assessment_at_a_repository(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, owner_headers = await _target(client, strong_password, "d")
    _engineer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    engineer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "codeengineer@example.test",
            "full_name": "Engineer",
            "password": strong_password,
        },
        headers={HEADER_NAME: _engineer_anon_token},
    )
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": engineer.json()["user"]["email"], "role": "security_engineer"},
        headers=owner_headers,
    )

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/code",
        json=CODE,
        headers={"Authorization": f"Bearer {engineer.json()['access_token']}"},
    )

    assert response.status_code == 403


async def test_a_target_without_a_code_scope_refuses_to_build_a_workspace(
    client: AsyncClient, strong_password: str, db_session, tmp_path: Path
) -> None:
    """The fail-closed rule, exercised through the real persisted target
    rather than a constructed one."""
    import uuid as _uuid

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models.target import Target

    _, target_id, _ = await _target(client, strong_password, "e")
    target = (
        await db_session.execute(
            select(Target)
            .where(Target.id == _uuid.UUID(target_id))
            .options(selectinload(Target.rules_of_engagement))
        )
    ).scalar_one()

    with pytest.raises(CodeScopeError, match="No code_scope is configured"):
        build_workspace(target, tmp_path)
