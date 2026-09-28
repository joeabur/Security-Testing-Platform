"""Declaring a `DOMAIN` target's asset scope (pentest module Phase 2).

Mirrors `test_code_scope_api.py`'s shape: the same "scope lives on the
Rules of Engagement, not the target" and "an unstated boundary is not a
permissive one" rules apply here to `asset_scope` as they do to
`code_scope`.
"""

from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

ROE = {
    "allowed_domains": ["example.test", "*.example.test"],
    "excluded_domains": [],
    "allowed_ip_ranges": [],
    "allowed_paths": [],
    "excluded_paths": [],
    "allowed_methods": ["GET"],
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

DOMAIN_SCOPE = {
    "root_domain": "example.test",
    "allowed_subdomain_patterns": ["www.example.test"],
}


async def _target(
    client: AsyncClient,
    password: str,
    suffix: str,
    *,
    kind: str = "domain",
    with_roe: bool = True,
):
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"domainowner{suffix}@example.test",
            "full_name": "Domain Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Domain Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "example.test",
                "environment": "staging",
                "kind": kind,
                "base_url": "example.test",
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


async def test_domain_scope_is_declared_and_read_back(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _target(client, strong_password, "a")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/domain-scope",
        json=DOMAIN_SCOPE,
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["kind"] == "domain"

    roe_response = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/rules-of-engagement",
        headers=headers,
    )
    assert roe_response.status_code == 200


async def test_domain_scope_requires_a_root_domain(
    client: AsyncClient, strong_password: str
) -> None:
    """An unstated boundary is not a permissive one, and the refusal happens
    before anything is stored."""
    org_id, target_id, headers = await _target(client, strong_password, "b")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/domain-scope",
        json={**DOMAIN_SCOPE, "root_domain": ""},
        headers=headers,
    )

    assert response.status_code == 422


async def test_domain_scope_requires_rules_of_engagement_first(
    client: AsyncClient, strong_password: str
) -> None:
    """The scope is part of the engagement, so it cannot exist without one."""
    org_id, target_id, headers = await _target(client, strong_password, "c", with_roe=False)

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/domain-scope",
        json=DOMAIN_SCOPE,
        headers=headers,
    )

    assert response.status_code == 409
    assert "Rules of Engagement" in response.json()["error"]["message"]


async def test_domain_scope_is_refused_against_a_non_domain_target(
    client: AsyncClient, strong_password: str
) -> None:
    """`asset_scope` belongs to the target kind that reads it — declaring a
    domain scope on an unrelated target kind would silently sit unused."""
    org_id, target_id, headers = await _target(client, strong_password, "d", kind="api")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/domain-scope",
        json=DOMAIN_SCOPE,
        headers=headers,
    )

    assert response.status_code == 409
    assert "domain" in response.json()["error"]["message"]


async def test_only_admins_may_configure_a_domain_scope(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, owner_headers = await _target(client, strong_password, "e")
    _engineer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    engineer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "domainengineer@example.test",
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
        f"/api/v1/organizations/{org_id}/targets/{target_id}/domain-scope",
        json=DOMAIN_SCOPE,
        headers={"Authorization": f"Bearer {engineer.json()['access_token']}"},
    )

    assert response.status_code == 403
