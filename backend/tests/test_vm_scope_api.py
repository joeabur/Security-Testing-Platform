"""Declaring a `VIRTUAL_MACHINE` target's asset scope (pentest module Phase
5).

Mirrors `test_container_scope_api.py`'s shape: the same "scope lives on the
Rules of Engagement, not the target" and "an unstated boundary is not a
permissive one" rules apply here to `asset_scope` as they do to
`domain_scope`/`container_scope`/`cloud_scope`.
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

VM_SCOPE = {
    "host": "8.8.8.8",
    "allowed_ports": [22, 80, 443],
}


async def _target(
    client: AsyncClient,
    password: str,
    suffix: str,
    *,
    kind: str = "virtual_machine",
    with_roe: bool = True,
):
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"vmowner{suffix}@example.test",
            "full_name": "VM Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"VM Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "jump host",
                "environment": "staging",
                "kind": kind,
                "base_url": "8.8.8.8",
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


async def test_vm_scope_is_declared_and_read_back(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _target(client, strong_password, "a")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json=VM_SCOPE,
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["kind"] == "virtual_machine"

    roe_response = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/rules-of-engagement",
        headers=headers,
    )
    assert roe_response.status_code == 200


async def test_vm_scope_requires_a_host(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, headers = await _target(client, strong_password, "b")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json={**VM_SCOPE, "host": ""},
        headers=headers,
    )

    assert response.status_code == 422


async def test_vm_scope_requires_allowed_ports(client: AsyncClient, strong_password: str) -> None:
    """An unstated port allowlist is not a permissive one — the refusal
    happens before anything is stored, the same as `resolve_vm_scope`
    enforces at run time."""
    org_id, target_id, headers = await _target(client, strong_password, "c")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json={**VM_SCOPE, "allowed_ports": []},
        headers=headers,
    )

    assert response.status_code == 422


async def test_vm_scope_rejects_an_out_of_range_port(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _target(client, strong_password, "d")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json={**VM_SCOPE, "allowed_ports": [70000]},
        headers=headers,
    )

    assert response.status_code == 422


async def test_vm_scope_requires_rules_of_engagement_first(
    client: AsyncClient, strong_password: str
) -> None:
    """The scope is part of the engagement, so it cannot exist without one."""
    org_id, target_id, headers = await _target(client, strong_password, "e", with_roe=False)

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json=VM_SCOPE,
        headers=headers,
    )

    assert response.status_code == 409
    assert "Rules of Engagement" in response.json()["error"]["message"]


async def test_vm_scope_is_refused_against_a_non_vm_target(
    client: AsyncClient, strong_password: str
) -> None:
    """`asset_scope` belongs to the target kind that reads it — declaring a
    VM scope on an unrelated target kind would silently sit unused."""
    org_id, target_id, headers = await _target(client, strong_password, "f", kind="api")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json=VM_SCOPE,
        headers=headers,
    )

    assert response.status_code == 409
    assert "virtual_machine" in response.json()["error"]["message"]


async def test_only_admins_may_configure_a_vm_scope(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, owner_headers = await _target(client, strong_password, "g")
    _engineer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    engineer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "vmengineer@example.test",
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
        f"/api/v1/organizations/{org_id}/targets/{target_id}/vm-scope",
        json=VM_SCOPE,
        headers={"Authorization": f"Bearer {engineer.json()['access_token']}"},
    )

    assert response.status_code == 403
