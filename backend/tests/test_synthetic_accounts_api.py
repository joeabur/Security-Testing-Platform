"""Synthetic account declaration (docs/BUILD_SPEC.md §2, §10).

The property under test throughout: the platform stores a reference to a
credential and never the credential.
"""

from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

ACCOUNT = {
    "label": "account_a",
    "credential_env_var": "KERVY_TARGET_TOKEN_A",
    "owned_object_ids": ["order-1"],
}


async def _org_with_target(client: AsyncClient, password: str, suffix: str) -> tuple[str, str, str]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"acctowner{suffix}@example.test",
            "full_name": "Acct Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    header = f"Bearer {owner.json()['access_token']}"
    org_id = (
        await client.post(
            "/api/v1/organizations",
            json={"name": f"Acct Org {suffix}"},
            headers={"Authorization": header},
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Demo",
                "environment": "staging",
                "kind": "api",
                "base_url": "https://ai.example.test",
            },
            headers={"Authorization": header},
        )
    ).json()["id"]
    return org_id, target_id, header


async def test_account_is_stored_by_reference_and_read_back(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "a")
    headers = {"Authorization": header}

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts/account_a",
        json=ACCOUNT,
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["credential_env_var"] == "KERVY_TARGET_TOKEN_A"
    assert body["value_template"] == "Bearer {credential}"
    assert body["owned_object_ids"] == ["order-1"]
    # There is no field in which a secret could be returned, because there
    # is no field in which one could be stored.
    assert "credential" not in body
    assert "token" not in body

    listed = await client.get(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts", headers=headers
    )
    assert [account["label"] for account in listed.json()] == ["account_a"]


async def test_a_credential_value_cannot_be_smuggled_in_as_a_variable_name(
    client: AsyncClient, strong_password: str
) -> None:
    """The field is validated as an environment variable *name* so that an
    operator cannot paste a token into it by mistake and have the platform
    store it."""
    org_id, target_id, header = await _org_with_target(client, strong_password, "b")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts/account_a",
        json={**ACCOUNT, "credential_env_var": "eyJhbGciOiJIUzI1NiJ9.secret.value"},
        headers={"Authorization": header},
    )

    assert response.status_code == 422


async def test_value_template_must_reference_the_credential(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "c")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts/account_a",
        json={**ACCOUNT, "value_template": "Bearer hardcoded-token"},
        headers={"Authorization": header},
    )

    assert response.status_code == 422


async def test_only_admins_may_declare_a_test_account(
    client: AsyncClient, strong_password: str
) -> None:
    """Declaring a test account asserts entitlement to use it, so it sits at
    the same privilege level as granting authorization."""
    org_id, target_id, owner_header = await _org_with_target(client, strong_password, "d")
    _engineer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    engineer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "acctengineer@example.test",
            "full_name": "Engineer",
            "password": strong_password,
        },
        headers={HEADER_NAME: _engineer_anon_token},
    )
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": engineer.json()["user"]["email"], "role": "security_engineer"},
        headers={"Authorization": owner_header},
    )

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts/account_a",
        json=ACCOUNT,
        headers={"Authorization": f"Bearer {engineer.json()['access_token']}"},
    )

    assert response.status_code == 403


async def test_account_can_be_updated_and_deleted(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "e")
    headers = {"Authorization": header}
    base = f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts/account_a"

    await client.put(base, json=ACCOUNT, headers=headers)
    updated = await client.put(
        base, json={**ACCOUNT, "is_privileged": True, "owned_object_ids": []}, headers=headers
    )
    assert updated.json()["is_privileged"] is True
    assert updated.json()["owned_object_ids"] == []

    assert (await client.delete(base, headers=headers)).status_code == 204
    assert (await client.delete(base, headers=headers)).status_code == 404


async def test_label_in_path_and_body_must_agree(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, header = await _org_with_target(client, strong_password, "f")

    response = await client.put(
        f"/api/v1/organizations/{org_id}/targets/{target_id}/accounts/account_b",
        json=ACCOUNT,
        headers={"Authorization": header},
    )

    assert response.status_code == 422
