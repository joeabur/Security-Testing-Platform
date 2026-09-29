"""API keys for CI/CD (docs/BUILD_SPEC.md §17.4).

The important assertions here are about what a key *cannot* do. A credential
that lives in a CI runner is the most exposed thing this platform issues, so
the tests that matter are the ones proving it cannot grant authorization,
cannot mint another key, and cannot act with the privileges of the person who
created it.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.api_key import ApiKey, role_for_scopes, split_token
from app.models.audit import AuditEvent
from app.models.organization import Role


async def _owner(client: AsyncClient, password: str, suffix: str) -> tuple[str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"keyowner{suffix}@example.test",
            "full_name": "Key Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Key Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    return org_id, headers


async def _mint(
    client: AsyncClient,
    org_id: str,
    headers: dict[str, str],
    scopes: list[str],
    **extra: object,
) -> dict:
    response = await client.post(
        f"/api/v1/organizations/{org_id}/api-keys",
        json={"name": "ci", "scopes": scopes, **extra},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


# --- creation -------------------------------------------------------------


async def test_the_secret_is_returned_once_and_never_again(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, headers = await _owner(client, strong_password, "a")
    created = await _mint(client, org_id, headers, ["read"])

    assert created["token"].startswith("kervy_")
    listed = (await client.get(f"/api/v1/organizations/{org_id}/api-keys", headers=headers)).json()
    assert len(listed) == 1
    assert "token" not in listed[0]

    # And the database holds a digest, not the secret.
    stored = (await db_session.execute(select(ApiKey))).scalar_one()
    parts = split_token(created["token"])
    assert parts is not None
    assert stored.token_digest != parts[1]
    assert parts[1] not in stored.token_digest


async def test_creating_a_key_is_audited_without_recording_the_key(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """An audit log that records a credential is a second place it leaks."""
    org_id, headers = await _owner(client, strong_password, "b")
    created = await _mint(client, org_id, headers, ["read", "scan"])

    event = (
        await db_session.execute(select(AuditEvent).where(AuditEvent.action == "api_key.create"))
    ).scalar_one()
    assert event.metadata_json["scopes"] == ["read", "scan"]
    assert created["token"] not in str(event.metadata_json)


async def test_a_key_expiring_in_the_past_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "c")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/api-keys",
        json={
            "name": "stale",
            "scopes": ["read"],
            "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
        },
        headers=headers,
    )
    assert response.status_code == 422


async def test_a_key_with_no_scopes_is_refused(client: AsyncClient, strong_password: str) -> None:
    """A key that authenticates and can do nothing is a confusing way to say
    "revoked"."""
    org_id, headers = await _owner(client, strong_password, "d")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/api-keys",
        json={"name": "empty", "scopes": []},
        headers=headers,
    )
    assert response.status_code == 422


async def test_only_an_admin_can_mint_a_key(client: AsyncClient, strong_password: str) -> None:
    org_id, headers = await _owner(client, strong_password, "e")
    _engineer_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    engineer = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "keyengineer@example.test",
            "full_name": "Engineer",
            "password": strong_password,
        },
        headers={HEADER_NAME: _engineer_anon_token},
    )
    engineer_headers = {"Authorization": f"Bearer {engineer.json()['access_token']}"}
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "keyengineer@example.test", "role": "security_engineer"},
        headers=headers,
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/api-keys",
        json={"name": "sneaky", "scopes": ["read"]},
        headers=engineer_headers,
    )
    assert response.status_code == 403


# --- using a key ----------------------------------------------------------


async def test_a_key_authenticates_and_reads(client: AsyncClient, strong_password: str) -> None:
    org_id, headers = await _owner(client, strong_password, "f")
    created = await _mint(client, org_id, headers, ["read"])
    key_headers = {"Authorization": f"Bearer {created['token']}"}

    response = await client.get(f"/api/v1/organizations/{org_id}/findings", headers=key_headers)
    assert response.status_code == 200


async def test_a_read_only_key_cannot_start_a_scan(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "g")
    created = await _mint(client, org_id, headers, ["read"])
    key_headers = {"Authorization": f"Bearer {created['token']}"}

    response = await client.post(
        f"/api/v1/organizations/{org_id}/runs",
        json={"target_id": str(uuid.uuid4()), "authorization_confirmed": True},
        headers=key_headers,
    )
    assert response.status_code == 403


async def test_a_key_minted_by_an_owner_does_not_act_as_an_owner(
    client: AsyncClient, strong_password: str
) -> None:
    """The escalation this design exists to prevent.

    The key authenticates as the member who created it. If it inherited that
    member's role, every CI key an owner created would be an owner key — able
    to grant authorization for a new target, add members, and mint more keys.
    """
    org_id, headers = await _owner(client, strong_password, "h")
    created = await _mint(client, org_id, headers, ["read", "scan", "triage"])
    key_headers = {"Authorization": f"Bearer {created['token']}"}

    # The scopes top out at security engineer, by design.
    assert created["role"] == Role.SECURITY_ENGINEER.value

    # Admin actions are refused: a target, a member, another key.
    assert (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "smuggled",
                "environment": "staging",
                "kind": "llm_app",
                "base_url": "https://smuggled.test",
            },
            headers=key_headers,
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/organizations/{org_id}/members",
            json={"email": "someone@example.test", "role": "admin"},
            headers=key_headers,
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/organizations/{org_id}/api-keys",
            json={"name": "second", "scopes": ["read"]},
            headers=key_headers,
        )
    ).status_code == 403


async def test_a_revoked_key_stops_working(client: AsyncClient, strong_password: str) -> None:
    org_id, headers = await _owner(client, strong_password, "i")
    created = await _mint(client, org_id, headers, ["read"])
    key_headers = {"Authorization": f"Bearer {created['token']}"}

    revoked = await client.post(
        f"/api/v1/organizations/{org_id}/api-keys/{created['id']}/revoke", headers=headers
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None

    response = await client.get(f"/api/v1/organizations/{org_id}/findings", headers=key_headers)
    assert response.status_code == 401
    assert "revoked" in response.json()["error"]["message"]


async def test_an_expired_key_stops_working(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, headers = await _owner(client, strong_password, "j")
    created = await _mint(client, org_id, headers, ["read"])

    key = (await db_session.execute(select(ApiKey))).scalar_one()
    key.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    response = await client.get(
        f"/api/v1/organizations/{org_id}/findings",
        headers={"Authorization": f"Bearer {created['token']}"},
    )
    assert response.status_code == 401


async def test_a_key_cannot_reach_another_organization(
    client: AsyncClient, strong_password: str
) -> None:
    """404, like a non-member: a key has no business learning that another
    organization exists."""
    first_org, first_headers = await _owner(client, strong_password, "k")
    created = await _mint(client, first_org, first_headers, ["read"])
    second_org, _ = await _owner(client, strong_password, "l")

    response = await client.get(
        f"/api/v1/organizations/{second_org}/findings",
        headers={"Authorization": f"Bearer {created['token']}"},
    )
    assert response.status_code == 404


async def test_using_a_key_records_when_it_was_last_used(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """So an operator can find the keys nothing is using and revoke them."""
    org_id, headers = await _owner(client, strong_password, "m")
    created = await _mint(client, org_id, headers, ["read"])
    assert created["last_used_at"] is None

    await client.get(
        f"/api/v1/organizations/{org_id}/findings",
        headers={"Authorization": f"Bearer {created['token']}"},
    )

    key = (await db_session.execute(select(ApiKey))).scalar_one()
    await db_session.refresh(key)
    assert key.last_used_at is not None


@pytest.mark.parametrize(
    "token",
    [
        "kervy_",
        "kervy_short_secret",
        "kervy_zzzzzzzzzzzzzzzz_secret",
        "kervy_0011223344556677",
        "kervy_0011223344556677_",
    ],
)
async def test_a_malformed_key_is_rejected(
    client: AsyncClient, strong_password: str, token: str
) -> None:
    org_id, _ = await _owner(client, strong_password, f"n{len(token)}")
    response = await client.get(
        f"/api/v1/organizations/{org_id}/findings",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


async def test_a_wrong_secret_for_a_real_key_id_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "o")
    created = await _mint(client, org_id, headers, ["read"])

    forged = f"kervy_{created['key_id']}_not-the-real-secret"
    response = await client.get(
        f"/api/v1/organizations/{org_id}/findings",
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert response.status_code == 401


# --- the scope-to-role mapping --------------------------------------------


def test_scopes_map_to_one_role_and_never_above_security_engineer() -> None:
    """One source of truth. A key carrying both a scope list and a role could
    have the two disagree, and then nobody can say which is enforced."""
    assert role_for_scopes(["read"]) is Role.VIEWER
    assert role_for_scopes(["triage"]) is Role.ANALYST
    assert role_for_scopes(["scan"]) is Role.SECURITY_ENGINEER
    assert role_for_scopes(["read", "scan"]) is Role.SECURITY_ENGINEER
    assert role_for_scopes([]) is Role.VIEWER

    for scope in ("read", "triage", "scan"):
        assert not role_for_scopes([scope]).at_least(Role.ADMIN)
