import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

pytestmark = pytest.mark.asyncio


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    _response_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0].title(), "password": password},
        headers={HEADER_NAME: _response_anon_token},
    )
    assert response.status_code == 201
    return response.json()


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_creator_becomes_owner(client: AsyncClient, strong_password: str) -> None:
    user = await _register(client, "owner@example.test", strong_password)
    headers = _auth_headers(user["access_token"])

    response = await client.post(
        "/api/v1/organizations", json={"name": "Demo Security Lab"}, headers=headers
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Demo Security Lab"
    assert body["role"] == "owner"


async def test_list_organizations_returns_only_memberships(
    client: AsyncClient, strong_password: str
) -> None:
    user_a = await _register(client, "listera@example.test", strong_password)
    user_b = await _register(client, "listerb@example.test", strong_password)
    headers_a = _auth_headers(user_a["access_token"])
    headers_b = _auth_headers(user_b["access_token"])

    await client.post("/api/v1/organizations", json={"name": "A's Org"}, headers=headers_a)
    await client.post("/api/v1/organizations", json={"name": "B's Org"}, headers=headers_b)

    response_a = await client.get("/api/v1/organizations", headers=headers_a)
    names_a = {org["name"] for org in response_a.json()}
    assert names_a == {"A's Org"}

    response_b = await client.get("/api/v1/organizations", headers=headers_b)
    names_b = {org["name"] for org in response_b.json()}
    assert names_b == {"B's Org"}


async def test_non_member_cannot_access_another_organization(
    client: AsyncClient, strong_password: str
) -> None:
    """Cross-organization isolation, per docs/BUILD_SPEC.md §17.3 / §24."""
    owner = await _register(client, "isolatedowner@example.test", strong_password)
    outsider = await _register(client, "outsider@example.test", strong_password)

    create = await client.post(
        "/api/v1/organizations",
        json={"name": "Private Org"},
        headers=_auth_headers(owner["access_token"]),
    )
    org_id = create.json()["id"]

    response = await client.get(
        f"/api/v1/organizations/{org_id}", headers=_auth_headers(outsider["access_token"])
    )
    assert response.status_code == 404

    members_response = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(outsider["access_token"])
    )
    assert members_response.status_code == 404

    invite_response = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "someone@example.test", "role": "viewer"},
        headers=_auth_headers(outsider["access_token"]),
    )
    assert invite_response.status_code == 404


async def test_unauthenticated_request_is_blocked(
    client: AsyncClient, strong_password: str
) -> None:
    owner = await _register(client, "authowner@example.test", strong_password)
    create = await client.post(
        "/api/v1/organizations",
        json={"name": "Needs Auth"},
        headers=_auth_headers(owner["access_token"]),
    )
    org_id = create.json()["id"]

    client.cookies.clear()  # registration left a session cookie on this shared client
    response = await client.get(f"/api/v1/organizations/{org_id}")
    assert response.status_code == 401


async def test_viewer_cannot_invite_members(client: AsyncClient, strong_password: str) -> None:
    owner = await _register(client, "rbacowner@example.test", strong_password)
    viewer = await _register(client, "rbacviewer@example.test", strong_password)

    create = await client.post(
        "/api/v1/organizations",
        json={"name": "RBAC Org"},
        headers=_auth_headers(owner["access_token"]),
    )
    org_id = create.json()["id"]

    invite = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": viewer["user"]["email"], "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert invite.status_code == 201

    forbidden = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "someone-else@example.test", "role": "viewer"},
        headers=_auth_headers(viewer["access_token"]),
    )
    assert forbidden.status_code == 403


async def test_admin_can_invite_member_with_role(client: AsyncClient, strong_password: str) -> None:
    owner = await _register(client, "adminowner@example.test", strong_password)
    engineer = await _register(client, "secengineer@example.test", strong_password)

    create = await client.post(
        "/api/v1/organizations",
        json={"name": "Invite Org"},
        headers=_auth_headers(owner["access_token"]),
    )
    org_id = create.json()["id"]

    invite = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": engineer["user"]["email"], "role": "security_engineer"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert invite.status_code == 201
    assert invite.json()["role"] == "security_engineer"

    members = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner["access_token"])
    )
    roles = {m["email"]: m["role"] for m in members.json()}
    assert roles["secengineer@example.test"] == "security_engineer"


async def test_cannot_invite_same_member_twice(client: AsyncClient, strong_password: str) -> None:
    owner = await _register(client, "dupowner@example.test", strong_password)
    member = await _register(client, "dupmember@example.test", strong_password)

    create = await client.post(
        "/api/v1/organizations",
        json={"name": "Dup Org"},
        headers=_auth_headers(owner["access_token"]),
    )
    org_id = create.json()["id"]

    payload = {"email": member["user"]["email"], "role": "analyst"}
    first = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json=payload,
        headers=_auth_headers(owner["access_token"]),
    )
    assert first.status_code == 201

    second = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json=payload,
        headers=_auth_headers(owner["access_token"]),
    )
    assert second.status_code == 409


async def _create_org_and_invite(
    client: AsyncClient, owner_token: str, invitee_email: str, role: str
) -> tuple[str, str]:
    create = await client.post(
        "/api/v1/organizations",
        json={"name": f"Org for {invitee_email}"},
        headers=_auth_headers(owner_token),
    )
    org_id = create.json()["id"]
    invite = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": invitee_email, "role": role},
        headers=_auth_headers(owner_token),
    )
    assert invite.status_code == 201
    return org_id, invite.json()["id"]


async def test_admin_cannot_grant_owner(client: AsyncClient, strong_password: str) -> None:
    owner = await _register(client, "escalowner@example.test", strong_password)
    admin = await _register(client, "escaladmin@example.test", strong_password)
    accomplice = await _register(client, "escalaccomplice@example.test", strong_password)

    org_id, _ = await _create_org_and_invite(
        client, owner["access_token"], admin["user"]["email"], "admin"
    )

    forbidden = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": accomplice["user"]["email"], "role": "owner"},
        headers=_auth_headers(admin["access_token"]),
    )
    assert forbidden.status_code == 403


async def test_owner_can_change_a_members_role(client: AsyncClient, strong_password: str) -> None:
    owner = await _register(client, "roleowner@example.test", strong_password)
    member = await _register(client, "rolemember@example.test", strong_password)

    org_id, member_id = await _create_org_and_invite(
        client, owner["access_token"], member["user"]["email"], "viewer"
    )

    response = await client.patch(
        f"/api/v1/organizations/{org_id}/members/{member_id}",
        json={"role": "analyst"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


async def test_admin_cannot_change_a_members_role_to_or_from_owner(
    client: AsyncClient, strong_password: str
) -> None:
    owner = await _register(client, "roleescalowner@example.test", strong_password)
    admin = await _register(client, "roleescaladmin@example.test", strong_password)
    member = await _register(client, "roleescalmember@example.test", strong_password)

    org_id, admin_id = await _create_org_and_invite(
        client, owner["access_token"], admin["user"]["email"], "admin"
    )
    invite_member = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": member["user"]["email"], "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )
    member_id = invite_member.json()["id"]

    # Admin cannot promote someone to owner.
    forbidden_promote = await client.patch(
        f"/api/v1/organizations/{org_id}/members/{member_id}",
        json={"role": "owner"},
        headers=_auth_headers(admin["access_token"]),
    )
    assert forbidden_promote.status_code == 403

    # Admin cannot demote the owner, either.
    owner_membership = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner["access_token"])
    )
    owner_member_id = next(m["id"] for m in owner_membership.json() if m["role"] == "owner")
    forbidden_demote = await client.patch(
        f"/api/v1/organizations/{org_id}/members/{owner_member_id}",
        json={"role": "admin"},
        headers=_auth_headers(admin["access_token"]),
    )
    assert forbidden_demote.status_code == 403
    assert admin_id  # the admin's own membership id, unused beyond setup


async def test_the_last_owner_cannot_be_demoted_or_removed(
    client: AsyncClient, strong_password: str
) -> None:
    owner = await _register(client, "lastowner@example.test", strong_password)

    create = await client.post(
        "/api/v1/organizations",
        json={"name": "Solo Org"},
        headers=_auth_headers(owner["access_token"]),
    )
    org_id = create.json()["id"]
    members = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner["access_token"])
    )
    owner_member_id = members.json()[0]["id"]

    demote = await client.patch(
        f"/api/v1/organizations/{org_id}/members/{owner_member_id}",
        json={"role": "admin"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert demote.status_code == 409

    remove = await client.delete(
        f"/api/v1/organizations/{org_id}/members/{owner_member_id}",
        headers=_auth_headers(owner["access_token"]),
    )
    assert remove.status_code == 409


async def test_a_second_owner_can_then_be_demoted(
    client: AsyncClient, strong_password: str
) -> None:
    owner = await _register(client, "twoownersowner@example.test", strong_password)
    second = await _register(client, "twoownerssecond@example.test", strong_password)

    org_id, second_id = await _create_org_and_invite(
        client, owner["access_token"], second["user"]["email"], "owner"
    )

    demote = await client.patch(
        f"/api/v1/organizations/{org_id}/members/{second_id}",
        json={"role": "admin"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert demote.status_code == 200
    assert demote.json()["role"] == "admin"


async def test_admin_can_remove_a_non_owner_member(
    client: AsyncClient, strong_password: str
) -> None:
    owner = await _register(client, "removeowner@example.test", strong_password)
    admin = await _register(client, "removeadmin@example.test", strong_password)
    member = await _register(client, "removemember@example.test", strong_password)

    org_id, _ = await _create_org_and_invite(
        client, owner["access_token"], admin["user"]["email"], "admin"
    )
    invite_member = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": member["user"]["email"], "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )
    member_id = invite_member.json()["id"]

    remove = await client.delete(
        f"/api/v1/organizations/{org_id}/members/{member_id}",
        headers=_auth_headers(admin["access_token"]),
    )
    assert remove.status_code == 204

    members = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner["access_token"])
    )
    assert member["user"]["email"] not in {m["email"] for m in members.json()}


async def test_removing_a_member_from_another_organization_is_404(
    client: AsyncClient, strong_password: str
) -> None:
    owner_a = await _register(client, "crossorga@example.test", strong_password)
    owner_b = await _register(client, "crossorgb@example.test", strong_password)
    member = await _register(client, "crossorgmember@example.test", strong_password)

    org_a_id, member_id = await _create_org_and_invite(
        client, owner_a["access_token"], member["user"]["email"], "viewer"
    )
    org_b = await client.post(
        "/api/v1/organizations",
        json={"name": "B's Org"},
        headers=_auth_headers(owner_b["access_token"]),
    )
    org_b_id = org_b.json()["id"]

    response = await client.delete(
        f"/api/v1/organizations/{org_b_id}/members/{member_id}",
        headers=_auth_headers(owner_b["access_token"]),
    )
    assert response.status_code == 404

    # And the member is still there in its real organization.
    members = await client.get(
        f"/api/v1/organizations/{org_a_id}/members", headers=_auth_headers(owner_a["access_token"])
    )
    assert member["user"]["email"] in {m["email"] for m in members.json()}
