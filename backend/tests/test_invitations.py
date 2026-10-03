"""Email invitations for a not-yet-registered address (docs/roadmap.md).

`send_invitation_email` is monkeypatched to a recorder rather than exercised
end to end here, the same split `test_password_reset.py` already uses: its
own SMTP-over-scope-engine path has its own coverage, so this file is about
the invitation lifecycle (issue, list, revoke, accept) and the RBAC/identity
rules around it.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import organizations as organizations_router
from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.integrations.contract import DeliveryResult
from app.models.invitation import OrganizationInvitation

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _smtp_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KERVY_PLATFORM_SMTP_HOST", "smtp.kervy.example.test")
    monkeypatch.setenv("KERVY_PLATFORM_SMTP_FROM_ADDRESS", "no-reply@kervy.example.test")
    monkeypatch.setenv("KERVY_PUBLIC_BASE_URL", "https://app.kervy.example.test")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def sent_invitations(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, str]]:
    sent: list[dict[str, str]] = []

    async def _fake_send(
        settings, *, to_address, organization_name, role, invited_by_name, accept_url
    ):  # noqa: ANN001
        sent.append(
            {
                "to": to_address,
                "organization": organization_name,
                "role": role.value,
                "invited_by": invited_by_name,
                "url": accept_url,
            }
        )
        return DeliveryResult(delivered=True, detail="ok")

    monkeypatch.setattr(organizations_router, "send_invitation_email", _fake_send)
    return sent


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


async def _register(client: AsyncClient, email: str, password: str) -> dict:
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0].title(), "password": password},
        headers=await _anon_headers(client),
    )
    assert response.status_code == 201
    return response.json()


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _owner_with_org(client: AsyncClient, password: str, suffix: str) -> tuple[dict, str]:
    owner = await _register(client, f"invowner{suffix}@example.test", password)
    create = await client.post(
        "/api/v1/organizations",
        json={"name": f"Invite Org {suffix}"},
        headers=_auth_headers(owner["access_token"]),
    )
    return owner, create.json()["id"]


async def test_inviting_an_unregistered_email_creates_a_pending_invitation(
    client: AsyncClient, strong_password: str, sent_invitations: list[dict[str, str]]
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "a")

    response = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "newcomer@example.test", "role": "analyst"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["email"] == "newcomer@example.test"
    assert body["role"] == "analyst"
    assert "user_id" not in body

    assert sent_invitations
    assert sent_invitations[0]["to"] == "newcomer@example.test"
    assert sent_invitations[0]["role"] == "analyst"
    assert "token=" in sent_invitations[0]["url"]

    members = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner["access_token"])
    )
    emails = {m["email"] for m in members.json()}
    assert "newcomer@example.test" not in emails


async def test_inviting_the_same_unregistered_email_twice_revokes_the_first(
    client: AsyncClient,
    strong_password: str,
    sent_invitations: list[dict[str, str]],
    db_session: AsyncSession,
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "b")

    for _ in range(2):
        response = await client.post(
            f"/api/v1/organizations/{org_id}/members",
            json={"email": "twice@example.test", "role": "viewer"},
            headers=_auth_headers(owner["access_token"]),
        )
        assert response.status_code == 201

    result = await db_session.execute(
        select(OrganizationInvitation).where(OrganizationInvitation.email == "twice@example.test")
    )
    rows = result.scalars().all()
    assert len(rows) == 2
    live = [row for row in rows if row.usable_at()]
    assert len(live) == 1


async def test_pending_invitations_are_listed_for_an_admin(
    client: AsyncClient, strong_password: str, sent_invitations: list[dict[str, str]]
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "c")
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "listed@example.test", "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )

    listing = await client.get(
        f"/api/v1/organizations/{org_id}/invitations", headers=_auth_headers(owner["access_token"])
    )
    assert listing.status_code == 200
    emails = [row["email"] for row in listing.json()]
    assert emails == ["listed@example.test"]


async def test_an_admin_can_revoke_a_pending_invitation(
    client: AsyncClient, strong_password: str, sent_invitations: list[dict[str, str]]
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "d")
    invite = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "revokeme@example.test", "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )
    invitation_id = invite.json()["id"]

    revoke = await client.delete(
        f"/api/v1/organizations/{org_id}/invitations/{invitation_id}",
        headers=_auth_headers(owner["access_token"]),
    )
    assert revoke.status_code == 204

    listing = await client.get(
        f"/api/v1/organizations/{org_id}/invitations", headers=_auth_headers(owner["access_token"])
    )
    assert listing.json() == []

    token = sent_invitations[0]["url"].split("token=")[1]
    newcomer = await _register(client, "revokeme@example.test", strong_password)
    accept = await client.post(
        "/api/v1/organizations/invitations/accept",
        json={"token": token},
        headers=_auth_headers(newcomer["access_token"]),
    )
    assert accept.status_code == 400


async def test_accepting_an_invitation_creates_membership_with_the_invited_role(
    client: AsyncClient, strong_password: str, sent_invitations: list[dict[str, str]]
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "e")
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "accepted@example.test", "role": "security_engineer"},
        headers=_auth_headers(owner["access_token"]),
    )
    token = sent_invitations[0]["url"].split("token=")[1]

    newcomer = await _register(client, "accepted@example.test", strong_password)
    accept = await client.post(
        "/api/v1/organizations/invitations/accept",
        json={"token": token},
        headers=_auth_headers(newcomer["access_token"]),
    )
    assert accept.status_code == 201, accept.text
    assert accept.json()["role"] == "security_engineer"
    assert accept.json()["email"] == "accepted@example.test"

    members = await client.get(
        f"/api/v1/organizations/{org_id}/members", headers=_auth_headers(owner["access_token"])
    )
    roles = {m["email"]: m["role"] for m in members.json()}
    assert roles["accepted@example.test"] == "security_engineer"

    # One-time use: redeeming again fails.
    again = await client.post(
        "/api/v1/organizations/invitations/accept",
        json={"token": token},
        headers=_auth_headers(newcomer["access_token"]),
    )
    assert again.status_code == 400


async def test_accepting_requires_the_callers_email_to_match_the_invitation(
    client: AsyncClient, strong_password: str, sent_invitations: list[dict[str, str]]
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "f")
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "intended@example.test", "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )
    token = sent_invitations[0]["url"].split("token=")[1]

    someone_else = await _register(client, "impostor@example.test", strong_password)
    accept = await client.post(
        "/api/v1/organizations/invitations/accept",
        json={"token": token},
        headers=_auth_headers(someone_else["access_token"]),
    )
    assert accept.status_code == 400


async def test_accepting_an_unknown_token_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "g")
    accept = await client.post(
        "/api/v1/organizations/invitations/accept",
        json={"token": "not-a-real-token"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert accept.status_code == 400


async def test_an_admin_cannot_create_an_owner_invitation(
    client: AsyncClient, strong_password: str, sent_invitations: list[dict[str, str]]
) -> None:
    owner, org_id = await _owner_with_org(client, strong_password, "h")
    admin = await _register(client, "notowneradmin@example.test", strong_password)
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": admin["user"]["email"], "role": "admin"},
        headers=_auth_headers(owner["access_token"]),
    )

    response = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "wouldbeowner@example.test", "role": "owner"},
        headers=_auth_headers(admin["access_token"]),
    )
    assert response.status_code == 403
    assert sent_invitations == []


async def test_the_invitation_row_is_created_even_when_mail_is_not_configured(
    client: AsyncClient,
    strong_password: str,
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
) -> None:
    monkeypatch.delenv("KERVY_PLATFORM_SMTP_HOST", raising=False)
    get_settings.cache_clear()

    owner, org_id = await _owner_with_org(client, strong_password, "i")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "nomail@example.test", "role": "viewer"},
        headers=_auth_headers(owner["access_token"]),
    )
    assert response.status_code == 201

    result = await db_session.execute(
        select(OrganizationInvitation).where(OrganizationInvitation.email == "nomail@example.test")
    )
    assert result.scalar_one() is not None

    get_settings.cache_clear()
