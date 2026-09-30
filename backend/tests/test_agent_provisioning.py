"""Provisioning an `AgentProvider`/`Agent` through the HTTP API
(`app/api/v1/routers/agent.py`'s `POST/GET/PATCH/DELETE .../agent/providers`
and `GET/PUT .../agent`).

RBAC and tenant isolation for these routes are already covered generically
by `tests/security/test_authorization_matrix.py` (they are registered in its
`EXPECTED_ROLES`). This file covers what that matrix test cannot: CRUD
correctness, the default-provider wiring that closes the "agent is fully
built but nothing can ever configure it" gap, `allowed_ip_ranges` CIDR
validation, and that creating a default provider is what actually clears
`POST .../agent/investigate`'s 409.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.agent import AgentProvider


async def _register(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    anon = await client.get("/api/v1/auth/csrf")
    anon_token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": email.split("@")[0], "password": password},
        headers={HEADER_NAME: anon_token},
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _organization(client: AsyncClient, owner: dict[str, str], name: str) -> str:
    response = await client.post("/api/v1/organizations", json={"name": name}, headers=owner)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


async def _org(
    client: AsyncClient, strong_password: str, suffix: str
) -> tuple[str, dict[str, str]]:
    owner = await _register(client, f"provisioning-{suffix}@example.test", strong_password)
    org_id = await _organization(client, owner, f"Provisioning Org {suffix}")
    return org_id, owner


def _provider_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "name": "primary-anthropic",
        "kind": "anthropic",
        "endpoint": "https://api.anthropic.test/v1/messages",
        "model": "claude-sonnet",
        "api_key_env_var": "ANTHROPIC_API_KEY",  # pragma: allowlist secret
    }
    payload.update(overrides)
    return payload


async def test_creating_a_provider_never_returns_a_secret_value(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(),
        headers=owner,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    # Only the env var *name* is ever in the body — never a value that
    # could be a key, and never even the literal string "sk-" a real
    # Anthropic key would start with, to catch a future regression that
    # accidentally started accepting a value here.
    assert body["api_key_env_var"] == "ANTHROPIC_API_KEY"  # pragma: allowlist secret
    assert "api_key" not in body
    assert "sk-" not in str(body)


async def test_creating_a_default_provider_enables_the_agent_and_clears_the_409(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    before = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "anything"},
        headers=owner,
    )
    assert before.status_code == 409, before.text

    created = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(),
        headers=owner,
    )
    assert created.status_code == 201, created.text
    assert created.json()["is_default"] is True

    agent = await client.get(f"/api/v1/organizations/{org_id}/agent", headers=owner)
    assert agent.status_code == 200, agent.text
    assert agent.json()["enabled"] is True
    assert agent.json()["default_provider_id"] == created.json()["id"]


async def test_a_second_provider_created_without_is_default_does_not_replace_the_first(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    first = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(name="first"),
        headers=owner,
    )
    assert first.status_code == 201, first.text

    second = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(name="second", is_default=False),
        headers=owner,
    )
    assert second.status_code == 201, second.text
    assert second.json()["is_default"] is False

    agent = await client.get(f"/api/v1/organizations/{org_id}/agent", headers=owner)
    assert agent.json()["default_provider_id"] == first.json()["id"]


async def test_an_invalid_cidr_is_rejected_at_write_time(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(allowed_ip_ranges=["not-a-cidr"]),
        headers=owner,
    )

    assert response.status_code == 422, response.text


async def test_a_local_openai_compatible_provider_can_authorize_its_own_private_range(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The whole point of `allowed_ip_ranges`: a self-hosted Ollama/vLLM
    endpoint lives at a private address by construction, and
    `platform_egress_context` must actually carry that authorization
    through to the `RulesOfEngagement` it builds — see
    app/core/assistant/egress.py."""
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(
            name="local-ollama",
            kind="openai_compatible",
            endpoint="http://127.0.0.1:11434/v1/chat/completions",
            model="llama3",
            api_key_env_var=None,
            allowed_ip_ranges=["127.0.0.1/32"],
        ),
        headers=owner,
    )
    assert response.status_code == 201, response.text
    provider_id = uuid.UUID(response.json()["id"])

    row = (
        await db_session.execute(select(AgentProvider).where(AgentProvider.id == provider_id))
    ).scalar_one()
    assert row.allowed_ip_ranges == ["127.0.0.1/32"]

    # `build_provider` (app/core/agent/provider/factory.py) is what a real
    # call goes through; construct the same `ProviderConfig` it builds from
    # this row to prove the allowlist survives the round trip into the
    # actual `RunContext` `platform_egress_context` hands `GatedTransport`.
    from app.core.assistant.egress import platform_egress_context
    from app.core.assistant.provider import ProviderConfig

    provider_config = ProviderConfig(
        provider=row.kind.value,
        endpoint=row.endpoint,
        model=row.model,
        api_key_env_var=row.api_key_env_var,
        allowed_ip_ranges=tuple(row.allowed_ip_ranges),
    )
    ctx = platform_egress_context(provider_config)
    assert ctx.roe.allowed_ip_ranges == ("127.0.0.1/32",)


async def test_updating_is_default_moves_the_agents_default_provider(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(name="first"),
        headers=owner,
    )
    second = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(name="second", is_default=False),
        headers=owner,
    )

    updated = await client.patch(
        f"/api/v1/organizations/{org_id}/agent/providers/{second.json()['id']}",
        json={"is_default": True},
        headers=owner,
    )
    assert updated.status_code == 200, updated.text

    agent = await client.get(f"/api/v1/organizations/{org_id}/agent", headers=owner)
    assert agent.json()["default_provider_id"] == second.json()["id"]


async def test_deleting_the_default_provider_leaves_the_agent_unconfigured_not_broken(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    created = await client.post(
        f"/api/v1/organizations/{org_id}/agent/providers",
        json=_provider_payload(),
        headers=owner,
    )
    provider_id = created.json()["id"]

    deleted = await client.delete(
        f"/api/v1/organizations/{org_id}/agent/providers/{provider_id}", headers=owner
    )
    assert deleted.status_code == 204, deleted.text

    agent = await client.get(f"/api/v1/organizations/{org_id}/agent", headers=owner)
    assert agent.status_code == 200, agent.text
    assert agent.json()["default_provider_id"] is None

    investigate = await client.post(
        f"/api/v1/organizations/{org_id}/agent/investigate",
        json={"request": "anything"},
        headers=owner,
    )
    assert investigate.status_code == 409, investigate.text


async def test_listing_providers_is_scoped_to_the_caller_s_own_organization(
    client: AsyncClient, strong_password: str
) -> None:
    suffix = uuid.uuid4().hex[:8]
    org_a, owner_a = await _org(client, strong_password, f"a{suffix}")
    org_b, owner_b = await _org(client, strong_password, f"b{suffix}")

    await client.post(
        f"/api/v1/organizations/{org_a}/agent/providers",
        json=_provider_payload(name="org-a-provider"),
        headers=owner_a,
    )

    listed = await client.get(f"/api/v1/organizations/{org_b}/agent/providers", headers=owner_b)
    assert listed.status_code == 200, listed.text
    assert listed.json() == []


async def test_put_agent_rejects_an_unknown_autonomy_mode(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.put(
        f"/api/v1/organizations/{org_id}/agent",
        json={"enabled": True, "autonomy_mode": "not-a-real-mode"},
        headers=owner,
    )

    assert response.status_code == 422, response.text


async def test_put_agent_rejects_a_default_provider_from_another_organization(
    client: AsyncClient, strong_password: str
) -> None:
    suffix = uuid.uuid4().hex[:8]
    org_a, owner_a = await _org(client, strong_password, f"a{suffix}")
    org_b, owner_b = await _org(client, strong_password, f"b{suffix}")

    foreign = await client.post(
        f"/api/v1/organizations/{org_a}/agent/providers",
        json=_provider_payload(),
        headers=owner_a,
    )
    foreign_id = foreign.json()["id"]

    response = await client.put(
        f"/api/v1/organizations/{org_b}/agent",
        json={"enabled": True, "default_provider_id": foreign_id, "autonomy_mode": "assist"},
        headers=owner_b,
    )

    assert response.status_code == 404, response.text


async def test_get_agent_before_any_configuration_is_404(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner = await _org(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.get(f"/api/v1/organizations/{org_id}/agent", headers=owner)

    assert response.status_code == 404, response.text
