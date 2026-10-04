"""The workflow API (docs/BUILD_SPEC.md §26 Phase 17, docs/workflows.md).

`tests/test_workflow.py` asserts the plan and the gate as pure functions. This
file asserts the endpoint around them, and concentrates on the three places an
API can quietly undo a guarantee the core got right:

* a **malformed gate** must be refused where it is typed, never stored to be
  read later as "no gate";
* a **disabled** workflow must not be runnable by URL;
* the **plan digest** must be stable, because a digest that moved on its own
  would make "did the plan change?" unanswerable.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME

LAB_HOST = "wf.example.test"
LAB_URL = f"http://{LAB_HOST}"


async def _setup(
    client: AsyncClient, password: str, suffix: str
) -> tuple[str, str, dict[str, str]]:
    _owner_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    owner = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"wf{suffix}@example.test",
            "full_name": "WF Owner",
            "password": password,
        },
        headers={HEADER_NAME: _owner_anon_token},
    )
    headers = {"Authorization": f"Bearer {owner.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"WF Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "Workflow target",
                "environment": "test",
                "kind": "api",
                "base_url": LAB_URL,
            },
            headers=headers,
        )
    ).json()["id"]
    return org_id, target_id, headers


async def test_a_workflow_can_be_created_listed_and_read(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    created = await client.post(
        f"/api/v1/organizations/{org_id}/workflows",
        json={"name": "main branch", "target_id": target_id},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["trigger_kind"] == "repository_change"
    assert body["enabled"] is True
    assert body["gate_config"] is None

    listed = await client.get(f"/api/v1/organizations/{org_id}/workflows", headers=headers)
    assert [item["id"] for item in listed.json()] == [body["id"]]

    fetched = await client.get(
        f"/api/v1/organizations/{org_id}/workflows/{body['id']}", headers=headers
    )
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "main branch"


async def test_a_duplicate_workflow_name_is_a_conflict(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    payload = {"name": "same", "target_id": target_id}
    first = await client.post(
        f"/api/v1/organizations/{org_id}/workflows", json=payload, headers=headers
    )
    second = await client.post(
        f"/api/v1/organizations/{org_id}/workflows", json=payload, headers=headers
    )
    assert first.status_code == 201
    # 409 rather than the database's own unique-constraint 500: a name clash is
    # something the caller can act on.
    assert second.status_code == 409


async def test_a_target_in_another_organization_cannot_be_used(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, _, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    _, other_target, _ = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows",
        json={"name": "cross tenant", "target_id": other_target},
        headers=headers,
    )
    assert response.status_code == 404


async def test_a_malformed_gate_is_refused_where_it_is_typed(
    client: AsyncClient, strong_password: str
) -> None:
    """A gate that cannot be parsed must never be stored.

    The gate's own rule is that a misconfigured gate never reports a pass. That
    holds at evaluation time — `finish` refuses — but storing the broken
    configuration would mean discovering it during a release rather than during
    a change to the workflow.

    Verified by removing the validator: this returns 201.
    """
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])

    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows",
        json={
            "name": "broken gate",
            "target_id": target_id,
            "gate_config": {"fail_on": ["critical"], "max_hihg": 0},
        },
        headers=headers,
    )
    assert response.status_code == 422, response.text
    assert "gate" in response.text.lower()

    listed = await client.get(f"/api/v1/organizations/{org_id}/workflows", headers=headers)
    assert listed.json() == []


async def test_a_disabled_workflow_cannot_be_triggered_by_url(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "off", "target_id": target_id, "enabled": False},
            headers=headers,
        )
    ).json()["id"]

    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs",
        json={},
        headers=headers,
    )
    assert response.status_code == 409
    assert "disabled" in response.text


async def test_running_a_workflow_stores_the_plan_and_a_gate_decision(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "ci", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]

    response = await client.post(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs",
        json={"ref": "refs/heads/main", "commit": "a" * 40},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    run = response.json()

    assert run["status"] == "completed"
    assert run["plan_digest"].startswith("sha256:")
    assert [stage["stage"] for stage in run["stages"]] == [
        "trigger",
        "plan",
        "actions",
        "evidence",
        "result",
    ]
    # No findings yet, so the gate passes — and says so with an exit code the
    # CLI documents rather than an empty result.
    assert run["gate_passed"] is True
    assert run["gate_exit_code"] == 0

    # Every skipped action carries its reason, so "nothing was found" is
    # distinguishable from "nothing was looked for".
    skipped = [a for a in run["plan"]["actions"] if a["skipped"]]
    assert skipped
    assert all(action["reason"] for action in skipped)


async def test_the_same_configuration_produces_the_same_plan_digest(
    client: AsyncClient, strong_password: str
) -> None:
    """A digest that moved on its own would make plan comparison meaningless.

    Verified by adding the trigger's commit to the digest input: the two
    digests then differ although nothing about what would run changed.
    """
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "stable", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]

    digests = []
    for commit in ("a" * 40, "b" * 40):
        response = await client.post(
            f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs",
            json={"ref": "refs/heads/main", "commit": commit},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        digests.append(response.json()["plan_digest"])

    assert digests[0] == digests[1]

    runs = await client.get(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}/runs", headers=headers
    )
    assert runs.status_code == 200
    assert len(runs.json()) == 2


async def test_changing_the_gate_is_recorded_as_changing_the_gate(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "gated", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]

    updated = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}",
        json={"gate_config": {"fail_on": ["critical", "high"], "max_medium": 5}},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["gate_config"] == {"fail_on": ["critical", "high"], "max_medium": 5}

    # And a malformed one is still refused on update, not only on create.
    broken = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}",
        json={"gate_config": {"fail_on": ["nonsense"]}},
        headers=headers,
    )
    assert broken.status_code == 422

    unchanged = await client.get(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}", headers=headers
    )
    assert unchanged.json()["gate_config"] == {"fail_on": ["critical", "high"], "max_medium": 5}


async def test_renaming_a_workflow_to_an_existing_name_is_a_conflict(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    await client.post(
        f"/api/v1/organizations/{org_id}/workflows",
        json={"name": "taken", "target_id": target_id},
        headers=headers,
    )
    other_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "free", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]

    # Renaming to a name already used by a *different* workflow in this
    # organization must be the same 409 a duplicate create gets, not the
    # database's own unique-constraint 500.
    collision = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{other_id}",
        json={"name": "taken"},
        headers=headers,
    )
    assert collision.status_code == 409, collision.text

    # Renaming to its own current name (a no-op) must not be refused as a
    # collision with itself.
    noop = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{other_id}",
        json={"name": "free"},
        headers=headers,
    )
    assert noop.status_code == 200, noop.text


async def test_editing_an_unrelated_field_does_not_reset_the_schedule_timer(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={
                "name": "scheduled",
                "target_id": target_id,
                "trigger_kind": "schedule",
                "schedule_interval_minutes": 120,
            },
            headers=headers,
        )
    ).json()["id"]
    first = (
        await client.get(f"/api/v1/organizations/{org_id}/workflows/{workflow_id}", headers=headers)
    ).json()
    assert first["next_run_at"] is not None

    # Toggling something unrelated to the schedule must leave the existing
    # countdown alone rather than re-arming it from now.
    toggled = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}",
        json={"enabled": False},
        headers=headers,
    )
    assert toggled.status_code == 200, toggled.text
    assert toggled.json()["next_run_at"] == first["next_run_at"]

    # Actually changing the interval does re-arm it.
    rescheduled = await client.patch(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}",
        json={"schedule_interval_minutes": 180},
        headers=headers,
    )
    assert rescheduled.status_code == 200, rescheduled.text
    assert rescheduled.json()["next_run_at"] != first["next_run_at"]


async def test_a_deleted_workflow_is_gone(client: AsyncClient, strong_password: str) -> None:
    org_id, target_id, headers = await _setup(client, strong_password, uuid.uuid4().hex[:8])
    workflow_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/workflows",
            json={"name": "temporary", "target_id": target_id},
            headers=headers,
        )
    ).json()["id"]

    deleted = await client.delete(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}", headers=headers
    )
    assert deleted.status_code == 204
    missing = await client.get(
        f"/api/v1/organizations/{org_id}/workflows/{workflow_id}", headers=headers
    )
    assert missing.status_code == 404
