"""Code-host connection API and publishing (docs/pull-requests.md).

The assertions that matter: a token never reaches the database or a response,
a connection cannot be pointed at a host nobody sanctioned, and a publish that
fails still leaves a record — because "did Kervy comment on that PR?" is a
question someone asks after the fact.
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.probes.models import Category, Confidence, Severity
from app.core.vcs.contract import RepoRef
from app.core.vcs.service import _existing_check_run_id, findings_for_run, publish
from app.models.audit import AuditEvent
from app.models.finding import Finding, Stability
from app.models.vcs import PullRequestPost, VcsConnection
from tests.test_vcs import client_for

TOKEN = "ghp_exampleexampleexampleexample5678"  # pragma: allowlist secret
TOKEN_ENV = "KERVY_TEST_VCS_TOKEN"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _token_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _owner(client: AsyncClient, password: str, suffix: str) -> tuple[str, dict[str, str]]:
    _registered_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    registered = await client.post(
        "/api/v1/auth/register",
        json={
            "email": f"vcsowner{suffix}@example.test",
            "full_name": "VCS Owner",
            "password": password,
        },
        headers={HEADER_NAME: _registered_anon_token},
    )
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"VCS Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    return org_id, headers


async def _run(
    client: AsyncClient, org_id: str, headers: dict[str, str], db_session: AsyncSession
) -> str:
    """A target and a completed run to publish the findings of."""
    from app.models.assessment_run import AssessmentRun, RunStatus

    target_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/targets",
            json={
                "name": "acme-api",
                "environment": "staging",
                "kind": "llm_app",
                "base_url": "https://acme-api.example.test",
            },
            headers=headers,
        )
    ).json()["id"]
    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
    )
    db_session.add(run)
    await db_session.commit()
    return str(run.id)


def connection_payload(**extra: object) -> dict[str, object]:
    return {
        "name": "github",
        "provider": "github",
        "token_env_var": TOKEN_ENV,
        **extra,
    }


def _finding_row(*, organization_id: uuid.UUID, run_id: uuid.UUID, fingerprint: str) -> Finding:
    """The minimal valid row `findings_for_run` can select — real
    findings/promotion is a different module's concern; this one only
    needs a shape the `Finding` model accepts."""
    now = datetime.now(UTC)
    return Finding(
        organization_id=organization_id,
        fingerprint=fingerprint,
        title="A finding",
        category=Category.INFRASTRUCTURE,
        probe_id="test",
        probe_version="1",
        surface="https://acme-api.example.test/",
        severity=Severity.HIGH,
        severity_rationale="7/10",
        confidence=Confidence.HIGH,
        stability=Stability.DETERMINISTIC,
        risk_model="kervy-v1",
        risk_score=7.0,
        risk_inputs={},
        description="d",
        impact="i",
        remediation="r",
        reproduction=[],
        mappings={},
        mapping_versions={},
        first_seen=now,
        last_seen=now,
        first_run_id=run_id,
        last_run_id=run_id,
    )


async def test_a_connection_stores_no_token_only_a_variable_name(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, headers = await _owner(client, strong_password, "a")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections",
        json=connection_payload(),
        headers=headers,
    )
    assert response.status_code == 201, response.text
    assert TOKEN not in response.text
    assert response.json()["token_env_var"] == TOKEN_ENV

    stored = (
        await db_session.execute(
            select(VcsConnection).where(VcsConnection.id == uuid.UUID(response.json()["id"]))
        )
    ).scalar_one()
    row = {column.name: getattr(stored, column.name) for column in VcsConnection.__table__.columns}
    assert not any(isinstance(value, str) and TOKEN in value for value in row.values())


async def test_a_github_connection_cannot_name_another_host(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "b")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections",
        json=connection_payload(api_host="attacker.test"),
        headers=headers,
    )
    assert response.status_code == 422


async def test_an_enterprise_host_outside_the_operator_allowlist_is_refused(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, headers = await _owner(client, strong_password, "c")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections",
        json={
            "name": "enterprise",
            "provider": "github_enterprise",
            "token_env_var": TOKEN_ENV,
            "api_host": "git.internal.test",
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "KERVY_VCS_ALLOWED_HOSTS" in response.json()["error"]["message"]

    # The attempt to add an outbound destination is recorded even though it
    # failed — that is the shape of someone probing for an egress path.
    refusals = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.action == "vcs_connection.refused")
            )
        )
        .scalars()
        .all()
    )
    assert len(refusals) == 1


async def test_a_missing_token_variable_is_refused_at_creation(
    client: AsyncClient, strong_password: str
) -> None:
    """A connection that would only fail mid-review is refused now."""
    org_id, headers = await _owner(client, strong_password, "d")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections",
        json=connection_payload(token_env_var="KERVY_TEST_VCS_ABSENT"),
        headers=headers,
    )
    assert response.status_code == 422
    assert "KERVY_TEST_VCS_ABSENT" in response.json()["error"]["message"]
    assert TOKEN not in response.text


async def test_a_token_pasted_where_a_variable_name_belongs_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "e")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections",
        json=connection_payload(token_env_var=TOKEN),
        headers=headers,
    )
    assert response.status_code == 422


async def test_an_analyst_can_read_but_not_create(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _owner(client, strong_password, "f")
    _analyst_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    analyst = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "vcs-analyst@example.test",
            "full_name": "Analyst",
            "password": strong_password,
        },
        headers={HEADER_NAME: _analyst_anon_token},
    )
    analyst_headers = {"Authorization": f"Bearer {analyst.json()['access_token']}"}
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "vcs-analyst@example.test", "role": "analyst"},
        headers=owner_headers,
    )
    assert (
        await client.get(f"/api/v1/organizations/{org_id}/vcs-connections", headers=analyst_headers)
    ).status_code == 200
    assert (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=analyst_headers,
        )
    ).status_code == 403


async def test_a_connection_in_another_organization_is_not_found(
    client: AsyncClient, strong_password: str
) -> None:
    org_a, headers_a = await _owner(client, strong_password, "g")
    org_b, headers_b = await _owner(client, strong_password, "h")
    created = await client.post(
        f"/api/v1/organizations/{org_a}/vcs-connections",
        json=connection_payload(),
        headers=headers_a,
    )
    connection_id = created.json()["id"]
    response = await client.patch(
        f"/api/v1/organizations/{org_b}/vcs-connections/{connection_id}",
        json={"enabled": False},
        headers=headers_b,
    )
    assert response.status_code == 404


async def test_publishing_through_a_disabled_connection_is_a_conflict(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "i")
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    await client.patch(
        f"/api/v1/organizations/{org_id}/vcs-connections/{connection_id}",
        json={"enabled": False},
        headers=headers,
    )
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections/{connection_id}/publish",
        json={
            "repo_owner": "acme",
            "repo_name": "api",
            "pull_number": 7,
            "head_sha": "a" * 40,
            "run_id": str(uuid.uuid4()),
        },
        headers=headers,
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    "bad",
    [
        {"repo_owner": "acme/../../evil"},
        {"repo_name": "api/../secrets"},
        {"head_sha": "not-a-sha"},
        {"pull_number": 0},
    ],
)
async def test_a_slug_cannot_smuggle_a_path_segment_into_an_api_url(
    client: AsyncClient, strong_password: str, bad: dict[str, object]
) -> None:
    org_id, headers = await _owner(client, strong_password, "j")
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    payload: dict[str, object] = {
        "repo_owner": "acme",
        "repo_name": "api",
        "pull_number": 7,
        "head_sha": "a" * 40,
        "run_id": str(uuid.uuid4()),
        **bad,
    }
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections/{connection_id}/publish",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 422


async def test_a_failed_publish_still_leaves_a_record_and_an_audit_event(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The host is unreachable from the test environment, which is the point:
    a publish that did not land must still be answerable afterwards."""
    org_id, headers = await _owner(client, strong_password, "k")
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    run_id = await _run(client, org_id, headers, db_session)

    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections/{connection_id}/publish",
        json={
            "repo_owner": "acme",
            "repo_name": "api",
            "pull_number": 7,
            "head_sha": "a" * 40,
            "run_id": run_id,
        },
        headers=headers,
    )
    # A 200 carrying the record: the caller asked us to try, we tried, and the
    # outcome is the answer. A 5xx would suggest a malformed request.
    assert response.status_code == 200, response.text
    assert TOKEN not in response.text

    posts = (
        (
            await db_session.execute(
                select(PullRequestPost).where(PullRequestPost.organization_id == uuid.UUID(org_id))
            )
        )
        .scalars()
        .all()
    )
    assert len(posts) == 1
    assert posts[0].repo_slug == "acme/api"

    audited = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.resource_type == "pull_request_post")
            )
        )
        .scalars()
        .all()
    )
    assert len(audited) == 1
    assert TOKEN not in str(audited[0].metadata_json)

    listed = await client.get(
        f"/api/v1/organizations/{org_id}/vcs-connections/{connection_id}/posts",
        headers=headers,
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1


async def test_a_duplicate_linked_finding_is_excluded_from_a_pull_request_publish(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The same exclusion `app/core/reporting/build.py` already applies to a
    run's own report: a finding a human has explicitly linked as a duplicate
    of another must not also count twice toward a PR check run or the gate
    it is judged by — that is the whole point of recording the link."""
    org_id, headers = await _owner(client, strong_password, "r")
    run_id = await _run(client, org_id, headers, db_session)

    primary = _finding_row(
        organization_id=uuid.UUID(org_id),
        run_id=uuid.UUID(run_id),
        fingerprint="sha256:" + "a" * 64,
    )
    duplicate = _finding_row(
        organization_id=uuid.UUID(org_id),
        run_id=uuid.UUID(run_id),
        fingerprint="sha256:" + "b" * 64,
    )
    db_session.add_all([primary, duplicate])
    await db_session.commit()

    before = await findings_for_run(db_session, uuid.UUID(org_id), uuid.UUID(run_id))
    assert {f.id for f in before} == {primary.id, duplicate.id}

    link = await client.post(
        f"/api/v1/organizations/{org_id}/findings/{duplicate.id}/duplicate",
        json={"duplicate_of_finding_id": str(primary.id)},
        headers=headers,
    )
    assert link.status_code == 200, link.text

    after = await findings_for_run(db_session, uuid.UUID(org_id), uuid.UUID(run_id))
    assert {f.id for f in after} == {primary.id}


async def test_publishing_an_unknown_run_is_a_404_not_a_500(
    client: AsyncClient, strong_password: str
) -> None:
    """A run id from another organization must be indistinguishable from one
    that does not exist — and neither may reach the foreign key as a crash."""
    org_id, headers = await _owner(client, strong_password, "m")
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    response = await client.post(
        f"/api/v1/organizations/{org_id}/vcs-connections/{connection_id}/publish",
        json={
            "repo_owner": "acme",
            "repo_name": "api",
            "pull_number": 7,
            "head_sha": "a" * 40,
            "run_id": str(uuid.uuid4()),
        },
        headers=headers,
    )
    assert response.status_code == 404


async def test_another_organizations_run_cannot_be_published(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_a, headers_a = await _owner(client, strong_password, "n")
    org_b, headers_b = await _owner(client, strong_password, "o")
    run_id = await _run(client, org_a, headers_a, db_session)
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_b}/vcs-connections",
            json=connection_payload(),
            headers=headers_b,
        )
    ).json()["id"]
    response = await client.post(
        f"/api/v1/organizations/{org_b}/vcs-connections/{connection_id}/publish",
        json={
            "repo_owner": "acme",
            "repo_name": "api",
            "pull_number": 7,
            "head_sha": "a" * 40,
            "run_id": run_id,
        },
        headers=headers_b,
    )
    assert response.status_code == 404


async def _connection_row(db_session: AsyncSession, connection_id: str) -> VcsConnection:
    return (
        await db_session.execute(
            select(VcsConnection).where(VcsConnection.id == uuid.UUID(connection_id))
        )
    ).scalar_one()


async def test_republishing_for_the_same_head_sha_updates_the_check_run_in_place(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The HTTP `/publish` route has no way to inject a test double, so this
    calls `app.core.vcs.service.publish()` directly — the only way to assert
    that a second publish for a head SHA this repo already has a check run
    for `PATCH`es that run instead of `POST`ing a second one."""
    org_id, headers = await _owner(client, strong_password, "p")
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    connection = await _connection_row(db_session, connection_id)
    run_id = await _run(client, org_id, headers, db_session)
    finding = _finding_row(
        organization_id=uuid.UUID(org_id),
        run_id=uuid.UUID(run_id),
        fingerprint="sha256:" + "c" * 64,
    )
    db_session.add(finding)
    await db_session.commit()

    repo = RepoRef("acme", "api")
    head_sha = "a" * 40

    first_client, _ = client_for(
        [
            (200, []),
            (201, {"id": 111, "html_url": "https://github.com/acme/api/runs/111"}),
        ]
    )
    first_post, first_outcome = await publish(
        db_session,
        connection,
        repo=repo,
        pull_number=7,
        head_sha=head_sha,
        findings=[finding],
        run_id=uuid.UUID(run_id),
        client=first_client,
    )
    assert first_outcome.posted
    assert first_post.check_run_id == 111

    second_client, second_transport = client_for(
        [
            (200, []),
            (200, {"id": 111, "html_url": "https://github.com/acme/api/runs/111"}),
        ]
    )
    second_post, second_outcome = await publish(
        db_session,
        connection,
        repo=repo,
        pull_number=7,
        head_sha=head_sha,
        findings=[finding],
        run_id=uuid.UUID(run_id),
        client=second_client,
    )
    assert second_outcome.posted
    assert second_post.id != first_post.id
    assert second_post.check_run_id == 111
    # One GET (the diff) then one PATCH to the exact run the first publish
    # created — never a second POST, which would be a duplicate comment.
    assert [call["method"] for call in second_transport.calls] == ["GET", "PATCH"]
    assert str(second_transport.calls[1]["url"]).endswith("/check-runs/111")


async def test_republishing_for_a_different_head_sha_creates_a_fresh_check_run(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """A new commit on the same pull request has nothing yet to update — the
    lookup must not reuse the previous SHA's check run."""
    org_id, headers = await _owner(client, strong_password, "q")
    connection_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    connection = await _connection_row(db_session, connection_id)
    run_id = await _run(client, org_id, headers, db_session)
    finding = _finding_row(
        organization_id=uuid.UUID(org_id),
        run_id=uuid.UUID(run_id),
        fingerprint="sha256:" + "d" * 64,
    )
    db_session.add(finding)
    await db_session.commit()

    repo = RepoRef("acme", "api")

    first_client, _ = client_for(
        [
            (200, []),
            (201, {"id": 111, "html_url": "https://github.com/acme/api/runs/111"}),
        ]
    )
    await publish(
        db_session,
        connection,
        repo=repo,
        pull_number=7,
        head_sha="a" * 40,
        findings=[finding],
        run_id=uuid.UUID(run_id),
        client=first_client,
    )

    second_client, second_transport = client_for(
        [
            (200, []),
            (201, {"id": 222, "html_url": "https://github.com/acme/api/runs/222"}),
        ]
    )
    second_post, second_outcome = await publish(
        db_session,
        connection,
        repo=repo,
        pull_number=7,
        head_sha="b" * 40,
        findings=[finding],
        run_id=uuid.UUID(run_id),
        client=second_client,
    )
    assert second_outcome.posted
    assert second_post.check_run_id == 222
    assert [call["method"] for call in second_transport.calls] == ["GET", "POST"]


async def test_existing_check_run_id_ignores_other_shas_and_failed_posts(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """Unit-level coverage of the lookup itself: it is scoped to the exact
    connection, repo, pull request and head SHA, and a post that never got a
    check run (every attempt failed before GitHub answered) is not a match."""
    org_id, headers = await _owner(client, strong_password, "s")
    connection_row_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/vcs-connections",
            json=connection_payload(),
            headers=headers,
        )
    ).json()["id"]
    org_id = uuid.UUID(org_id)
    connection_id = uuid.UUID(connection_row_id)
    repo = RepoRef("acme", "api")

    async def _none_for(head_sha: str) -> int | None:
        return await _existing_check_run_id(
            db_session,
            connection_id=connection_id,
            repo=repo,
            pull_number=7,
            head_sha=head_sha,
        )

    assert await _none_for("a" * 40) is None

    failed = PullRequestPost(
        organization_id=org_id,
        connection_id=connection_id,
        repo_slug=repo.slug,
        pull_number=7,
        head_sha="a" * 40,
        conclusion="neutral",
        findings_total=0,
        fingerprints=[],
    )
    db_session.add(failed)
    # Committed, not merely flushed: `created_at` is `func.now()`, which
    # Postgres resolves once per transaction — the lookup's "most recent
    # wins" ordering needs each post in its own transaction to mean anything,
    # exactly as it does in production, where each publish() is its own
    # request.
    await db_session.commit()
    # Never posted: `check_run_id` stays unset, so it must not be matched.
    assert await _none_for("a" * 40) is None

    older = PullRequestPost(
        organization_id=org_id,
        connection_id=connection_id,
        repo_slug=repo.slug,
        pull_number=7,
        head_sha="a" * 40,
        conclusion="neutral",
        findings_total=0,
        fingerprints=[],
        check_run_id=111,
    )
    db_session.add(older)
    await db_session.commit()
    assert await _none_for("a" * 40) == 111

    newer = PullRequestPost(
        organization_id=org_id,
        connection_id=connection_id,
        repo_slug=repo.slug,
        pull_number=7,
        head_sha="a" * 40,
        conclusion="neutral",
        findings_total=0,
        fingerprints=[],
        check_run_id=222,
    )
    db_session.add(newer)
    await db_session.commit()
    # The most recent post for this exact SHA wins.
    assert await _none_for("a" * 40) == 222
    # A different head SHA on the same pull request is a different commit —
    # nothing to update yet.
    assert await _none_for("b" * 40) is None
