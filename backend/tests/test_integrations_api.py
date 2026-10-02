"""Notification channel API (docs/BUILD_SPEC.md §27).

What the tests here are really checking is that the database never becomes a
place a secret lives, and never becomes a way to widen egress. A channel is
created by an organization admin — someone the platform trusts with a lot, but
not with choosing a brand-new outbound destination, which is an operator
decision recorded in the environment.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.models.audit import AuditEvent
from app.models.integration import NotificationChannel

# pragma: allowlist nextline secret
SLACK_URL = "https://hooks.slack.com/services/T111/B222/zzzzzzzzzzzzzzzzzzzzzzzz"
SLACK_ENV = "KERVY_TEST_SLACK_WEBHOOK"


@pytest.fixture(autouse=True)
def _slack_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    # The settings object is cached, and these tests change what an operator
    # has sanctioned, so the cache has to go with them.
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
            "email": f"chanowner{suffix}@example.test",
            "full_name": "Channel Owner",
            "password": password,
        },
        headers={HEADER_NAME: _registered_anon_token},
    )
    headers = {"Authorization": f"Bearer {registered.json()['access_token']}"}
    org_id = (
        await client.post(
            "/api/v1/organizations", json={"name": f"Chan Org {suffix}"}, headers=headers
        )
    ).json()["id"]
    return org_id, headers


def _finding_fields() -> dict[str, object]:
    """The non-nullable columns a finding needs, filled with plausible values.

    Spelled out here rather than going through the promotion service, so this
    test stays about the notification fan-out.
    """
    from datetime import UTC, datetime

    from app.core.probes.models import Category, Confidence, Severity
    from app.models.finding import Stability

    now = datetime.now(UTC)
    return {
        "category": Category.API_SECURITY,
        "probe_id": "KERVY-API-050",
        "probe_version": "1.0.0",
        "surface": "GET /orders/{id}",
        "severity": Severity.CRITICAL,
        "severity_rationale": "authenticated cross-tenant read",
        "confidence": Confidence.HIGH,
        "stability": Stability.DETERMINISTIC,
        "risk_model": "kervy-ordinal-v1",
        "risk_score": 9,
        "description": "Another tenant's order is readable.",
        "impact": "Cross-tenant data exposure.",
        "remediation": "Authorize the object, not just the caller.",
        "first_seen": now,
        "last_seen": now,
    }


async def _target(client: AsyncClient, org_id: str, headers: dict[str, str]) -> str:
    return (
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


def slack_payload(**extra: object) -> dict[str, object]:
    return {
        "name": "sec-alerts",
        "kind": "slack_webhook",
        "events": ["finding.critical"],
        "endpoint_env_var": SLACK_ENV,
        **extra,
    }


# --- creation ---------------------------------------------------------------


async def test_a_created_channel_stores_no_url_only_a_variable_name(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, headers = await _owner(client, strong_password, "a")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(),
        headers=headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["endpoint_env_var"] == SLACK_ENV
    # The token lives in the URL path, so no part of it may be returned.
    assert "zzzzzzzzzzzzzzzzzzzzzzzz" not in response.text
    assert "hooks.slack.com" in body["endpoint_redacted"]
    assert "services" not in body["endpoint_redacted"]

    stored = (
        await db_session.execute(
            select(NotificationChannel).where(NotificationChannel.id == uuid.UUID(body["id"]))
        )
    ).scalar_one()
    # The decisive assertion: the row itself cannot hold the credential.
    row = {
        column.name: getattr(stored, column.name)
        for column in NotificationChannel.__table__.columns
    }
    assert not any(
        isinstance(value, str) and "zzzzzzzzzzzzzzzzzzzzzzzz" in value for value in row.values()
    )


async def test_a_channel_pointing_at_an_unsanctioned_host_is_refused(
    client: AsyncClient, strong_password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    org_id, headers = await _owner(client, strong_password, "b")
    monkeypatch.setenv("KERVY_TEST_EVIL", "https://attacker.test/collect")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "evil",
            "kind": "generic_webhook",
            "events": ["finding.critical"],
            "endpoint_env_var": "KERVY_TEST_EVIL",
            "signing_secret_env_var": "KERVY_TEST_SIGNING",  # pragma: allowlist secret
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "not permitted" in response.json()["error"]["message"]


async def test_a_refused_channel_is_audited(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An attempt to add an outbound destination is worth recording even when
    it failed — that is the shape of someone probing for an egress path."""
    org_id, headers = await _owner(client, strong_password, "c")
    monkeypatch.setenv("KERVY_TEST_EVIL2", "https://169.254.169.254/latest/meta-data/")
    await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "meta",
            "kind": "generic_webhook",
            "events": ["finding.critical"],
            "endpoint_env_var": "KERVY_TEST_EVIL2",
            "signing_secret_env_var": "KERVY_TEST_SIGNING",  # pragma: allowlist secret
        },
        headers=headers,
    )
    events = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.action == "notification_channel.refused")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


async def test_a_missing_endpoint_variable_is_refused_at_creation(
    client: AsyncClient, strong_password: str
) -> None:
    """A channel that would only fail during an incident is refused now."""
    org_id, headers = await _owner(client, strong_password, "d")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(endpoint_env_var="KERVY_TEST_ABSENT"),
        headers=headers,
    )
    assert response.status_code == 422
    assert "KERVY_TEST_ABSENT" in response.json()["error"]["message"]


async def test_a_url_pasted_where_a_variable_name_belongs_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "e")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(endpoint_env_var=SLACK_URL),
        headers=headers,
    )
    assert response.status_code == 422


async def test_a_generic_webhook_without_a_signing_secret_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "f")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "siem",
            "kind": "generic_webhook",
            "events": ["finding.critical"],
            "endpoint_env_var": SLACK_ENV,
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "signing_secret_env_var" in response.text


# --- RBAC and tenancy -------------------------------------------------------


async def test_an_analyst_can_read_but_not_create(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, owner_headers = await _owner(client, strong_password, "g")
    _analyst_anon_token = (await client.get("/api/v1/auth/csrf")).cookies[
        csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)
    ]
    analyst = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "chan-analyst@example.test",
            "full_name": "Analyst",
            "password": strong_password,
        },
        headers={HEADER_NAME: _analyst_anon_token},
    )
    analyst_headers = {"Authorization": f"Bearer {analyst.json()['access_token']}"}
    await client.post(
        f"/api/v1/organizations/{org_id}/members",
        json={"email": "chan-analyst@example.test", "role": "analyst"},
        headers=owner_headers,
    )

    assert (
        await client.get(
            f"/api/v1/organizations/{org_id}/notification-channels", headers=analyst_headers
        )
    ).status_code == 200
    assert (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=analyst_headers,
        )
    ).status_code == 403


async def test_a_channel_in_another_organization_is_not_found(
    client: AsyncClient, strong_password: str
) -> None:
    org_a, headers_a = await _owner(client, strong_password, "h")
    org_b, headers_b = await _owner(client, strong_password, "i")
    created = await client.post(
        f"/api/v1/organizations/{org_a}/notification-channels",
        json=slack_payload(),
        headers=headers_a,
    )
    channel_id = created.json()["id"]
    # 404, not 403: existence in another tenant must not be observable.
    response = await client.patch(
        f"/api/v1/organizations/{org_b}/notification-channels/{channel_id}",
        json={"enabled": False},
        headers=headers_b,
    )
    assert response.status_code == 404


# --- update and delete ------------------------------------------------------


async def test_a_channel_can_be_muted_and_resubscribed(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "j")
    channel_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=headers,
        )
    ).json()["id"]

    patched = await client.patch(
        f"/api/v1/organizations/{org_id}/notification-channels/{channel_id}",
        json={"enabled": False, "events": ["assessment.completed"], "min_severity": "HIGH"},
        headers=headers,
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False
    assert patched.json()["events"] == ["assessment.completed"]
    assert patched.json()["min_severity"] == "HIGH"


async def test_the_endpoint_cannot_be_repointed_in_place(
    client: AsyncClient, strong_password: str
) -> None:
    """Changing where a channel points is creating a different channel: doing
    it in place would leave the delivery history attached to a destination it
    never reached."""
    org_id, headers = await _owner(client, strong_password, "k")
    channel_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=headers,
        )
    ).json()["id"]
    patched = await client.patch(
        f"/api/v1/organizations/{org_id}/notification-channels/{channel_id}",
        json={"endpoint_env_var": "KERVY_TEST_OTHER"},
        headers=headers,
    )
    # The field is not on the update schema, so it is ignored rather than
    # applied — and the stored value is unchanged.
    assert patched.status_code == 200
    assert patched.json()["endpoint_env_var"] == SLACK_ENV


async def test_deleting_a_channel_is_audited(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    org_id, headers = await _owner(client, strong_password, "m")
    channel_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=headers,
        )
    ).json()["id"]
    response = await client.delete(
        f"/api/v1/organizations/{org_id}/notification-channels/{channel_id}", headers=headers
    )
    assert response.status_code == 204
    actions = {
        event.action
        for event in (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.resource_type == "notification_channel")
            )
        ).scalars()
    }
    assert "notification_channel.delete" in actions


# --- test delivery ----------------------------------------------------------


async def test_a_test_delivery_is_recorded_and_audited_even_when_it_fails(
    client: AsyncClient,
    strong_password: str,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The channel resolves, but the destination is unreachable from here. The
    point is that the attempt leaves a trace either way: "was the team told?"
    is a question an incident review asks."""
    org_id, headers = await _owner(client, strong_password, "n")
    channel_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=headers,
        )
    ).json()["id"]

    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels/{channel_id}/test",
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    # Whether it reached Slack depends on the environment; what must hold is
    # that nothing about the token appears in the result.
    assert "zzzzzzzzzzzzzzzzzzzzzzzz" not in response.text
    assert body["delivery_id"]

    deliveries = await client.get(
        f"/api/v1/organizations/{org_id}/notification-channels/{channel_id}/deliveries",
        headers=headers,
    )
    assert deliveries.status_code == 200
    assert len(deliveries.json()) == 1
    assert "zzzzzzzzzzzzzzzzzzzzzzzz" not in deliveries.text

    audited = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.resource_type == "notification_delivery")
            )
        )
        .scalars()
        .all()
    )
    assert len(audited) == 1
    assert "zzzzzzzzzzzzzzzzzzzzzzzz" not in str(audited[0].metadata_json)


# --- delivery lifecycle -----------------------------------------------------


async def test_only_subscribed_channels_get_a_delivery_row(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The delivery table records intent, not everything that ever happened."""
    from app.core.integrations.dispatch import event_for_finding
    from app.core.integrations.service import enqueue

    org_id, headers = await _owner(client, strong_password, "p")
    await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(name="criticals-only", events=["finding.critical"]),
        headers=headers,
    )
    await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(name="runs-only", events=["assessment.completed"]),
        headers=headers,
    )

    event = event_for_finding(
        organization_id=uuid.UUID(org_id),
        finding_id=uuid.uuid4(),
        title="BOLA on /orders/{id}",
        severity="critical",
        target_name="acme-api",
    )
    deliveries = await enqueue(db_session, event)
    await db_session.commit()
    assert len(deliveries) == 1


async def test_a_dead_lettered_delivery_is_not_picked_up_again(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    from datetime import UTC, datetime, timedelta

    from app.core.integrations.service import due_deliveries
    from app.models.integration import DeliveryStatus, NotificationDelivery

    org_id, headers = await _owner(client, strong_password, "q")
    channel_id = (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=headers,
        )
    ).json()["id"]

    past = datetime.now(UTC) - timedelta(minutes=1)
    for status in (
        DeliveryStatus.FAILED,
        DeliveryStatus.DEAD_LETTER,
        DeliveryStatus.REFUSED,
        DeliveryStatus.DELIVERED,
    ):
        db_session.add(
            NotificationDelivery(
                organization_id=uuid.UUID(org_id),
                channel_id=uuid.UUID(channel_id),
                event_type="finding.critical",
                status=status.value,
                attempts=1,
                next_attempt_at=past,
                event_json={"event_type": "finding.critical", "title": "x"},
            )
        )
    await db_session.flush()

    due = await due_deliveries(db_session)
    # Only the retryable one. Excluded by status rather than by attempt count,
    # so changing MAX_ATTEMPTS can never resurrect a dead-lettered row.
    assert [delivery.status for delivery in due] == [DeliveryStatus.FAILED.value]


async def test_an_attempt_is_audited_with_the_redacted_endpoint_only(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    from app.core.integrations.dispatch import event_for_finding
    from app.core.integrations.service import attempt
    from app.models.integration import DeliveryStatus, NotificationDelivery

    org_id, headers = await _owner(client, strong_password, "r")
    created = (
        await client.post(
            f"/api/v1/organizations/{org_id}/notification-channels",
            json=slack_payload(),
            headers=headers,
        )
    ).json()
    channel = await db_session.get(NotificationChannel, uuid.UUID(created["id"]))
    assert channel is not None

    delivery = NotificationDelivery(
        organization_id=uuid.UUID(org_id),
        channel_id=channel.id,
        event_type="finding.critical",
        status=DeliveryStatus.PENDING.value,
        attempts=0,
    )
    db_session.add(delivery)
    await db_session.flush()

    event = event_for_finding(
        organization_id=uuid.UUID(org_id),
        finding_id=uuid.uuid4(),
        title="BOLA on /orders/{id}",
        severity="critical",
        target_name="acme-api",
    )
    await attempt(db_session, delivery, channel, event)
    await db_session.flush()

    audited = (
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.resource_type == "notification_delivery")
            )
        )
        .scalars()
        .all()
    )
    assert len(audited) == 1
    metadata = audited[0].metadata_json or {}
    assert metadata["channel_kind"] == "slack_webhook"
    assert metadata["attempt"] == 1
    assert "zzzzzzzzzzzzzzzzzzzzzzzz" not in str(metadata)
    # The attempt counter advanced, which is what stops an infinite retry.
    assert delivery.attempts == 1


async def test_a_finished_run_fans_out_to_subscribed_channels(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """The run-completion path, exercised end to end against the database.

    Asserts what a reader of `docs/integrations.md` would expect: one delivery
    for the run summary, and one per finding first seen in that run.
    """
    from app.models.assessment_run import AssessmentRun, RunStatus
    from app.models.finding import Finding, FindingStatus
    from app.models.integration import NotificationDelivery
    from app.workers.notifications import _notify_run

    org_id, headers = await _owner(client, strong_password, "s")
    await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(name="everything", events=["assessment.completed", "finding.critical"]),
        headers=headers,
    )

    target_id = await _target(client, org_id, headers)
    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
    )
    earlier = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
    )
    db_session.add_all([run, earlier])
    await db_session.flush()
    db_session.add(
        Finding(
            organization_id=uuid.UUID(org_id),
            fingerprint="fp-critical-1",
            title="BOLA on /orders/{id}",
            status=FindingStatus.NEW,
            first_run_id=run.id,
            last_run_id=run.id,
            **_finding_fields(),
        )
    )
    # Seen before this run, so it is not announced again as new.
    db_session.add(
        Finding(
            organization_id=uuid.UUID(org_id),
            fingerprint="fp-critical-2",
            title="Recurring critical",
            status=FindingStatus.CONFIRMED,
            first_run_id=earlier.id,
            last_run_id=run.id,
            **_finding_fields(),
        )
    )
    await db_session.commit()

    await _notify_run(run.id)

    rows = (
        (
            await db_session.execute(
                select(NotificationDelivery).where(
                    NotificationDelivery.organization_id == uuid.UUID(org_id)
                )
            )
        )
        .scalars()
        .all()
    )
    events = sorted(row.event_type for row in rows)
    assert events == ["assessment.completed", "finding.critical"]
    summary = next(row for row in rows if row.event_type == "assessment.completed")
    # Both criticals counted, because the summary describes what the run found.
    assert (summary.event_json or {}).get("severity") == "CRITICAL"


async def test_a_retest_run_also_fans_out_its_own_verdict_event(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    """A retest run gets `retest.completed` alongside `assessment.completed`
    — the verdict counts are the whole reason a retest was requested, and a
    channel subscribed to `retest.completed` should not have to infer them
    from the run summary's generic facts.
    """
    from app.models.assessment_run import AssessmentRun, RunKind, RunStatus
    from app.models.finding import Finding, FindingStatus
    from app.models.integration import NotificationDelivery
    from app.models.retest import RetestResult, RetestVerdict
    from app.workers.notifications import _notify_run

    org_id, headers = await _owner(client, strong_password, "u")
    await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(name="retests", events=["retest.completed"]),
        headers=headers,
    )
    target_id = await _target(client, org_id, headers)
    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
        kind=RunKind.RETEST,
    )
    db_session.add(run)
    await db_session.flush()
    fixed = Finding(
        organization_id=uuid.UUID(org_id),
        fingerprint="sha256:" + "a" * 64,
        title="Fixed finding",
        status=FindingStatus.REMEDIATED,
        first_run_id=run.id,
        last_run_id=run.id,
        **_finding_fields(),
    )
    still_open = Finding(
        organization_id=uuid.UUID(org_id),
        fingerprint="sha256:" + "b" * 64,
        title="Still-open finding",
        status=FindingStatus.CONFIRMED,
        first_run_id=run.id,
        last_run_id=run.id,
        **_finding_fields(),
    )
    db_session.add_all([fixed, still_open])
    await db_session.flush()
    db_session.add_all(
        [
            RetestResult(
                organization_id=uuid.UUID(org_id),
                run_id=run.id,
                finding_id=fixed.id,
                fingerprint="sha256:" + "a" * 64,
                verdict=RetestVerdict.NOT_REPRODUCED,
                before_evidence_ref=None,
                after_evidence_ref=None,
                detail="probe ran, no longer reproduced",
            ),
            RetestResult(
                organization_id=uuid.UUID(org_id),
                run_id=run.id,
                finding_id=still_open.id,
                fingerprint="sha256:" + "b" * 64,
                verdict=RetestVerdict.REPRODUCED,
                before_evidence_ref=None,
                after_evidence_ref=None,
                detail="probe ran, still reproduced",
            ),
        ]
    )
    await db_session.commit()

    await _notify_run(run.id)

    rows = (
        (
            await db_session.execute(
                select(NotificationDelivery).where(
                    NotificationDelivery.organization_id == uuid.UUID(org_id)
                )
            )
        )
        .scalars()
        .all()
    )
    retest_row = next(row for row in rows if row.event_type == "retest.completed")
    facts = (retest_row.event_json or {}).get("facts") or {}
    assert facts.get("reproduced") == "1"
    assert facts.get("not_reproduced") == "1"
    assert facts.get("not_tested") == "0"


async def test_a_run_with_no_subscribed_channel_writes_no_delivery_rows(
    client: AsyncClient, strong_password: str, db_session: AsyncSession
) -> None:
    from app.models.assessment_run import AssessmentRun, RunStatus
    from app.models.integration import NotificationDelivery
    from app.workers.notifications import _notify_run

    org_id, headers = await _owner(client, strong_password, "t")
    await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json=slack_payload(name="findings-only", events=["finding.critical"]),
        headers=headers,
    )
    target_id = await _target(client, org_id, headers)
    run = AssessmentRun(
        organization_id=uuid.UUID(org_id),
        target_id=uuid.UUID(target_id),
        status=RunStatus.COMPLETED,
    )
    db_session.add(run)
    await db_session.commit()

    await _notify_run(run.id)

    rows = (
        (
            await db_session.execute(
                select(NotificationDelivery).where(
                    NotificationDelivery.organization_id == uuid.UUID(org_id)
                )
            )
        )
        .scalars()
        .all()
    )
    assert rows == []


# --- SIEM: Splunk HEC and Sentinel channels ----------------------------------


async def test_a_splunk_hec_channel_without_an_auth_token_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "h")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "splunk",
            "kind": "siem_splunk_hec",
            "events": ["finding.critical"],
            "endpoint_env_var": SLACK_ENV,
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "auth_token_env_var" in response.text


async def test_a_splunk_hec_channel_is_created_with_an_operator_sanctioned_host(
    client: AsyncClient, strong_password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    monkeypatch.setenv("KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS", json.dumps(["splunk.internal.test"]))
    monkeypatch.setenv(
        "KERVY_TEST_SPLUNK_HEC", "https://splunk.internal.test:8088/services/collector/event"
    )
    get_settings.cache_clear()
    org_id, headers = await _owner(client, strong_password, "i")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "splunk",
            "kind": "siem_splunk_hec",
            "events": ["finding.critical"],
            "endpoint_env_var": "KERVY_TEST_SPLUNK_HEC",
            "auth_token_env_var": "KERVY_TEST_SPLUNK_TOKEN",
        },
        headers=headers,
    )
    get_settings.cache_clear()
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["auth_token_env_var"] == "KERVY_TEST_SPLUNK_TOKEN"
    assert "splunk.internal.test" in body["endpoint_redacted"]


async def test_a_sentinel_channel_missing_required_fields_is_rejected(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "j")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "sentinel",
            "kind": "siem_sentinel",
            "events": ["finding.critical"],
            "sentinel_endpoint": "https://my-dce.eastus-1.ingest.monitor.azure.com",
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "azure_tenant_id" in response.text


async def test_a_sentinel_channel_pointing_off_the_azure_domain_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    org_id, headers = await _owner(client, strong_password, "k")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "sentinel",
            "kind": "siem_sentinel",
            "events": ["finding.critical"],
            "sentinel_endpoint": "https://attacker.test/x",
            "azure_tenant_id": "tenant-1",
            "azure_client_id": "client-1",
            "azure_client_secret_env_var": "KERVY_TEST_AZURE_SECRET",  # pragma: allowlist secret
            "sentinel_dcr_immutable_id": "dcr-abc",
            "sentinel_stream_name": "Custom-KervySecurityEvent",
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert "not permitted" in response.text


async def test_a_sentinel_channel_is_created_with_identifiers_but_no_secret_value(
    client: AsyncClient, strong_password: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KERVY_TEST_AZURE_SECRET", "super-secret-client-secret")
    org_id, headers = await _owner(client, strong_password, "l")
    response = await client.post(
        f"/api/v1/organizations/{org_id}/notification-channels",
        json={
            "name": "sentinel",
            "kind": "siem_sentinel",
            "events": ["finding.critical"],
            "sentinel_endpoint": "https://my-dce.eastus-1.ingest.monitor.azure.com",
            "azure_tenant_id": "tenant-1",
            "azure_client_id": "client-1",
            "azure_client_secret_env_var": "KERVY_TEST_AZURE_SECRET",  # pragma: allowlist secret
            "sentinel_dcr_immutable_id": "dcr-abc",
            "sentinel_stream_name": "Custom-KervySecurityEvent",
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["azure_tenant_id"] == "tenant-1"
    env_var_name = "KERVY_TEST_AZURE_SECRET"  # pragma: allowlist secret
    assert body["azure_client_secret_env_var"] == env_var_name
    assert "super-secret-client-secret" not in response.text
