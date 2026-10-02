"""Outbound integrations (docs/BUILD_SPEC.md §27).

The tests that matter most here are the negative ones. A notification channel
is operator-configured data that produces an outbound request, which is the
shape of an SSRF primitive, so most of this file is about the ways a channel
must fail: a host nobody sanctioned, a loopback address, the cloud metadata
service, a plaintext scheme, a payload carrying a secret.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.integrations.contract import (
    ChannelKind,
    EventType,
    IntegrationError,
    IntegrationEvent,
    host_permitted,
    severity_at_least,
)
from app.core.integrations.dispatch import (
    BACKOFF_SECONDS,
    MAX_ATTEMPTS,
    ChannelSecrets,
    backoff_for,
    deliver_once,
    event_for_finding,
    event_for_investigation,
    event_for_retest,
    event_for_run,
    event_for_workflow_gate,
    event_from_snapshot,
    event_snapshot,
    select_channels,
    status_after,
    subscribes,
)
from app.core.integrations.egress import notification_egress_context
from app.core.integrations.policy import (
    redact_url,
    resolve_jira_destination,
    resolve_secret,
    resolve_servicenow_destination,
    resolve_smtp_host,
    resolve_webhook_destination,
    valid_env_var_name,
)
from app.core.integrations.render import MAX_SUMMARY_CHARS, render
from app.core.integrations.send import send_jira_ticket, send_servicenow_ticket, send_webhook
from app.core.integrations.signing import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign,
    verify,
)
from app.core.scope.transport import Observation
from app.models.integration import DeliveryStatus, NotificationChannel

ORG = uuid.UUID("11111111-1111-1111-1111-111111111111")
# pragma: allowlist nextline secret
SLACK_URL = "https://hooks.slack.com/services/T000/B000/xxxxxxxxxxxxxxxxxxxxxxxx"


def make_event(**overrides: object) -> IntegrationEvent:
    defaults: dict[str, object] = {
        "event_type": EventType.FINDING_CRITICAL,
        "organization_id": ORG,
        "occurred_at_iso": "2026-09-20T00:00:00+00:00",
        "title": "Broken object level authorization on /orders/{id}",
        "severity": "CRITICAL",
        "target_name": "acme-api",
        "link_path": "findings/abc",
    }
    defaults.update(overrides)
    return IntegrationEvent(**defaults)  # type: ignore[arg-type]


def make_channel(**overrides: object) -> NotificationChannel:
    channel = NotificationChannel(
        id=uuid.uuid4(),
        organization_id=ORG,
        name="sec-alerts",
        kind=ChannelKind.SLACK_WEBHOOK.value,
        endpoint_env_var="KERVY_TEST_SLACK_URL",
        endpoint_redacted="https://hooks.slack.com/…/…/…",
        events=[EventType.FINDING_CRITICAL.value],
        enabled=True,
    )
    for key, value in overrides.items():
        setattr(channel, key, value)
    return channel


class RecordingTransport:
    """Stands in for `GatedTransport`, recording what it was asked to send.

    Used only where the question is "what did we send"; the questions about
    *whether* we may send go through the real engine below.
    """

    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code
        self.calls: list[dict[str, object]] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append(kwargs)
        return Observation(
            method=str(kwargs.get("method")),
            url=str(kwargs.get("url")),
            status_code=self.status_code,
            headers={},
            elapsed_ms=1.0,
        )


# --- policy: where a channel may point ---------------------------------------


def test_host_wildcard_does_not_match_a_sibling_domain() -> None:
    assert host_permitted("a.webhook.office.com", ["*.webhook.office.com"])
    assert host_permitted("x.y.webhook.office.com", ["*.webhook.office.com"])
    # The leading dot is part of the suffix: this is the attack the wildcard
    # would otherwise allow.
    assert not host_permitted("evilwebhook.office.com", ["*.webhook.office.com"])
    assert not host_permitted("webhook.office.com.evil.test", ["*.webhook.office.com"])


def test_slack_channel_cannot_point_at_an_arbitrary_host() -> None:
    with pytest.raises(IntegrationError, match="not permitted"):
        resolve_webhook_destination(
            ChannelKind.SLACK_WEBHOOK,
            "VAR",
            environ={"VAR": "https://attacker.test/collect"},
        )


def test_generic_webhook_needs_an_operator_sanctioned_host() -> None:
    """The database alone must never be able to widen egress."""
    with pytest.raises(IntegrationError, match="KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS"):
        resolve_webhook_destination(
            ChannelKind.GENERIC_WEBHOOK, "VAR", environ={"VAR": "https://siem.internal.test/in"}
        )

    destination = resolve_webhook_destination(
        ChannelKind.GENERIC_WEBHOOK,
        "VAR",
        operator_hosts=["siem.internal.test"],
        environ={"VAR": "https://siem.internal.test/in"},
    )
    assert destination.host == "siem.internal.test"


def test_a_channel_endpoint_must_be_https() -> None:
    with pytest.raises(IntegrationError, match="must be https"):
        resolve_webhook_destination(
            ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": "http://hooks.slack.com/services/x"}
        )


def test_a_missing_secret_is_a_refusal_naming_the_variable_not_a_value() -> None:
    with pytest.raises(IntegrationError) as exc:
        resolve_secret("KERVY_ABSENT_VAR", {})
    assert "KERVY_ABSENT_VAR" in str(exc.value)


def test_env_var_names_are_validated_so_a_url_cannot_be_pasted_as_one() -> None:
    assert valid_env_var_name("KERVY_SLACK_URL")
    assert not valid_env_var_name("https://hooks.slack.com/x")
    assert not valid_env_var_name("1BAD")
    assert not valid_env_var_name("")


def test_redacted_url_keeps_the_host_and_drops_every_path_segment() -> None:
    redacted = redact_url(SLACK_URL)
    assert "hooks.slack.com" in redacted
    # The token lives in the path, so no segment may survive.
    for segment in ("services", "T000", "B000", "xxxxxxxxxxxxxxxxxxxxxxxx"):
        assert segment not in redacted


def test_smtp_host_needs_the_operator_allowlist() -> None:
    with pytest.raises(IntegrationError, match="KERVY_NOTIFY_ALLOWED_SMTP_HOSTS"):
        resolve_smtp_host("smtp.example.test")
    assert resolve_smtp_host("smtp.example.test", operator_hosts=["smtp.example.test"]) == (
        "smtp.example.test"
    )


# --- egress: the scope engine still decides ----------------------------------


def test_notification_context_allowlists_only_the_destination_host() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    ctx = notification_egress_context(destination)
    assert ctx.roe.allowed_domains == ("hooks.slack.com",)
    # Empty on purpose: this is what keeps loopback, RFC1918 and the metadata
    # service blocked for a notification.
    assert ctx.roe.allowed_ip_ranges == ()
    assert ctx.roe.allowed_methods == ("POST",)
    assert ctx.roe.safe_mode is True


def test_notification_context_cannot_reach_a_second_host() -> None:
    """There is no parameter through which the allowlist could be widened."""
    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    ctx = notification_egress_context(destination)
    assert "attacker.test" not in ctx.roe.allowed_domains


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1"],
)
async def test_a_channel_resolving_to_a_blocked_address_is_refused(address: str) -> None:
    """The real scope engine, with a resolver that answers with the address.

    A channel host that passes the allowlist policy and *then* resolves
    internally is the DNS-rebind case, and it must still be refused.
    """
    from app.core.scope.engine import ScopeEngine
    from app.core.scope.transport import GatedTransport

    class FixedResolver:
        async def resolve(self, hostname: str) -> list[object]:
            return [ipaddress.ip_address(address)]

    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    transport = GatedTransport(engine=ScopeEngine(), dns_resolver=FixedResolver())
    message = render(ChannelKind.SLACK_WEBHOOK, make_event())
    result = await send_webhook(
        destination, message, event_type="finding.critical", transport=transport
    )
    assert not result.delivered
    assert "blocked" in result.detail or "refused" in result.detail
    # A scope decision is never retried.
    assert result.retryable is False


# --- rendering: what a notification may carry --------------------------------


def test_a_payload_carrying_a_secret_is_refused_not_truncated() -> None:
    event = make_event(title="leaked AKIAIOSFODNN7EXAMPLE from config")
    with pytest.raises(IntegrationError, match="redaction failure upstream"):
        render(ChannelKind.SLACK_WEBHOOK, event)


def test_an_oversized_payload_is_refused() -> None:
    event = make_event(title="x" * (MAX_SUMMARY_CHARS + 1))
    with pytest.raises(IntegrationError, match="over the"):
        render(ChannelKind.SLACK_WEBHOOK, event)


def test_no_link_is_rendered_when_no_base_url_is_configured() -> None:
    message = render(ChannelKind.SLACK_WEBHOOK, make_event(), base_url=None)
    assert "findings/abc" not in message.summary


def test_a_link_is_built_from_the_configured_base_url() -> None:
    message = render(
        ChannelKind.SLACK_WEBHOOK, make_event(), base_url="https://kervy.example.test/"
    )
    assert "https://kervy.example.test/findings/abc" in message.summary


def test_slack_payload_carries_plain_text_as_well_as_blocks() -> None:
    import json

    payload = json.loads(render(ChannelKind.SLACK_WEBHOOK, make_event()).body)
    # Mobile notifications and screen readers use `text`; blocks alone read
    # as an empty message there.
    assert payload["text"]
    assert payload["blocks"]


def test_generic_payload_is_stable_bytes_for_signing() -> None:
    event = make_event()
    first = render(ChannelKind.GENERIC_WEBHOOK, event).body
    second = render(ChannelKind.GENERIC_WEBHOOK, event).body
    assert first == second


# --- signing ------------------------------------------------------------------


def test_signature_covers_the_body_and_the_timestamp() -> None:
    body = b'{"a":1}'
    timestamp, signature = sign("shh", body)
    assert verify("shh", body, timestamp=timestamp, signature=signature)
    assert not verify("shh", b'{"a":2}', timestamp=timestamp, signature=signature)
    assert not verify("other", body, timestamp=timestamp, signature=signature)


def test_a_stale_timestamp_fails_verification() -> None:
    body = b"{}"
    timestamp, signature = sign("shh", body)
    assert not verify(
        "shh",
        body,
        timestamp=timestamp,
        signature=signature,
        now=float(timestamp) + 100_000,
    )


async def test_a_generic_webhook_refuses_to_send_unsigned() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.GENERIC_WEBHOOK,
        "VAR",
        operator_hosts=["siem.test"],
        environ={"VAR": "https://siem.test/in"},
    )
    message = render(ChannelKind.GENERIC_WEBHOOK, make_event())
    with pytest.raises(IntegrationError, match="must be signed"):
        await send_webhook(destination, message, event_type="x", signing_secret=None)


async def test_a_signed_delivery_sends_a_verifiable_signature() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.GENERIC_WEBHOOK,
        "VAR",
        operator_hosts=["siem.test"],
        environ={"VAR": "https://siem.test/in"},
    )
    message = render(ChannelKind.GENERIC_WEBHOOK, make_event())
    transport = RecordingTransport()
    result = await send_webhook(
        destination,
        message,
        event_type="finding.critical",
        signing_secret="shh",
        transport=transport,  # type: ignore[arg-type]
    )
    assert result.delivered
    headers = transport.calls[0]["headers"]
    assert isinstance(headers, dict)
    body = transport.calls[0]["content"]
    assert isinstance(body, bytes)
    # Verified over the exact bytes the transport was handed, which is the
    # property a re-serialization would quietly break.
    assert verify(
        "shh",
        body,
        timestamp=headers[TIMESTAMP_HEADER],
        signature=headers[SIGNATURE_HEADER],
    )


# --- subscription and retry ---------------------------------------------------


def test_a_channel_only_receives_the_events_it_subscribed_to() -> None:
    channel = make_channel(events=[EventType.ASSESSMENT_COMPLETED.value])
    assert not subscribes(channel, make_event(event_type=EventType.FINDING_CRITICAL))
    assert subscribes(channel, make_event(event_type=EventType.ASSESSMENT_COMPLETED))


def test_a_disabled_channel_receives_nothing() -> None:
    assert not subscribes(make_channel(enabled=False), make_event())


def test_min_severity_is_a_floor_not_an_exact_match() -> None:
    channel = make_channel(
        events=[EventType.FINDING_CREATED.value, EventType.FINDING_CRITICAL.value],
        min_severity="HIGH",
    )
    assert subscribes(channel, make_event(severity="CRITICAL"))
    assert subscribes(channel, make_event(event_type=EventType.FINDING_CREATED, severity="HIGH"))
    assert not subscribes(
        channel, make_event(event_type=EventType.FINDING_CREATED, severity="MEDIUM")
    )


def test_an_unrankable_severity_is_not_silently_dropped() -> None:
    """A dropped security notification is the costliest failure mode."""
    assert severity_at_least(None, "HIGH")
    assert severity_at_least("WEIRD", "HIGH")


def test_channels_from_another_organization_are_never_selected() -> None:
    mine = make_channel()
    theirs = make_channel(organization_id=uuid.uuid4())
    assert select_channels([mine, theirs], make_event()) == [mine]


def test_backoff_runs_out_rather_than_retrying_forever() -> None:
    assert backoff_for(1) == timedelta(seconds=BACKOFF_SECONDS[0])
    assert backoff_for(len(BACKOFF_SECONDS)) == timedelta(seconds=BACKOFF_SECONDS[-1])
    assert backoff_for(MAX_ATTEMPTS) is None


def test_a_refusal_is_never_retried_and_a_failure_dead_letters() -> None:
    from app.core.integrations.contract import DeliveryResult

    refused = DeliveryResult(delivered=False, detail="bad host", retryable=False)
    status, when = status_after(refused, attempts=1)
    assert status is DeliveryStatus.REFUSED
    assert when is None

    transient = DeliveryResult(delivered=False, status_code=503, detail="", retryable=True)
    status, when = status_after(transient, attempts=1)
    assert status is DeliveryStatus.FAILED
    assert when is not None

    status, when = status_after(transient, attempts=MAX_ATTEMPTS)
    assert status is DeliveryStatus.DEAD_LETTER
    assert when is None


async def _attempt_with(status_code: int) -> object:
    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    message = render(ChannelKind.SLACK_WEBHOOK, make_event())
    transport = RecordingTransport(status_code=status_code)
    return await send_webhook(
        destination,
        message,
        event_type="finding.critical",
        transport=transport,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(("status_code", "retryable"), [(503, True), (429, True), (404, False)])
async def test_retryability_follows_the_status_class(status_code: int, retryable: bool) -> None:
    result = await _attempt_with(status_code)
    assert result.retryable is retryable  # type: ignore[attr-defined]


async def test_a_destination_response_body_is_never_recorded() -> None:
    """A receiver that echoes our payload back must not put it in our database."""
    result = await _attempt_with(400)
    assert result.detail == "destination returned HTTP 400"  # type: ignore[attr-defined]


# --- event construction -------------------------------------------------------


def test_a_run_event_takes_the_highest_severity_actually_present() -> None:
    event = event_for_run(
        organization_id=ORG,
        run_id=uuid.uuid4(),
        status="completed",
        target_name="acme-api",
        counts={"high": 2, "low": 5},
    )
    assert event.event_type is EventType.ASSESSMENT_COMPLETED
    assert event.severity == "HIGH"


def test_a_run_that_found_nothing_has_no_severity() -> None:
    event = event_for_run(
        organization_id=ORG,
        run_id=uuid.uuid4(),
        status="completed",
        target_name="acme-api",
        counts={},
    )
    assert event.severity is None


def test_a_failed_run_is_its_own_event_type() -> None:
    event = event_for_run(
        organization_id=ORG, run_id=uuid.uuid4(), status="failed", target_name="t", counts={}
    )
    assert event.event_type is EventType.ASSESSMENT_FAILED


def test_a_critical_finding_is_its_own_event_type() -> None:
    critical = event_for_finding(
        organization_id=ORG,
        finding_id=uuid.uuid4(),
        title="t",
        severity="critical",
        target_name="x",
    )
    high = event_for_finding(
        organization_id=ORG,
        finding_id=uuid.uuid4(),
        title="t",
        severity="high",
        target_name="x",
    )
    assert critical.event_type is EventType.FINDING_CRITICAL
    assert high.event_type is EventType.FINDING_CREATED


def test_a_completed_investigation_is_its_own_event_type() -> None:
    event = event_for_investigation(
        organization_id=ORG,
        investigation_id=uuid.uuid4(),
        status="completed",
        tool_count=3,
    )
    assert event.event_type is EventType.AGENT_INVESTIGATION_COMPLETED
    assert event.facts == {"steps": 3}


def test_a_failed_investigation_names_the_tool_that_failed() -> None:
    event = event_for_investigation(
        organization_id=ORG,
        investigation_id=uuid.uuid4(),
        status="failed",
        tool_count=2,
        failed_tool_name="start_scan",
    )
    assert event.event_type is EventType.AGENT_INVESTIGATION_FAILED
    assert event.facts == {"steps": 2, "failed_tool": "start_scan"}


def test_a_retest_event_carries_verdict_counts() -> None:
    event = event_for_retest(
        organization_id=ORG,
        run_id=uuid.uuid4(),
        target_name="acme-api",
        reproduced=1,
        not_reproduced=2,
        not_tested=0,
    )
    assert event.event_type is EventType.RETEST_COMPLETED
    assert event.facts == {"reproduced": 1, "not_reproduced": 2, "not_tested": 0}


def test_a_retest_event_round_trips_through_its_snapshot() -> None:
    event = event_for_retest(
        organization_id=ORG,
        run_id=uuid.uuid4(),
        target_name="acme-api",
        reproduced=1,
        not_reproduced=0,
        not_tested=1,
    )
    rebuilt = event_from_snapshot(ORG, event_snapshot(event))
    assert event_snapshot(rebuilt) == event_snapshot(event)


def test_a_failed_gate_event_names_the_workflow_and_the_reasons() -> None:
    event = event_for_workflow_gate(
        organization_id=ORG,
        workflow_run_id=uuid.uuid4(),
        workflow_name="nightly-scan",
        reasons=["2 CRITICAL findings exceed the gate's limit of 0"],
        counts={"critical": 2, "high": 1},
    )
    assert event.event_type is EventType.GATE_FAILED
    assert "nightly-scan" in event.title
    assert event.facts["critical"] == 2
    assert event.facts["high"] == 1
    assert event.facts["reasons"] == "2 CRITICAL findings exceed the gate's limit of 0"


def test_a_gate_event_round_trips_through_its_snapshot() -> None:
    event = event_for_workflow_gate(
        organization_id=ORG,
        workflow_run_id=uuid.uuid4(),
        workflow_name="nightly-scan",
        reasons=["blocked"],
        counts={"critical": 1},
    )
    rebuilt = event_from_snapshot(ORG, event_snapshot(event))
    assert event_snapshot(rebuilt) == event_snapshot(event)


def test_an_investigation_event_round_trips_through_its_snapshot() -> None:
    event = event_for_investigation(
        organization_id=ORG, investigation_id=uuid.uuid4(), status="completed", tool_count=1
    )
    rebuilt = event_from_snapshot(ORG, event_snapshot(event))
    assert event_snapshot(rebuilt) == event_snapshot(event)


def test_an_event_round_trips_through_its_snapshot() -> None:
    """A retry must send what the first attempt would have sent."""
    event = make_event(facts={"probe": "KERVY-API-050", "count": 2})
    rebuilt = event_from_snapshot(ORG, event_snapshot(event))
    assert event_snapshot(rebuilt) == event_snapshot(event)


# --- deliver_once: configuration problems never raise ------------------------


async def test_an_unknown_channel_kind_is_a_final_refusal() -> None:
    result = await deliver_once(make_channel(kind="carrier-pigeon"), make_event())
    assert not result.delivered
    assert result.retryable is False


async def test_a_channel_with_no_endpoint_variable_is_a_final_refusal() -> None:
    result = await deliver_once(make_channel(endpoint_env_var=None), make_event())
    assert not result.delivered
    assert result.retryable is False


async def test_a_refusal_detail_never_carries_the_resolved_url() -> None:
    channel = make_channel(kind=ChannelKind.GENERIC_WEBHOOK.value)
    result = await deliver_once(
        channel,
        make_event(),
        secrets=ChannelSecrets(endpoint_url="https://attacker.test/collect?t=supersecrettoken"),
    )
    assert not result.delivered
    assert "supersecrettoken" not in result.detail


def test_scrub_removes_a_url_path_the_secret_detector_would_not_recognise() -> None:
    """A webhook token is opaque random text, so pattern redaction alone fails.

    This is why `scrub` strips URL paths outright instead of trusting the
    detector: nothing about `Tabc/Bdef/kQ2...` says "credential".
    """
    from app.core.integrations.dispatch import scrub

    leaky = f"ConnectError: could not reach {SLACK_URL}"
    # Establish the premise: the secret detector does not catch this token.
    from app.core.redaction.secrets import redact

    assert "xxxxxxxxxxxxxxxxxxxxxxxx" in redact(leaky).redacted_text

    cleaned = scrub(leaky)
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in cleaned
    assert "services" not in cleaned
    # The host survives, because an operator needs to know which channel broke.
    assert "hooks.slack.com" in cleaned


async def test_a_transport_failure_detail_is_scrubbed_before_it_is_returned() -> None:
    """The `deliver_once` wrapper is the one door every outcome passes through."""

    class ExplodingTransport:
        async def send(self, ctx: object, **kwargs: object) -> object:
            raise RuntimeError(f"connection reset posting to {kwargs['url']}")

    import app.core.integrations.send as send_module

    original = send_module.GatedTransport
    send_module.GatedTransport = ExplodingTransport  # type: ignore[misc,assignment]
    try:
        result = await deliver_once(
            make_channel(), make_event(), secrets=ChannelSecrets(endpoint_url=SLACK_URL)
        )
    finally:
        send_module.GatedTransport = original  # type: ignore[misc]

    assert not result.delivered
    assert result.retryable is True
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in result.detail


def test_authorization_window_is_short_lived() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    ctx = notification_egress_context(destination)
    assert ctx.authorization.valid_until - datetime.now(UTC) < timedelta(minutes=10)


class FixedResolver:
    """Resolves every host to one public address, so the engine's IP rules pass
    and what is left under test is the rest of the decision."""

    def __init__(self, address: str = "93.184.216.34") -> None:
        self._address = address

    async def resolve(self, hostname: str) -> list[object]:
        return [ipaddress.ip_address(self._address)]


async def test_a_good_destination_is_actually_allowed_by_the_real_engine() -> None:
    """The negative cases above would all pass if the context blocked everything.

    This is the control for them: the same context, a host that resolves
    publicly, and a decision of `allow`. It also pins that the zero token
    budgets in `DELIVERY_BUDGETS` do not refuse a request that spends none.
    """
    from app.core.scope.engine import ScopeEngine

    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    decision = await ScopeEngine().explain(
        notification_egress_context(destination),
        dns_resolver=FixedResolver(),
        method="POST",
        url=destination.url,
    )
    assert decision.allowed, decision.reason


async def test_a_notification_context_permits_post_and_nothing_else() -> None:
    from app.core.scope.engine import ScopeEngine

    destination = resolve_webhook_destination(
        ChannelKind.SLACK_WEBHOOK, "VAR", environ={"VAR": SLACK_URL}
    )
    decision = await ScopeEngine().explain(
        notification_egress_context(destination),
        dns_resolver=FixedResolver(),
        method="GET",
        url=destination.url,
    )
    assert not decision.allowed
    assert decision.rule == "method_not_allowed"


async def test_the_smtp_context_clears_a_relay_but_cannot_be_used_for_http() -> None:
    """`allowed_methods=("SMTP",)` is the point: a context built to clear a mail
    relay must not become a second way to make an HTTP request."""
    from app.core.integrations.send import smtp_scope_context
    from app.core.scope.engine import ScopeEngine

    ctx = smtp_scope_context("smtp.example.test", 587)
    cleared = await ScopeEngine().explain(
        ctx,
        dns_resolver=FixedResolver(),
        method="SMTP",
        url="smtp://smtp.example.test:587/",
    )
    assert cleared.allowed, cleared.reason

    refused = await ScopeEngine().explain(
        ctx,
        dns_resolver=FixedResolver(),
        method="POST",
        url="https://smtp.example.test/collect",
    )
    assert not refused.allowed
    assert refused.rule == "method_not_allowed"


async def test_an_smtp_relay_resolving_to_the_metadata_service_is_refused() -> None:
    """The engine adjudicates the relay before `smtplib` is touched."""
    from app.core.integrations.render import render
    from app.core.integrations.send import send_email
    from app.core.scope.engine import ScopeEngine

    message = render(ChannelKind.EMAIL_SMTP, make_event())

    class MetadataResolver(FixedResolver):
        def __init__(self) -> None:
            super().__init__("169.254.169.254")

    import app.core.scope.dns as dns_module

    original = dns_module.SystemDnsResolver
    dns_module.SystemDnsResolver = MetadataResolver  # type: ignore[misc,assignment]
    try:
        result = await send_email(
            message,
            host="smtp.example.test",
            from_address="kervy@example.test",
            recipients=["soc@example.test"],
            engine=ScopeEngine(),
        )
    finally:
        dns_module.SystemDnsResolver = original  # type: ignore[misc]

    assert not result.delivered
    assert "refused by scope engine" in result.detail
    assert result.retryable is False


# --- ticketing: Jira Cloud, ServiceNow -----------------------------------------


class RecordingJsonTransport:
    """Like `RecordingTransport`, but returns a configurable JSON body.

    Jira and ServiceNow both answer a successful create with the created
    record's identifier in the body, which `send_jira_ticket`/
    `send_servicenow_ticket` must parse back out as `external_reference` —
    `RecordingTransport` above never needed to return a body at all.
    """

    def __init__(self, status_code: int = 201, body: bytes = b"{}") -> None:
        self.status_code = status_code
        self.body = body
        self.calls: list[dict[str, object]] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append(kwargs)
        return Observation(
            method=str(kwargs.get("method")),
            url=str(kwargs.get("url")),
            status_code=self.status_code,
            headers={},
            elapsed_ms=1.0,
            body=self.body,
        )


def test_jira_site_must_be_a_dns_label() -> None:
    with pytest.raises(IntegrationError, match="not a valid Jira site label"):
        resolve_jira_destination("not a label/")


def test_jira_destination_is_pinned_to_atlassian_net() -> None:
    destination = resolve_jira_destination("mycompany")
    assert destination.host == "mycompany.atlassian.net"
    assert destination.url == "https://mycompany.atlassian.net"


def test_servicenow_instance_must_be_a_dns_label() -> None:
    with pytest.raises(IntegrationError, match="not a valid ServiceNow instance name"):
        resolve_servicenow_destination("evil.com")


def test_servicenow_destination_is_pinned_to_service_now_com() -> None:
    destination = resolve_servicenow_destination("mycompany")
    assert destination.host == "mycompany.service-now.com"
    assert destination.url == "https://mycompany.service-now.com"


def test_jira_payload_has_an_adf_description_and_a_summary() -> None:
    message = render(ChannelKind.TICKET_JIRA, make_event())
    payload = json.loads(message.body)
    assert payload["summary"].startswith("[Kervy]")
    adf = payload["description_adf"]
    assert adf["type"] == "doc"
    assert adf["content"][0]["type"] == "paragraph"


def test_servicenow_payload_maps_severity_to_urgency() -> None:
    critical = render(ChannelKind.TICKET_SERVICENOW, make_event(severity="CRITICAL"))
    low = render(ChannelKind.TICKET_SERVICENOW, make_event(severity="LOW"))
    assert json.loads(critical.body)["urgency"] == 1
    assert json.loads(low.body)["urgency"] == 3


async def test_jira_creates_an_issue_and_returns_its_key() -> None:
    destination = resolve_jira_destination("mycompany")
    message = render(ChannelKind.TICKET_JIRA, make_event())
    transport = RecordingJsonTransport(
        status_code=201, body=json.dumps({"id": "10001", "key": "SEC-123"}).encode()
    )
    result = await send_jira_ticket(
        destination,
        message,
        email="bot@example.test",
        api_token="tok",  # noqa: S106 - test fixture value, not a real token
        project_key="SEC",
        issue_type="Bug",
        transport=transport,  # type: ignore[arg-type]
    )
    assert result.delivered
    assert result.external_reference == "SEC-123"
    assert result.status_code == 201
    call = transport.calls[0]
    assert call["url"] == "https://mycompany.atlassian.net/rest/api/3/issue"
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"].startswith("Basic ")
    body = json.loads(call["content"])  # type: ignore[arg-type]
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["issuetype"]["name"] == "Bug"


async def test_jira_a_non_201_response_is_not_delivered() -> None:
    destination = resolve_jira_destination("mycompany")
    message = render(ChannelKind.TICKET_JIRA, make_event())
    transport = RecordingJsonTransport(status_code=400, body=b"{}")
    result = await send_jira_ticket(
        destination,
        message,
        email="bot@example.test",
        api_token="tok",  # noqa: S106
        project_key="SEC",
        issue_type="Bug",
        transport=transport,  # type: ignore[arg-type]
    )
    assert not result.delivered
    assert result.external_reference is None
    assert result.retryable is False


async def test_servicenow_creates_a_record_and_returns_its_number() -> None:
    destination = resolve_servicenow_destination("mycompany")
    message = render(ChannelKind.TICKET_SERVICENOW, make_event())
    transport = RecordingJsonTransport(
        status_code=201,
        body=json.dumps({"result": {"sys_id": "abc123", "number": "INC0012345"}}).encode(),
    )
    result = await send_servicenow_ticket(
        destination,
        message,
        username="bot",
        password="pw",  # noqa: S106 - test fixture value, not a real password  # pragma: allowlist secret
        table="incident",
        transport=transport,  # type: ignore[arg-type]
    )
    assert result.delivered
    assert result.external_reference == "INC0012345"
    call = transport.calls[0]
    assert call["url"] == "https://mycompany.service-now.com/api/now/table/incident"
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"].startswith("Basic ")


async def test_servicenow_a_500_response_is_retryable() -> None:
    destination = resolve_servicenow_destination("mycompany")
    message = render(ChannelKind.TICKET_SERVICENOW, make_event())
    transport = RecordingJsonTransport(status_code=500, body=b"{}")
    result = await send_servicenow_ticket(
        destination,
        message,
        username="bot",
        password="pw",  # noqa: S106  # pragma: allowlist secret
        table="incident",
        transport=transport,  # type: ignore[arg-type]
    )
    assert not result.delivered
    assert result.retryable is True


async def test_servicenow_table_name_is_escaped_in_the_request_path() -> None:
    """A table name outside the schema's own pattern should never reach this
    far in production, but `send_servicenow_ticket` does not trust that: the
    `quote` it applies is the second of two independent checks (the other
    being the schema's own `pattern=r"^[a-z0-9_]+$"`), and this proves it
    actually runs rather than just existing in a docstring."""
    destination = resolve_servicenow_destination("mycompany")
    message = render(ChannelKind.TICKET_SERVICENOW, make_event())
    transport = RecordingJsonTransport(status_code=201, body=b'{"result": {}}')
    await send_servicenow_ticket(
        destination,
        message,
        username="bot",
        password="pw",  # noqa: S106  # pragma: allowlist secret
        table="incident/../secret",
        transport=transport,  # type: ignore[arg-type]
    )
    url = str(transport.calls[0]["url"])
    assert "/../" not in url
    assert "incident%2F..%2Fsecret" in url
