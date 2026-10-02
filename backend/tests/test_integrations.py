"""Outbound integrations (docs/BUILD_SPEC.md §27).

The tests that matter most here are the negative ones. A notification channel
is operator-configured data that produces an outbound request, which is the
shape of an SSRF primitive, so most of this file is about the ways a channel
must fail: a host nobody sanctioned, a loopback address, the cloud metadata
service, a plaintext scheme, a payload carrying a secret.
"""

from __future__ import annotations

import ipaddress
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
    resolve_secret,
    resolve_sentinel_destination,
    resolve_smtp_host,
    resolve_webhook_destination,
    valid_env_var_name,
)
from app.core.integrations.render import MAX_SUMMARY_CHARS, render
from app.core.integrations.send import send_sentinel, send_webhook
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


# --- SIEM: Splunk HEC, Sentinel, generic CEF ---------------------------------


def test_splunk_hec_needs_an_operator_sanctioned_host() -> None:
    """Almost always self-hosted, so it carries no built-in vendor host."""
    with pytest.raises(IntegrationError, match="KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS"):
        resolve_webhook_destination(
            ChannelKind.SIEM_SPLUNK_HEC,
            "VAR",
            environ={"VAR": "https://splunk.internal.test:8088/x"},
        )
    destination = resolve_webhook_destination(
        ChannelKind.SIEM_SPLUNK_HEC,
        "VAR",
        operator_hosts=["splunk.internal.test"],
        environ={"VAR": "https://splunk.internal.test:8088/services/collector/event"},
    )
    assert destination.host == "splunk.internal.test"


async def test_splunk_hec_refuses_to_send_with_no_token() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.SIEM_SPLUNK_HEC,
        "VAR",
        operator_hosts=["splunk.test"],
        environ={"VAR": "https://splunk.test:8088/services/collector/event"},
    )
    message = render(ChannelKind.SIEM_SPLUNK_HEC, make_event())
    with pytest.raises(IntegrationError, match="auth_token_env_var"):
        await send_webhook(destination, message, event_type="x", auth_token=None)


async def test_splunk_hec_sends_the_documented_authorization_scheme() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.SIEM_SPLUNK_HEC,
        "VAR",
        operator_hosts=["splunk.test"],
        environ={"VAR": "https://splunk.test:8088/services/collector/event"},
    )
    message = render(ChannelKind.SIEM_SPLUNK_HEC, make_event())
    transport = RecordingTransport()
    result = await send_webhook(
        destination,
        message,
        event_type="finding.critical",
        auth_token="hec-token-123",
        transport=transport,  # type: ignore[arg-type]
    )
    assert result.delivered
    headers = transport.calls[0]["headers"]
    assert isinstance(headers, dict)
    # HEC's own documented scheme — not Bearer, not Basic.
    assert headers["Authorization"] == "Splunk hec-token-123"


def test_splunk_hec_event_envelope_carries_time_sourcetype_and_event() -> None:
    import json

    message = render(ChannelKind.SIEM_SPLUNK_HEC, make_event())
    payload = json.loads(message.body)
    assert payload["sourcetype"] == "kervy:security_event"
    assert isinstance(payload["time"], float)
    assert payload["event"]["title"] == make_event().title
    assert payload["event"]["severity"] == "CRITICAL"


async def test_generic_cef_needs_signing_like_the_generic_webhook() -> None:
    destination = resolve_webhook_destination(
        ChannelKind.SIEM_GENERIC_CEF,
        "VAR",
        operator_hosts=["siem.test"],
        environ={"VAR": "https://siem.test/cef"},
    )
    message = render(ChannelKind.SIEM_GENERIC_CEF, make_event())
    with pytest.raises(IntegrationError, match="must be signed"):
        await send_webhook(destination, message, event_type="x", signing_secret=None)


def test_cef_payload_has_the_documented_header_shape() -> None:
    message = render(ChannelKind.SIEM_GENERIC_CEF, make_event())
    line = message.body.decode("utf-8")
    assert line.startswith("CEF:0|Kervy|SecurityTestingPlatform|1.0|")
    # CRITICAL maps to the top of this platform's CEF severity scale.
    fields = line.split("|")
    assert fields[6] == "10"
    assert "cs1Label=OrganizationId" in line


def test_cef_header_fields_are_pipe_escaped() -> None:
    """A finding title is free text; it must never be able to inject a CEF
    field boundary."""
    event = make_event(title="Injected|Field|Boundary")
    message = render(ChannelKind.SIEM_GENERIC_CEF, event)
    line = message.body.decode("utf-8")
    assert "Injected\\|Field\\|Boundary" in line


def test_sentinel_endpoint_needs_the_ingest_monitor_azure_com_domain() -> None:
    with pytest.raises(IntegrationError, match="not permitted"):
        resolve_sentinel_destination("https://attacker.test/x")
    destination = resolve_sentinel_destination(
        "https://my-dce-1234.eastus-1.ingest.monitor.azure.com"
    )
    assert destination.host == "my-dce-1234.eastus-1.ingest.monitor.azure.com"


def test_sentinel_endpoint_must_be_https() -> None:
    with pytest.raises(IntegrationError, match="must be https"):
        resolve_sentinel_destination("http://my-dce.eastus-1.ingest.monitor.azure.com")


class SentinelTransport:
    """Two distinct calls, two distinct responses — the token exchange, then
    the ingestion POST — matched by the request URL rather than call order,
    so a bug that skipped the token call would fail loudly instead of
    silently reading the wrong fixture."""

    def __init__(self, *, token_status: int = 200, data_status: int = 204) -> None:
        self.token_status = token_status
        self.data_status = data_status
        self.calls: list[dict[str, object]] = []

    async def send(self, ctx: object, **kwargs: object) -> Observation:
        self.calls.append(kwargs)
        url = str(kwargs.get("url"))
        if "login.microsoftonline.com" in url:
            import json

            return Observation(
                method="POST",
                url=url,
                status_code=self.token_status,
                headers={},
                elapsed_ms=1.0,
                body=json.dumps({"access_token": "fake-bearer-token"}).encode("utf-8"),
            )
        return Observation(
            method="POST", url=url, status_code=self.data_status, headers={}, elapsed_ms=1.0
        )


async def test_sentinel_exchanges_a_token_then_posts_to_the_dcr_stream_url() -> None:
    destination = resolve_sentinel_destination("https://my-dce.eastus-1.ingest.monitor.azure.com")
    message = render(ChannelKind.SIEM_SENTINEL, make_event())
    transport = SentinelTransport()
    result = await send_sentinel(
        destination,
        message,
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="shh",
        dcr_immutable_id="dcr-abc",
        stream_name="Custom-KervySecurityEvent",
        transport=transport,  # type: ignore[arg-type]
    )
    assert result.delivered
    assert result.status_code == 204
    assert len(transport.calls) == 2
    token_call, data_call = transport.calls
    assert "login.microsoftonline.com/tenant-1" in str(token_call["url"])
    assert "dataCollectionRules/dcr-abc/streams/Custom-KervySecurityEvent" in str(data_call["url"])
    data_headers = data_call["headers"]
    assert isinstance(data_headers, dict)
    assert data_headers["Authorization"] == "Bearer fake-bearer-token"


async def test_sentinel_a_non_204_data_response_is_not_delivered() -> None:
    destination = resolve_sentinel_destination("https://my-dce.eastus-1.ingest.monitor.azure.com")
    message = render(ChannelKind.SIEM_SENTINEL, make_event())
    transport = SentinelTransport(data_status=400)
    result = await send_sentinel(
        destination,
        message,
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="shh",
        dcr_immutable_id="dcr-abc",
        stream_name="Custom-KervySecurityEvent",
        transport=transport,  # type: ignore[arg-type]
    )
    assert not result.delivered
    assert result.status_code == 400


async def test_sentinel_a_failed_token_exchange_never_reaches_the_dce() -> None:
    destination = resolve_sentinel_destination("https://my-dce.eastus-1.ingest.monitor.azure.com")
    message = render(ChannelKind.SIEM_SENTINEL, make_event())
    transport = SentinelTransport(token_status=401)
    result = await send_sentinel(
        destination,
        message,
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="wrong",  # pragma: allowlist secret
        dcr_immutable_id="dcr-abc",
        stream_name="Custom-KervySecurityEvent",
        transport=transport,  # type: ignore[arg-type]
    )
    assert not result.delivered
    assert result.retryable is False
    # One call only: the DCE is never touched without a token.
    assert len(transport.calls) == 1


def test_sentinel_record_shape_matches_the_custom_table_schema() -> None:
    import json

    message = render(ChannelKind.SIEM_SENTINEL, make_event())
    records = json.loads(message.body)
    assert isinstance(records, list) and len(records) == 1
    record = records[0]
    assert record["EventType"] == "finding.critical"
    assert record["Severity"] == "CRITICAL"
    assert record["TargetName"] == "acme-api"
