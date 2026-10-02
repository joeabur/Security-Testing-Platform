"""Deciding which channels an event goes to, and delivering it once.

Three things here are load-bearing.

**Subscription is a filter, not a fan-out of everything.** A channel names the
event types it wants and a severity floor. An event that no channel subscribes
to produces no delivery rows at all, so the table stays a record of intent
rather than a log of everything that ever happened.

**A delivery row is written before the attempt, not after.** If the worker
dies mid-send, the row is there in `pending` with an attempt count, and the
retry sweep finds it. Recording afterwards would make a crash indistinguishable
from an event nobody ever tried to send.

**A refusal and a failure are different outcomes.** A misconfigured channel, a
host the policy does not permit, or a payload the redactor stopped goes to
`REFUSED` and is never retried, because the same configuration fails the same
way and a retry loop against a bad config is how rate limits get hit. A 503 or
a socket error goes to `FAILED` with a backoff, and to `DEAD_LETTER` once the
attempts run out — visible, not silently dropped.

Nothing here decides *whether* the platform may reach a destination: that is
`policy.resolve_destination` plus the scope engine, and this module treats
their refusals as final.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from app.core.integrations.contract import (
    ChannelKind,
    DeliveryResult,
    EventType,
    IntegrationError,
    IntegrationEvent,
    severity_at_least,
)
from app.core.integrations.policy import (
    redact_url,
    resolve_secret,
    resolve_sentinel_destination,
    resolve_smtp_host,
    resolve_webhook_destination,
)
from app.core.integrations.render import render
from app.core.integrations.send import (
    DEFAULT_SMTP_PORT,
    send_email,
    send_sentinel,
    send_webhook,
)
from app.core.redaction.secrets import redact
from app.models.integration import DeliveryStatus, NotificationChannel

#: Attempts in total, including the first. Four attempts across ~15 minutes
#: covers a vendor blip without keeping a dead channel alive for hours.
MAX_ATTEMPTS = 4

#: Backoff per completed attempt, in seconds. Explicit rather than computed so
#: the schedule is something an operator can read off and predict.
BACKOFF_SECONDS: tuple[int, ...] = (30, 120, 600)

MAX_ERROR_CHARS = 400


@dataclass(frozen=True)
class ChannelSecrets:
    """Secrets resolved for one channel, held only for the duration of a send.

    A separate type rather than loose arguments so that the one place holding
    credential values is named, easy to find, and obviously never persisted.
    """

    endpoint_url: str | None = None
    signing_secret: str | None = None
    smtp_password: str | None = None
    #: Splunk HEC only.
    auth_token: str | None = None
    #: Sentinel only — the Entra ID app's client secret.
    azure_client_secret: str | None = None


def subscribes(channel: NotificationChannel, event: IntegrationEvent) -> bool:
    """Does this channel want this event?"""
    if not channel.enabled:
        return False
    if event.event_type.value not in (channel.events or []):
        return False
    return severity_at_least(event.severity, channel.min_severity)


def select_channels(
    channels: Sequence[NotificationChannel], event: IntegrationEvent
) -> list[NotificationChannel]:
    return [
        channel
        for channel in channels
        if channel.organization_id == event.organization_id and subscribes(channel, event)
    ]


def backoff_for(attempts: int) -> timedelta | None:
    """Delay before attempt number `attempts + 1`, or None if there is none left."""
    if attempts >= MAX_ATTEMPTS or attempts > len(BACKOFF_SECONDS):
        return None
    return timedelta(seconds=BACKOFF_SECONDS[attempts - 1])


#: Any absolute URL appearing in text we are about to store or return.
_URL_IN_TEXT = re.compile(r"https?://[^\s\"\'<>)\]]+")


def scrub(text: str) -> str:
    """Make an error string safe to store, return by API and log.

    Two passes, because one is not enough:

    * **URLs are replaced by their redacted shape.** A channel endpoint is a
      credential — the token is in the path — and an `httpx` or `smtplib`
      exception routinely quotes the URL it failed on. Relying on the secret
      detector here would be a mistake: a Slack webhook token is an opaque
      random string that matches no issuer pattern, so the redactor has no
      reason to catch it. Removing the path outright does not depend on
      recognising what is in it.
    * **Then the secret detector runs**, for anything else that came along.

    Truncated last, so a long message cannot push the redaction off the end.
    """
    without_urls = _URL_IN_TEXT.sub(lambda match: redact_url(match.group(0)), text)
    return redact(without_urls).redacted_text[:MAX_ERROR_CHARS]


async def _deliver_once_raw(
    channel: NotificationChannel,
    event: IntegrationEvent,
    *,
    secrets: ChannelSecrets | None = None,
    environ: Mapping[str, str] | None = None,
    operator_webhook_hosts: Sequence[str] = (),
    operator_smtp_hosts: Sequence[str] = (),
    base_url: str | None = None,
) -> DeliveryResult:
    """One attempt at one channel. Never raises for a configuration problem.

    `secrets` is an injection point for tests and for a caller that has already
    resolved them; left out, they are read from the environment here.
    """
    try:
        kind = ChannelKind(channel.kind)
    except ValueError:
        return DeliveryResult(
            delivered=False, detail=f"unknown channel kind {channel.kind!r}", retryable=False
        )

    try:
        message = render(kind, event, base_url=base_url)
    except IntegrationError as exc:
        return DeliveryResult(delivered=False, detail=scrub(str(exc)), retryable=False)

    resolved = secrets or ChannelSecrets()
    try:
        if kind is ChannelKind.SIEM_SENTINEL:
            if not channel.sentinel_endpoint:
                raise IntegrationError("Sentinel channel has no sentinel_endpoint configured")
            if not (
                channel.azure_tenant_id
                and channel.azure_client_id
                and channel.sentinel_dcr_immutable_id
                and channel.sentinel_stream_name
            ):
                raise IntegrationError(
                    "Sentinel channel is missing azure_tenant_id, azure_client_id, "
                    "sentinel_dcr_immutable_id, or sentinel_stream_name"
                )
            client_secret = resolved.azure_client_secret
            if client_secret is None and channel.azure_client_secret_env_var:
                client_secret = resolve_secret(channel.azure_client_secret_env_var, environ)
            if not client_secret:
                raise IntegrationError("Sentinel channel has no azure_client_secret_env_var")
            destination = resolve_sentinel_destination(
                channel.sentinel_endpoint, operator_hosts=operator_webhook_hosts
            )
            return await send_sentinel(
                destination,
                message,
                tenant_id=channel.azure_tenant_id,
                client_id=channel.azure_client_id,
                client_secret=client_secret,
                dcr_immutable_id=channel.sentinel_dcr_immutable_id,
                stream_name=channel.sentinel_stream_name,
            )

        if kind is ChannelKind.EMAIL_SMTP:
            host = resolve_smtp_host(channel.smtp_host or "", operator_hosts=operator_smtp_hosts)
            password = resolved.smtp_password
            if password is None and channel.smtp_password_env_var:
                password = resolve_secret(channel.smtp_password_env_var, environ)
            if not channel.from_address:
                raise IntegrationError("email channel has no from_address")
            return await send_email(
                message,
                host=host,
                port=channel.smtp_port or DEFAULT_SMTP_PORT,
                from_address=channel.from_address,
                recipients=list(channel.recipients or []),
                username=channel.smtp_username,
                password=password,
            )

        if not channel.endpoint_env_var:
            raise IntegrationError("webhook channel has no endpoint_env_var")
        destination = resolve_webhook_destination(
            kind,
            channel.endpoint_env_var,
            operator_hosts=operator_webhook_hosts,
            environ=(
                {channel.endpoint_env_var: resolved.endpoint_url}
                if resolved.endpoint_url is not None
                else environ
            ),
        )
        signing_secret = resolved.signing_secret
        if (
            signing_secret is None
            and kind in (ChannelKind.GENERIC_WEBHOOK, ChannelKind.SIEM_GENERIC_CEF)
            and channel.signing_secret_env_var
        ):
            signing_secret = resolve_secret(channel.signing_secret_env_var, environ)
        auth_token = resolved.auth_token
        if (
            auth_token is None
            and kind is ChannelKind.SIEM_SPLUNK_HEC
            and channel.auth_token_env_var
        ):
            auth_token = resolve_secret(channel.auth_token_env_var, environ)
        return await send_webhook(
            destination,
            message,
            event_type=event.event_type.value,
            signing_secret=signing_secret,
            auth_token=auth_token,
        )
    except IntegrationError as exc:
        # Configuration, policy, or a payload the redactor stopped. Final.
        return DeliveryResult(delivered=False, detail=scrub(str(exc)), retryable=False)


async def deliver_once(
    channel: NotificationChannel,
    event: IntegrationEvent,
    *,
    secrets: ChannelSecrets | None = None,
    environ: Mapping[str, str] | None = None,
    operator_webhook_hosts: Sequence[str] = (),
    operator_smtp_hosts: Sequence[str] = (),
    base_url: str | None = None,
) -> DeliveryResult:
    """One attempt, with every outcome's detail scrubbed on the way out.

    A wrapper rather than scrubbing at each `return` inside, so a future branch
    that forgets to scrub cannot leak a URL: there is one door.
    """
    result = await _deliver_once_raw(
        channel,
        event,
        secrets=secrets,
        environ=environ,
        operator_webhook_hosts=operator_webhook_hosts,
        operator_smtp_hosts=operator_smtp_hosts,
        base_url=base_url,
    )
    return replace(result, detail=scrub(result.detail))


def event_snapshot(event: IntegrationEvent) -> dict[str, object]:
    """The scalar form stored on a delivery row, for replay and for reading."""
    return {
        "event_type": event.event_type.value,
        "occurred_at": event.occurred_at_iso,
        "title": event.title,
        "severity": event.severity,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "target_name": event.target_name,
        "run_id": str(event.run_id) if event.run_id else None,
        "facts": {key: str(value) for key, value in event.facts.items()},
        "link_path": event.link_path,
    }


def event_from_snapshot(
    organization_id: uuid.UUID, snapshot: Mapping[str, object]
) -> IntegrationEvent:
    """Rebuild an event from a delivery row, for a retry.

    Rebuilt rather than re-derived from the finding or run, on purpose: a retry
    must send what the original attempt would have sent. Re-reading the finding
    would silently notify about its *current* state, which is how a "critical
    finding" alert arrives about something a human already closed.
    """
    facts_raw = snapshot.get("facts")
    facts: dict[str, str | int | float] = (
        {str(key): str(value) for key, value in facts_raw.items()}
        if isinstance(facts_raw, Mapping)
        else {}
    )
    run_id_raw = snapshot.get("run_id")
    return IntegrationEvent(
        event_type=EventType(str(snapshot["event_type"])),
        organization_id=organization_id,
        occurred_at_iso=str(snapshot.get("occurred_at") or ""),
        title=str(snapshot.get("title") or ""),
        severity=_opt_str(snapshot.get("severity")),
        resource_type=_opt_str(snapshot.get("resource_type")),
        resource_id=_opt_str(snapshot.get("resource_id")),
        target_name=_opt_str(snapshot.get("target_name")),
        run_id=uuid.UUID(str(run_id_raw)) if run_id_raw else None,
        facts=facts,
        link_path=_opt_str(snapshot.get("link_path")),
    )


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)


def status_after(result: DeliveryResult, attempts: int) -> tuple[DeliveryStatus, datetime | None]:
    """Where a delivery lands after an attempt, and when to try again."""
    if result.delivered:
        return DeliveryStatus.DELIVERED, None
    if not result.retryable:
        return DeliveryStatus.REFUSED, None
    delay = backoff_for(attempts)
    if delay is None:
        return DeliveryStatus.DEAD_LETTER, None
    return DeliveryStatus.FAILED, datetime.now(UTC) + delay


def event_for_run(
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    status: str,
    target_name: str | None,
    counts: Mapping[str, int],
    occurred_at: datetime | None = None,
) -> IntegrationEvent:
    """The `assessment.completed` / `assessment.failed` event.

    Severity is the highest band actually present, so a channel with a
    `min_severity` of HIGH is not woken by a run that found nothing.
    """
    highest: str | None = None
    for candidate in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        if counts.get(candidate.lower(), counts.get(candidate, 0)):
            highest = candidate
            break
    when = occurred_at or datetime.now(UTC)
    completed = status.lower() in {"completed", "succeeded"}
    return IntegrationEvent(
        event_type=(EventType.ASSESSMENT_COMPLETED if completed else EventType.ASSESSMENT_FAILED),
        organization_id=organization_id,
        occurred_at_iso=when.isoformat(),
        title=f"Assessment {status} for {target_name or 'target'}",
        severity=highest,
        resource_type="assessment_run",
        resource_id=str(run_id),
        target_name=target_name,
        run_id=run_id,
        facts={key: value for key, value in counts.items() if value},
        link_path=f"runs/{run_id}",
    )


def event_for_investigation(
    *,
    organization_id: uuid.UUID,
    investigation_id: uuid.UUID,
    status: str,
    tool_count: int,
    failed_tool_name: str | None = None,
    occurred_at: datetime | None = None,
) -> IntegrationEvent:
    """`agent_investigation.completed` / `.failed`, fired once per
    investigation that reaches a terminal state (never while it is still
    awaiting approval — that is not "done" yet).

    `facts` carries only a step count and, on failure, the tool's own fixed
    name — never the natural-language request, a tool's arguments, or any
    tool's result, per the agent framework's zero-persistence rule. A
    channel that renders this sees "an investigation ran three tools and
    completed," not what it asked or what it found.
    """
    when = occurred_at or datetime.now(UTC)
    completed = status.lower() == "completed"
    facts: dict[str, str | int | float] = {"steps": tool_count}
    if failed_tool_name:
        facts["failed_tool"] = failed_tool_name
    return IntegrationEvent(
        event_type=(
            EventType.AGENT_INVESTIGATION_COMPLETED
            if completed
            else EventType.AGENT_INVESTIGATION_FAILED
        ),
        organization_id=organization_id,
        occurred_at_iso=when.isoformat(),
        title=f"AI agent investigation {status}",
        resource_type="agent_investigation",
        resource_id=str(investigation_id),
        facts=facts,
        link_path=f"agent/investigate/{investigation_id}/status",
    )


def event_for_finding(
    *,
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    title: str,
    severity: str,
    target_name: str | None,
    run_id: uuid.UUID | None = None,
    occurred_at: datetime | None = None,
) -> IntegrationEvent:
    """`finding.created`, or `finding.critical` when it is a critical one.

    A critical finding is emitted as its own event type so a channel can page
    on criticals without also taking every low.
    """
    when = occurred_at or datetime.now(UTC)
    is_critical = severity.upper() == "CRITICAL"
    return IntegrationEvent(
        event_type=EventType.FINDING_CRITICAL if is_critical else EventType.FINDING_CREATED,
        organization_id=organization_id,
        occurred_at_iso=when.isoformat(),
        # The finding's own title, which is probe-generated and never contains
        # target output — see `app/core/findings`.
        title=title,
        severity=severity.upper(),
        resource_type="finding",
        resource_id=str(finding_id),
        target_name=target_name,
        run_id=run_id,
        link_path=f"findings/{finding_id}",
    )


def event_for_retest(
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    target_name: str | None,
    reproduced: int,
    not_reproduced: int,
    not_tested: int,
    occurred_at: datetime | None = None,
) -> IntegrationEvent:
    """`retest.completed`, fired once a `RunKind.RETEST` run finishes.

    Distinct from `assessment.completed`, which every run — retest or not —
    already gets: this one carries the verdict counts a retest exists to
    produce, so a channel can tell "a scan ran" from "three findings were
    confirmed fixed" without parsing the run summary's generic facts.
    """
    when = occurred_at or datetime.now(UTC)
    return IntegrationEvent(
        event_type=EventType.RETEST_COMPLETED,
        organization_id=organization_id,
        occurred_at_iso=when.isoformat(),
        title=f"Retest completed for {target_name or 'target'}",
        resource_type="assessment_run",
        resource_id=str(run_id),
        target_name=target_name,
        run_id=run_id,
        facts={
            "reproduced": reproduced,
            "not_reproduced": not_reproduced,
            "not_tested": not_tested,
        },
        link_path=f"runs/{run_id}",
    )


def event_for_workflow_gate(
    *,
    organization_id: uuid.UUID,
    workflow_run_id: uuid.UUID,
    workflow_name: str,
    reasons: Sequence[str],
    counts: Mapping[str, int],
    occurred_at: datetime | None = None,
) -> IntegrationEvent:
    """`gate.failed`, fired when a workflow run's gate decision refuses it.

    Only the failing decision gets an event — a passing gate is already
    covered by `workflow.completed` in the audit log, and this platform
    fires no `workflow.*` integration event at all (§ module docstring: "a
    channel that fires on every triage keystroke gets muted by its
    readers"). A failing gate is the one workflow outcome worth paging on:
    it is the automation equivalent of a broken CI build.
    """
    when = occurred_at or datetime.now(UTC)
    facts: dict[str, str | int | float] = {key: value for key, value in counts.items() if value}
    if reasons:
        facts["reasons"] = "; ".join(reasons)
    return IntegrationEvent(
        event_type=EventType.GATE_FAILED,
        organization_id=organization_id,
        occurred_at_iso=when.isoformat(),
        title=f"Security gate failed for workflow {workflow_name}",
        resource_type="workflow_run",
        resource_id=str(workflow_run_id),
        facts=facts,
        link_path=f"workflows/{workflow_run_id}",
    )
