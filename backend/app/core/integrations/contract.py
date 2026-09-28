"""What an outbound integration is, and what it is allowed to carry.

Notifications are the first feature in this platform that sends data *out*
to a destination somebody else controls, so the contract here is written
around two questions rather than around convenience.

**Can a channel become an SSRF primitive?** No, and not because the
destination is trusted. Every delivery goes through the one scope-gated
transport under a context whose allowlist is derived from the channel's
resolved endpoint and contains exactly that host (see `egress.py`), with no
allowed IP ranges — so loopback, RFC1918 and the cloud metadata service are
refused for a notification exactly as they are for a target. On top of that,
`KIND_HOST_POLICY` pins the vendor kinds to their vendor hosts, and a
generic webhook host must appear in an operator-set allowlist that lives in
the environment, not in the database. An organization admin can therefore
choose *which* Slack workspace to notify; they cannot choose to notify
`169.254.169.254`.

**Can a notification leak what the platform redacts?** Evidence bundles are
redacted before they are written (§13); a notification must not be the hole
in that. So a payload is assembled from a fixed set of low-cardinality
fields — identifiers, counts, severities, a link back into the platform —
and never from a response body, an evidence bundle, a judge transcript or a
secret-bearing snippet. `render` then runs the assembled text through the
same redactor as a last line of defence, and a payload that still trips the
detector is refused rather than truncated.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum


class ChannelKind(StrEnum):
    """Transports we know how to speak.

    `GENERIC_WEBHOOK` is the extension point: a signed JSON POST, which is
    what a customer needs to feed a SIEM, a ticket tracker or an internal
    bot without us writing an adapter per vendor.
    """

    SLACK_WEBHOOK = "slack_webhook"
    MSTEAMS_WEBHOOK = "msteams_webhook"
    GENERIC_WEBHOOK = "generic_webhook"
    EMAIL_SMTP = "email_smtp"


class EventType(StrEnum):
    """Events an organization can subscribe a channel to.

    Deliberately few, and all of them describe something that already
    happened and was already recorded. There is no `finding.updated`: a
    channel that fires on every triage keystroke gets muted by its readers,
    and a muted channel is worse than no channel.
    """

    ASSESSMENT_COMPLETED = "assessment.completed"
    ASSESSMENT_FAILED = "assessment.failed"
    FINDING_CREATED = "finding.created"
    FINDING_CRITICAL = "finding.critical"
    RETEST_COMPLETED = "retest.completed"
    GATE_FAILED = "gate.failed"
    # The native AI agent (Agent Phase 6). Fired once an investigation
    # reaches a terminal state — never while awaiting approval, and never
    # carrying the request text or any tool's output; see
    # `event_for_investigation`.
    AGENT_INVESTIGATION_COMPLETED = "agent_investigation.completed"
    AGENT_INVESTIGATION_FAILED = "agent_investigation.failed"


#: Severity order, lowest first, for `min_severity` comparisons. Kept local
#: rather than imported from the probe contract so a change to probe
#: severities cannot silently re-tune which notifications go out.
SEVERITY_ORDER: tuple[str, ...] = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def severity_at_least(severity: str | None, minimum: str | None) -> bool:
    """True when `severity` meets `minimum`.

    An unknown or absent severity passes: an event we cannot rank is not
    silently dropped, because a dropped security notification is the failure
    mode that costs the most.
    """
    if minimum is None:
        return True
    if severity is None or severity.upper() not in SEVERITY_ORDER:
        return True
    if minimum.upper() not in SEVERITY_ORDER:
        return True
    return SEVERITY_ORDER.index(severity.upper()) >= SEVERITY_ORDER.index(minimum.upper())


#: Hosts each vendor kind may reach, as exact hostnames or a single leading
#: `*.` wildcard. Empty means "no built-in hosts": the operator allowlist is
#: the only way in, which is the rule for `GENERIC_WEBHOOK` and
#: `EMAIL_SMTP` because their destinations are site-specific by nature.
KIND_HOST_POLICY: Mapping[ChannelKind, tuple[str, ...]] = {
    ChannelKind.SLACK_WEBHOOK: ("hooks.slack.com",),
    ChannelKind.MSTEAMS_WEBHOOK: (
        "*.webhook.office.com",
        "*.logic.azure.com",
    ),
    ChannelKind.GENERIC_WEBHOOK: (),
    ChannelKind.EMAIL_SMTP: (),
}


class IntegrationError(Exception):
    """A channel is misconfigured, or a payload is not safe to send.

    Distinct from a delivery failure: this means do not retry, because
    retrying the same configuration will fail the same way.
    """


@dataclass(frozen=True)
class IntegrationEvent:
    """One thing that happened, in the vocabulary a channel renders.

    Every field is either an identifier, an enum value, a count or a short
    human label. There is deliberately no free-text field carrying target
    output: see the module docstring.
    """

    event_type: EventType
    organization_id: uuid.UUID
    occurred_at_iso: str
    title: str
    severity: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    target_name: str | None = None
    run_id: uuid.UUID | None = None
    #: Small, scalar-valued facts: `{"critical": 2, "high": 5}`. Values are
    #: coerced to `str` when rendered, so nothing structured sneaks through.
    facts: Mapping[str, str | int | float] = field(default_factory=dict)
    #: Path within the platform UI, appended to the configured public base
    #: URL by the renderer. A path, not a URL, so an event cannot carry a
    #: link to somewhere the platform does not host.
    link_path: str | None = None


@dataclass(frozen=True)
class RenderedMessage:
    """A channel-specific body, ready to hand to the transport.

    `body` is bytes because signing must cover exactly what is sent; a
    re-serialization between signing and sending is how signature mismatches
    happen.
    """

    body: bytes
    content_type: str
    #: Plain-text rendering, for the email adapter and for tests that assert
    #: on what a human will read.
    summary: str
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Destination:
    """Where a delivery goes, after policy checks and secret resolution.

    Holds a resolved URL that may contain a token in its path (a Slack
    incoming webhook does), so it is never persisted, logged or returned by
    the API — `redacted` is what any of those use.
    """

    kind: ChannelKind
    host: str
    url: str = field(repr=False)
    redacted: str = ""
    port: int | None = None

    def __post_init__(self) -> None:
        if not self.host:
            raise IntegrationError("destination has no host")


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of one attempt."""

    delivered: bool
    status_code: int | None = None
    #: Already-redacted, short. Stored on the delivery row and shown in the
    #: API, so it must never carry a token or a response body.
    detail: str = ""
    retryable: bool = False


def host_permitted(host: str, patterns: Sequence[str]) -> bool:
    """Exact match, or a single leading `*.` wildcard one label deep or more.

    `*.webhook.office.com` matches `foo.webhook.office.com` and
    `a.b.webhook.office.com`, but not `webhook.office.com` itself and not
    `evilwebhook.office.com` — the dot is part of the suffix on purpose.
    """
    candidate = host.lower().rstrip(".")
    for raw in patterns:
        pattern = raw.lower().strip().rstrip(".")
        if not pattern:
            continue
        if pattern.startswith("*."):
            if candidate.endswith(pattern[1:]):
                return True
            continue
        if candidate == pattern:
            return True
    return False
