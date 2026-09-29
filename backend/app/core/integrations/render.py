"""Turning an `IntegrationEvent` into a body a channel will accept.

One module for every kind, because the interesting part is shared: what may
appear in the text. Each renderer draws from the same small set of scalar
fields, builds the link from the configured public base URL, and then hands
the result to `_safe` which runs the redactor over it and *refuses* rather
than truncates if anything matches.

Refusing is the right failure here. A truncated notification that silently
dropped the one line somebody needed is worse than a delivery marked
`refused` with a reason an operator can act on — and if a secret reaches this
layer at all, something upstream is broken and should be noticed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from app.core.integrations.contract import (
    ChannelKind,
    IntegrationError,
    IntegrationEvent,
    RenderedMessage,
)
from app.core.redaction.secrets import find_secrets

#: Kept well under every vendor's limit (Slack's block text cap is 3000).
#: A notification is a pointer to the platform, not a report.
MAX_SUMMARY_CHARS = 2000

_SEVERITY_ICON: Mapping[str, str] = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
    "INFORMATIONAL": "⚪",
}


def _safe(text: str) -> str:
    """Last line of defence before a payload leaves the deployment."""
    matches = find_secrets(text)
    if matches:
        kinds = sorted({match.kind for match in matches})
        raise IntegrationError(
            "refusing to send a notification containing "
            f"{', '.join(kinds)}; this is a redaction failure upstream, not a formatting problem"
        )
    if len(text) > MAX_SUMMARY_CHARS:
        raise IntegrationError(
            f"notification body is {len(text)} chars, over the {MAX_SUMMARY_CHARS} cap; "
            "a notification links to the platform rather than reproducing a report"
        )
    return text


def link_for(event: IntegrationEvent, base_url: str | None) -> str | None:
    """Absolute link back into the platform, or nothing.

    Nothing, rather than a guess, when no base URL is configured: a broken
    link in an alert teaches readers to ignore alerts.
    """
    if not base_url or not event.link_path:
        return None
    return f"{base_url.rstrip('/')}/{event.link_path.lstrip('/')}"


def summary_lines(event: IntegrationEvent, base_url: str | None) -> list[str]:
    """The shared plain-text rendering every kind is built from."""
    icon = _SEVERITY_ICON.get((event.severity or "").upper(), "")
    heading = f"{icon} {event.title}".strip()
    lines = [heading, f"Event: {event.event_type.value}"]
    if event.severity:
        lines.append(f"Severity: {event.severity}")
    if event.target_name:
        lines.append(f"Target: {event.target_name}")
    for key, value in event.facts.items():
        lines.append(f"{key}: {value}")
    lines.append(f"At: {event.occurred_at_iso}")
    link = link_for(event, base_url)
    if link:
        lines.append(link)
    return lines


def _slack(event: IntegrationEvent, base_url: str | None) -> RenderedMessage:
    summary = _safe("\n".join(summary_lines(event, base_url)))
    # `text` as well as blocks: `text` is what a mobile notification and a
    # screen reader use, and a blocks-only message reads as empty there.
    payload = {
        "text": summary,
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": summary}}],
    }
    return RenderedMessage(
        body=json.dumps(payload).encode("utf-8"),
        content_type="application/json",
        summary=summary,
    )


def _teams(event: IntegrationEvent, base_url: str | None) -> RenderedMessage:
    summary = _safe("\n".join(summary_lines(event, base_url)))
    # MessageCard rather than an Adaptive Card: it is what a plain Teams
    # incoming webhook renders without a Power Automate flow in front of it.
    payload: dict[str, object] = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": event.title,
        "title": event.title,
        "text": summary.replace("\n", "\n\n"),
    }
    link = link_for(event, base_url)
    if link:
        payload["potentialAction"] = [
            {
                "@type": "OpenUri",
                "name": "Open in Kervy",
                "targets": [{"os": "default", "uri": link}],
            }
        ]
    return RenderedMessage(
        body=json.dumps(payload).encode("utf-8"),
        content_type="application/json",
        summary=summary,
    )


def _generic(event: IntegrationEvent, base_url: str | None) -> RenderedMessage:
    summary = _safe("\n".join(summary_lines(event, base_url)))
    payload = {
        "event": event.event_type.value,
        "occurred_at": event.occurred_at_iso,
        "organization_id": str(event.organization_id),
        "title": event.title,
        "severity": event.severity,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "target_name": event.target_name,
        "run_id": str(event.run_id) if event.run_id else None,
        "facts": {key: str(value) for key, value in event.facts.items()},
        "link": link_for(event, base_url),
    }
    # Sorted keys and no whitespace: the signature covers these exact bytes,
    # so the serialization must be stable across processes and versions.
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _safe(body.decode("utf-8"))
    return RenderedMessage(body=body, content_type="application/json", summary=summary)


def _email(event: IntegrationEvent, base_url: str | None) -> RenderedMessage:
    summary = _safe("\n".join(summary_lines(event, base_url)))
    subject = _safe(f"[Kervy] {event.severity or event.event_type.value}: {event.title}"[:200])
    return RenderedMessage(
        body=summary.encode("utf-8"),
        content_type="text/plain; charset=utf-8",
        summary=summary,
        headers={"Subject": subject},
    )


_RENDERERS = {
    ChannelKind.SLACK_WEBHOOK: _slack,
    ChannelKind.MSTEAMS_WEBHOOK: _teams,
    ChannelKind.GENERIC_WEBHOOK: _generic,
    ChannelKind.EMAIL_SMTP: _email,
}


def render(
    kind: ChannelKind, event: IntegrationEvent, *, base_url: str | None = None
) -> RenderedMessage:
    renderer = _RENDERERS.get(kind)
    if renderer is None:
        raise IntegrationError(f"no renderer for channel kind {kind.value}")
    return renderer(event, base_url)
