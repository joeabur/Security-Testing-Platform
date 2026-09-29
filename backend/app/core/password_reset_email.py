"""Sending a password-reset link, through the same scope-adjudicated SMTP
path every other outbound email in this platform uses.

`app.core.integrations.send.send_email` turns out to already be generic
enough to reuse as-is: its parameters are a relay host/port/credentials and
a recipient list, not a `NotificationChannel` row — the organization-binding
lives one layer up, in `app.core.integrations.service`, which this module
never touches. A password reset has no organization in scope (the caller has
only proven they can read an inbox), so it calls `send_email` directly with
the platform's own relay from `Settings`, the same "one static, operator-
configured destination" shape `app.core.vcs.egress`/`app.core.oauth.egress`
already use for their own fixed hosts.
"""

from __future__ import annotations

import os

from app.core.config import Settings
from app.core.integrations.contract import DeliveryResult, RenderedMessage
from app.core.integrations.send import send_email


class PasswordResetEmailNotConfigured(Exception):
    """No platform SMTP relay is configured. Callers must not treat this as
    a delivery failure to retry — it is a deployment that has not turned the
    feature on."""


async def send_password_reset_email(
    settings: Settings, *, to_address: str, reset_url: str
) -> DeliveryResult:
    if (
        not settings.password_reset_enabled
        or not settings.platform_smtp_host
        or not settings.platform_smtp_from_address
    ):
        raise PasswordResetEmailNotConfigured("platform SMTP relay is not configured")

    password = (
        os.environ.get(settings.platform_smtp_password_env_var)
        if settings.platform_smtp_password_env_var
        else None
    )
    summary = (
        "A password reset was requested for your Kervy Security account.\n\n"
        f"Reset your password: {reset_url}\n\n"
        "This link expires shortly and can be used once. If you did not "
        "request this, you can ignore this email — your password has not "
        "been changed."
    )
    message = RenderedMessage(
        body=summary.encode("utf-8"),
        content_type="text/plain",
        summary=summary,
        headers={"Subject": "Reset your Kervy Security password"},
    )
    return await send_email(
        message,
        host=settings.platform_smtp_host,
        port=settings.platform_smtp_port,
        from_address=settings.platform_smtp_from_address,
        recipients=[to_address],
        username=settings.platform_smtp_username,
        password=password,
    )
