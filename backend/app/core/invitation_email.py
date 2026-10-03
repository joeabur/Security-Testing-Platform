"""Sending an organization-invitation link, through the same scope-adjudicated
SMTP path every other outbound email in this platform uses.

Same shape as `app/core/password_reset_email.py`, for the same reason: this
has no `NotificationChannel` to bind to (the invited address has no
organization membership yet — that is exactly what the invitation grants),
so it calls `app.core.integrations.send.send_email` directly with the
platform's own fixed relay.
"""

from __future__ import annotations

import os

from app.core.config import Settings
from app.core.integrations.contract import DeliveryResult, RenderedMessage
from app.core.integrations.send import send_email
from app.models.organization import Role


class InvitationEmailNotConfigured(Exception):
    """No platform SMTP relay is configured. Callers must not treat this as
    a delivery failure to retry — it is a deployment that has not turned the
    feature on. The invitation row is still created either way: an admin
    can always read the token out of band if mail is not wired up yet."""


async def send_invitation_email(
    settings: Settings,
    *,
    to_address: str,
    organization_name: str,
    role: Role,
    invited_by_name: str,
    accept_url: str,
) -> DeliveryResult:
    if (
        not settings.invitation_email_enabled
        or not settings.platform_smtp_host
        or not settings.platform_smtp_from_address
    ):
        raise InvitationEmailNotConfigured("platform SMTP relay is not configured")

    password = (
        os.environ.get(settings.platform_smtp_password_env_var)
        if settings.platform_smtp_password_env_var
        else None
    )
    summary = (
        f"{invited_by_name} invited you to join {organization_name} on Kervy "
        f"Security as {role.value}.\n\n"
        f"Accept the invitation: {accept_url}\n\n"
        "This link expires in a week and can be used once. If you were not "
        "expecting this, you can ignore this email."
    )
    message = RenderedMessage(
        body=summary.encode("utf-8"),
        content_type="text/plain",
        summary=summary,
        headers={"Subject": f"You've been invited to {organization_name} on Kervy Security"},
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
