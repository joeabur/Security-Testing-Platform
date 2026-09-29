"""Actually sending a rendered message.

A webhook delivery goes through `GatedTransport` like everything else, under
`notification_egress_context`. Nothing here constructs an HTTP client.

Email is the awkward case and worth being explicit about. SMTP is not HTTP,
so it cannot literally travel through `GatedTransport` — but the reason §28
routes everything through one place is that outbound destinations get checked
by the scope engine, and that reason applies to a mail relay exactly as much.
So `send_email` asks the same `ScopeEngine` to adjudicate the relay first, via
`explain` on an `smtp://host:port/` URL under a context whose allowlist holds
that one host. The engine re-resolves DNS and applies the blocked-range rules,
so a relay that resolves to loopback or to the cloud metadata service is
refused before `smtplib` is touched. The connection is then opened with
STARTTLS required, and `smtplib` is imported inside the function so that
nothing in the request path pulls it in.

That is a smaller guarantee than the webhook path has — the engine does not
see the socket — and it is written down rather than glossed over.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from app.core.integrations.contract import (
    ChannelKind,
    DeliveryResult,
    Destination,
    IntegrationError,
    RenderedMessage,
)
from app.core.integrations.egress import notification_egress_context
from app.core.integrations.signing import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    sign,
)
from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.engine import ScopeEngine
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import Budgets, ResolvedAuthorization, RulesOfEngagement
from app.core.scope.transport import GatedTransport, ScopeBlockedError

DEFAULT_SMTP_PORT = 587

#: 5xx and 429 are worth another go; a 4xx means the request was wrong and
#: will be wrong again. 408 is the exception: a timeout is about the moment,
#: not the request.
_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504, 507, 509})


async def send_webhook(
    destination: Destination,
    message: RenderedMessage,
    *,
    event_type: str,
    signing_secret: str | None = None,
    transport: GatedTransport | None = None,
) -> DeliveryResult:
    """POST a rendered body to a checked destination through the gated transport."""
    if destination.kind == ChannelKind.EMAIL_SMTP:
        raise IntegrationError("send_webhook called for an email channel")

    headers = {"Content-Type": message.content_type, EVENT_HEADER: event_type}
    if destination.kind == ChannelKind.GENERIC_WEBHOOK:
        if not signing_secret:
            raise IntegrationError(
                "a generic webhook must be signed; configure signing_secret_env_var "
                "so the receiver can tell this POST from anyone else's"
            )
        # Signed over the exact bytes about to be sent, not a re-render.
        timestamp, signature = sign(signing_secret, message.body)
        headers[TIMESTAMP_HEADER] = timestamp
        headers[SIGNATURE_HEADER] = signature

    ctx = notification_egress_context(destination)
    client = transport or GatedTransport()
    try:
        observation = await client.send(
            ctx,
            method="POST",
            url=destination.url,
            headers=headers,
            content=message.body,
            timeout_seconds=15.0,
        )
    except ScopeBlockedError as exc:
        # A scope refusal is never retried: it is a decision, not a fault.
        return DeliveryResult(
            delivered=False,
            detail=f"refused by scope engine: {exc.decision.reason}",
            retryable=False,
        )
    except Exception as exc:  # noqa: BLE001 - a transport fault is retryable
        return DeliveryResult(
            delivered=False, detail=f"{type(exc).__name__}: {exc}"[:400], retryable=True
        )

    status = observation.status_code
    if 200 <= status < 300:
        return DeliveryResult(delivered=True, status_code=status, detail="delivered")
    return DeliveryResult(
        delivered=False,
        status_code=status,
        # The response body is deliberately not recorded: a vendor error page
        # is noise, and a receiver that echoes our payload back would put it
        # in our database.
        detail=f"destination returned HTTP {status}",
        retryable=status in _RETRYABLE_STATUS,
    )


def smtp_scope_context(host: str, port: int) -> RunContext:
    """Scope context for one mail relay, so the engine can adjudicate it.

    `allowed_methods` is `("SMTP",)` rather than a borrowed HTTP verb: this
    context must not be usable to make an HTTP request even by accident.
    """
    now = datetime.now(UTC)
    budgets = Budgets(
        max_requests=2,
        max_concurrency=1,
        requests_per_second=2.0,
        max_tokens_sent=0,
        max_tokens_received=0,
        max_estimated_cost_usd=0.0,
        max_wall_clock_minutes=2,
    )
    roe = RulesOfEngagement(
        allowed_domains=(host,),
        excluded_domains=(),
        allowed_ip_ranges=(),
        allowed_paths=(),
        excluded_paths=(),
        allowed_methods=("SMTP",),
        forbidden_headers=(),
        budgets=budgets,
        safe_mode=True,
    )
    return RunContext(
        roe=roe,
        authorization=ResolvedAuthorization(
            valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(minutes=5)
        ),
        budgets=BudgetTracker(budgets),
        kill_switch=KillSwitch(),
    )


async def send_email(
    message: RenderedMessage,
    *,
    host: str,
    port: int = DEFAULT_SMTP_PORT,
    from_address: str,
    recipients: Sequence[str],
    username: str | None = None,
    password: str | None = None,
    engine: ScopeEngine | None = None,
    timeout_seconds: float = 20.0,
) -> DeliveryResult:
    """Relay one message, after the scope engine has cleared the relay host."""
    if not recipients:
        raise IntegrationError("email channel has no recipients")

    from app.core.scope.dns import SystemDnsResolver

    scope = engine or ScopeEngine()
    decision = await scope.explain(
        smtp_scope_context(host, port),
        dns_resolver=SystemDnsResolver(),
        method="SMTP",
        url=f"smtp://{host}:{port}/",
    )
    if not decision.allowed:
        return DeliveryResult(
            delivered=False,
            detail=f"refused by scope engine: {decision.reason}",
            retryable=False,
        )

    # Imported here so the request path never loads smtplib, and so the one
    # place that opens a socket outside GatedTransport is visible in a grep.
    import smtplib
    from email.message import EmailMessage

    mail = EmailMessage()
    mail["From"] = from_address
    mail["To"] = ", ".join(recipients)
    mail["Subject"] = message.headers.get("Subject", "Kervy notification")
    mail.set_content(message.summary)

    try:
        with smtplib.SMTP(host, port, timeout=timeout_seconds) as smtp:
            smtp.ehlo()
            # Required, not opportunistic: a notification carries finding
            # titles and severities, and a silent downgrade to clear text
            # would be a finding of ours in someone else's report.
            smtp.starttls()
            smtp.ehlo()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(mail, from_addr=from_address, to_addrs=list(recipients))
    except smtplib.SMTPNotSupportedError as exc:
        return DeliveryResult(
            delivered=False,
            detail=f"relay does not support STARTTLS: {exc}"[:400],
            retryable=False,
        )
    except smtplib.SMTPResponseException as exc:
        return DeliveryResult(
            delivered=False,
            status_code=exc.smtp_code,
            detail=f"SMTP {exc.smtp_code}"[:400],
            # 4xx is a transient SMTP refusal by definition; 5xx is permanent.
            retryable=400 <= exc.smtp_code < 500,
        )
    except Exception as exc:  # noqa: BLE001 - a socket fault is retryable
        return DeliveryResult(
            delivered=False, detail=f"{type(exc).__name__}: {exc}"[:400], retryable=True
        )
    return DeliveryResult(delivered=True, detail="relayed")
