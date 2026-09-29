"""Turning a stored channel into a destination we are allowed to reach.

Three checks, in order, and all three must pass before any bytes move:

1. **The secret is resolved from the environment, not the database.** A Slack
   or Teams incoming webhook URL carries its token in the path, so the URL
   *is* a credential and §5 forbids storing it. The channel row holds the
   *name* of an environment variable; the value is read here, at delivery
   time, in the process that needs it. Nothing persists it and nothing logs
   it — `Destination.redacted` is what the API and the audit log see.
2. **The scheme is TLS.** `https` for a webhook. A notification carries
   finding titles and severities; sending that in clear text would be a
   finding of ours in someone else's report.
3. **The host is permitted.** A vendor kind may only reach its vendor hosts
   (`KIND_HOST_POLICY`); a generic webhook or SMTP host must appear in the
   operator allowlist from the environment. An organization admin therefore
   chooses among destinations an operator already sanctioned, and cannot
   invent one.

The IP-level checks are deliberately *not* here. They belong to the scope
engine, which sees the resolved address at send time and re-resolves DNS, so
a host that passes this policy and then resolves to loopback or to the cloud
metadata service is still refused. Doing it here as well would risk the
appearance of a check that a DNS rebind could walk past.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from app.core.integrations.contract import (
    KIND_HOST_POLICY,
    ChannelKind,
    Destination,
    IntegrationError,
    host_permitted,
)

WEBHOOK_KINDS = frozenset(
    {ChannelKind.SLACK_WEBHOOK, ChannelKind.MSTEAMS_WEBHOOK, ChannelKind.GENERIC_WEBHOOK}
)

#: Env-var names must look like env-var names. Without this a channel row
#: could name something that is not a variable at all and produce a confusing
#: failure much later; with it the refusal happens at configuration time.
_ENV_VAR_OK = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def valid_env_var_name(name: str) -> bool:
    return (
        bool(name)
        and len(name) <= 128
        and not name[0].isdigit()
        and all(char in _ENV_VAR_OK for char in name)
    )


def resolve_secret(
    env_var: str, environ: Mapping[str, str] | None = None, *, subject: str = "channel"
) -> str:
    """Read a referenced secret, or refuse.

    The error names the variable, never a value — an error string is the most
    common way a credential ends up in a log. `subject` only shapes the
    wording, so a code-host connection is not told it is a notification
    channel.
    """
    if not valid_env_var_name(env_var):
        raise IntegrationError(
            f"{env_var!r} is not a valid environment variable name; "
            f"a {subject} references its secret by variable name"
        )
    value = (environ if environ is not None else os.environ).get(env_var, "")
    if not value.strip():
        raise IntegrationError(
            f"environment variable {env_var} is not set in this process; "
            f"the {subject} cannot be used until the operator provides it"
        )
    return value.strip()


def redact_url(url: str) -> str:
    """A form of the URL that is safe to store, log and return by API.

    Keeps the scheme, host and a path *shape* (segment count) so an operator
    can tell two channels apart and spot an obviously wrong host, and drops
    every segment's contents because that is where the token lives.
    """
    parts = urlsplit(url)
    segments = [segment for segment in parts.path.split("/") if segment]
    shape = "".join("/…" for _ in segments)
    query = "?…" if parts.query else ""
    return f"{parts.scheme}://{parts.hostname or ''}{shape}{query}"


def _allowlist(kind: ChannelKind, operator_hosts: Sequence[str]) -> tuple[str, ...]:
    """Vendor hosts for the kind, plus whatever the operator added.

    The operator list is additive rather than a replacement: an operator who
    needs a Slack-compatible endpoint on their own host can add it without
    also having to re-state `hooks.slack.com`.
    """
    return tuple(KIND_HOST_POLICY.get(kind, ())) + tuple(operator_hosts)


def resolve_webhook_destination(
    kind: ChannelKind,
    endpoint_env_var: str,
    *,
    operator_hosts: Sequence[str] = (),
    environ: Mapping[str, str] | None = None,
) -> Destination:
    if kind not in WEBHOOK_KINDS:
        raise IntegrationError(f"{kind.value} is not a webhook channel")

    url = resolve_secret(endpoint_env_var, environ)
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise IntegrationError(
            f"channel endpoint in {endpoint_env_var} must be https; got {parts.scheme or 'no'} "
            "scheme. A notification carries finding titles and severities."
        )
    host = (parts.hostname or "").lower()
    if not host:
        raise IntegrationError(f"channel endpoint in {endpoint_env_var} has no host")

    permitted = _allowlist(kind, operator_hosts)
    if not host_permitted(host, permitted):
        raise IntegrationError(
            f"host {host!r} is not permitted for a {kind.value} channel. "
            "Permitted: "
            + (", ".join(permitted) if permitted else "none configured")
            + ". Add it to KERVY_NOTIFY_ALLOWED_WEBHOOK_HOSTS to sanction it."
        )
    return Destination(kind=kind, host=host, url=url, redacted=redact_url(url), port=parts.port)


def resolve_smtp_host(smtp_host: str, *, operator_hosts: Sequence[str] = ()) -> str:
    """Check an SMTP host against the operator allowlist.

    SMTP has no built-in vendor list: every deployment relays through its own
    server, so there is nothing safe to assume and the operator must say.
    """
    host = smtp_host.strip().lower().rstrip(".")
    if not host:
        raise IntegrationError("channel has no SMTP host")
    if not host_permitted(host, operator_hosts):
        raise IntegrationError(
            f"SMTP host {host!r} is not permitted. Add it to "
            "KERVY_NOTIFY_ALLOWED_SMTP_HOSTS to sanction it."
        )
    return host
