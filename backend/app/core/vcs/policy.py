"""Turning a stored code-host connection into an endpoint we may reach.

Identical discipline to `app/core/integrations/policy.py`, because the risk is
identical: a row in the database that produces an outbound HTTP request.

* **The token comes from the environment**, named by the connection row. A
  GitHub token grants read (and, for a check run, write) access to a customer's
  source; §5's rule that credentials never live in the database is at its most
  load-bearing here.
* **The scheme is https.** Always, with no development exception — a flag that
  allowed http would be a flag that leaks the token.
* **The host is pinned or sanctioned.** `github.com` connections may reach
  `api.github.com` and nothing else, decided in code rather than by the row. A
  GitHub Enterprise host is site-specific, so it must appear in an operator
  allowlist held in the environment (`KERVY_VCS_ALLOWED_HOSTS`) — an
  organization admin picks among hosts an operator sanctioned, and cannot
  invent one.

The IP-level checks are not here. They belong to the scope engine, which
re-resolves DNS at send time, so a host that passes this policy and then
resolves to loopback or the metadata service is still refused.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from app.core.integrations.contract import IntegrationError, host_permitted
from app.core.integrations.policy import resolve_secret, valid_env_var_name
from app.core.vcs.contract import GITHUB_API_HOST, Destination, VcsError, VcsProvider

__all__ = [
    "resolve_destination",
    "resolve_enterprise_host",
    "valid_env_var_name",
]


def resolve_enterprise_host(raw: str, *, operator_hosts: Sequence[str] = ()) -> str:
    host = raw.strip().lower().rstrip("/").rstrip(".")
    if "://" in host:
        host = urlsplit(host).hostname or ""
    if not host:
        raise VcsError("a GitHub Enterprise connection needs an api_host")
    if not host_permitted(host, operator_hosts):
        raise VcsError(
            f"host {host!r} is not permitted for a code-host connection. "
            "Add it to KERVY_VCS_ALLOWED_HOSTS to sanction it."
        )
    return host


def resolve_destination(
    provider: VcsProvider,
    token_env_var: str,
    *,
    api_host: str | None = None,
    operator_hosts: Sequence[str] = (),
    environ: Mapping[str, str] | None = None,
) -> Destination:
    """Resolve a connection to a checked endpoint, reading the token now."""
    if provider is VcsProvider.GITHUB:
        if api_host and api_host.strip().lower() not in {GITHUB_API_HOST, "github.com"}:
            raise VcsError(
                f"a {provider.value} connection always reaches {GITHUB_API_HOST}; "
                f"use {VcsProvider.GITHUB_ENTERPRISE.value} for {api_host!r}"
            )
        host = GITHUB_API_HOST
        api_base = f"https://{GITHUB_API_HOST}"
    else:
        host = resolve_enterprise_host(api_host or "", operator_hosts=operator_hosts)
        # GitHub Enterprise Server serves its API under /api/v3, which is the
        # one structural difference from github.com worth encoding here.
        api_base = f"https://{host}/api/v3"

    try:
        token = resolve_secret(token_env_var, environ, subject="code host connection")
    except IntegrationError as exc:
        # Re-raised as a `VcsError` rather than allowed to escape: every caller
        # here catches `VcsError` and records a refusal, so leaking the
        # notification layer's exception type turned a misconfigured connection
        # into an unhandled 500 instead of a message naming the variable.
        raise VcsError(str(exc)) from exc
    return Destination(provider=provider, host=host, api_base=api_base, token=token)
