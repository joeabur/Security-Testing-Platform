"""DNS brute-force subdomain discovery against the built-in wordlist.

Uses the same `DnsResolver` protocol every scope check already resolves
through — never a second resolver implementation — so a brute-forced
hostname is subject to the identical DNS-rebinding-safe, no-caching
behaviour as any other lookup in this platform.
"""

from __future__ import annotations

from app.core.domain.wordlist import COMMON_SUBDOMAIN_PREFIXES
from app.core.scope.dns import DnsResolver


async def brute_force_subdomains(
    resolver: DnsResolver, root_domain: str
) -> dict[str, tuple[str, ...]]:
    """hostname -> resolved IPs, for every wordlist candidate that resolves.

    A candidate that fails to resolve simply does not exist under this root
    domain — that is the expected outcome for most of the wordlist, not an
    error worth surfacing.
    """
    found: dict[str, tuple[str, ...]] = {}
    for prefix in COMMON_SUBDOMAIN_PREFIXES:
        hostname = f"{prefix}.{root_domain}"
        try:
            ips = await resolver.resolve(hostname)
        except Exception:  # noqa: BLE001 - most candidates simply don't exist
            continue
        if ips:
            found[hostname] = tuple(str(ip) for ip in ips)
    return found
