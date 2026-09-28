"""What a domain/DNS assessment is, and what it discovers.

Mirrors `app/core/dast/contract.py`'s shape: the engine both tests a known
seed (the root domain) and discovers more of its own (subdomains found via
certificate-transparency logs and a DNS wordlist). The same discipline DAST's
docstring describes applies here — a discovered hostname is recorded, never
silently handed the same depth of testing as the seed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class SubdomainSource(StrEnum):
    SEED = "seed"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    DNS_BRUTE_FORCE = "dns_brute_force"


@dataclass(frozen=True)
class DiscoveredSubdomain:
    hostname: str
    source: SubdomainSource
    resolved_ips: tuple[str, ...] = ()
    #: Whether this hostname is the root domain or matched
    #: `DomainTarget.allowed_subdomain_patterns`, and therefore received the
    #: HTTP/TLS checks — vs. recorded as discovered but not probed further.
    probed: bool = False


@dataclass(frozen=True)
class DomainTarget:
    """The input to the domain engine.

    `allowed_subdomain_patterns` is carried explicitly, resolved once from
    `RulesOfEngagementRecord.asset_scope` by `resolve_domain_scope`, the same
    way `DastTarget.allow_state_mutation` is resolved once and handed to
    every adapter rather than re-read from the RoE inside each one.
    """

    root_domain: str
    allowed_subdomain_patterns: tuple[str, ...] = field(default_factory=tuple)
