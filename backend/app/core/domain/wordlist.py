"""A conservative, built-in wordlist for DNS brute-force subdomain discovery.

Intentionally small and static rather than operator-supplied: an
RoE-declared wordlist is a later increment. This list only needs to prove
the discovery -> `DiscoveredAsset` pipeline end to end, not be exhaustive.
"""

COMMON_SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    "www",
    "mail",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "app",
    "vpn",
    "ftp",
    "git",
    "ci",
    "docs",
    "blog",
    "beta",
    "internal",
    "db",
    "cdn",
    "static",
    "assets",
    "shop",
    "support",
    "status",
)
