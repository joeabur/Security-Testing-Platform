"""Deriving a bucket key from a request, without creating two new problems.

Both problems are ones rate limiters routinely introduce, so each gets its own
treatment here rather than being left to the call site.

## 1. A bucket key must not disclose who was trying

An identity bucket keyed on `login:alice@example.test` puts an email address in
Redis, in every `KEYS` dump, in every memory snapshot and in any log line that
ever prints a key. The address is the thing being attacked; it does not belong
in the mitigation's own storage.

So identity keys are an HMAC over the normalized address under a server-side
pepper. HMAC rather than a bare hash because the address space is small enough
to enumerate — an attacker who obtained the key store could otherwise recover
every address by hashing a wordlist. The pepper makes that useless without also
stealing the secret.

Normalizing first (lower-cased, trimmed) matters as much: without it,
`Alice@example.test` and `alice@example.test` are separate buckets and the
limit is one wordlist-capitalization away from being doubled.

## 2. A client must not be able to choose its own bucket

`X-Forwarded-For` is attacker-controlled. A limiter that reads it without
thinking gives every attacker unlimited buckets — one per forged header value —
which is worse than having no limiter, because the dashboard says the control
is on.

So the header is **ignored unless an operator states how many proxies sit in
front**, and even then only the hop that many places from the right is trusted.
Everything to the left of that was appended by something upstream of the
operator's own proxies, which is to say by the client.

`trusted_proxy_count = 0`, the default, means the socket address and nothing
else. An operator behind one load balancer sets 1.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress

#: Buckets are namespaced so a key cannot collide with the run kill switch or
#: anything else in the same Redis.
PREFIX = "kervy:rl"


def normalize_identity(value: str) -> str:
    """Case-fold and trim, so one identity is one bucket.

    Without this the limit is one capitalization away from being multiplied.
    """
    return value.strip().lower()


def identity_key(rule_name: str, identity: str, *, pepper: str) -> str:
    """A bucket key for an identity that does not contain the identity.

    HMAC, not a plain digest: email addresses are enumerable, so an unkeyed
    hash of one is reversible with a wordlist by anyone who reads the store.
    """
    digest = hmac.new(
        pepper.encode("utf-8"),
        normalize_identity(identity).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    # Half the digest: 128 bits is far beyond collision concern for this, and
    # a shorter key keeps Redis memory down under a spraying attack, which is
    # exactly when the key count explodes.
    return f"{PREFIX}:{rule_name}:id:{digest[:32]}"


def ip_key(rule_name: str, client_ip: str) -> str:
    return f"{PREFIX}:{rule_name}:ip:{client_ip}"


def client_ip(
    *,
    socket_ip: str | None,
    forwarded_for: str | None,
    trusted_proxy_count: int,
) -> str:
    """The client address, trusting only as many proxy hops as configured.

    Returns `"unknown"` when there is no socket address at all (an ASGI
    transport with no client, as in some test harnesses). That is a single
    shared bucket rather than no bucket: an unattributable request should be
    limited more aggressively, not exempted.

    Verified against the obvious attack in
    `tests/security/test_rate_limit.py::test_a_forged_forwarded_header_cannot_mint_new_buckets`.
    """
    socket_address = (socket_ip or "").strip() or "unknown"

    if trusted_proxy_count < 1 or not forwarded_for:
        # The default, and the safe one: believe the socket.
        return socket_address

    # `X-Forwarded-For: client, proxy1, proxy2`. Each proxy appends the address
    # it saw. With N trusted proxies, the Nth entry from the right is the
    # address the outermost trusted proxy saw; everything left of it was
    # appended by something the operator does not control.
    hops = [part.strip() for part in forwarded_for.split(",") if part.strip()]
    if len(hops) < trusted_proxy_count:
        # Fewer hops than proxies means the header did not come through the
        # expected chain. Believe the socket rather than guess.
        return socket_address

    candidate = hops[-trusted_proxy_count]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        # Not an address. A limiter that accepted arbitrary text here would let
        # a client mint a bucket per random string.
        return socket_address
    return candidate
