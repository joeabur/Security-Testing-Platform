"""Authentication rate limiting (docs/BUILD_SPEC.md §18, §22).

§18 requires login rate limiting and §22 per-route rate limiting.
`docs/security-review.md` carried its absence as the oldest open gap, and named
it the one most likely to matter first in a real deployment.

A rate limiter is unusually easy to ship in a state that looks enabled and
protects nothing, so most of this file is about the ways that happens:

* a client that can **choose its own bucket** via `X-Forwarded-For` has no
  limit at all;
* a limiter keyed on an **unpeppered hash of an email** puts a reversible
  identifier in the counter store;
* a 429 that **differs between a real and a fake account** is an enumeration
  oracle bolted onto the login endpoint;
* counting **successes** as well as failures throttles legitimate users, which
  is how the control gets switched off in production;
* a **lockout** rather than a throttle is a denial-of-service primitive aimed
  at any user whose address an attacker knows.

Each is asserted, and each was checked by breaking the control it covers.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import HEADER_NAME
from app.core.ratelimit.contract import Decision, Dimension, Rule, StoreUnavailable
from app.core.ratelimit.keys import PREFIX, client_ip, identity_key, normalize_identity
from app.core.ratelimit.policy import POLICY, RateLimiter
from app.core.ratelimit.stores import MemoryStore


async def _anon_headers(client: AsyncClient) -> dict[str, str]:
    """The pre-session token `/auth/login` and `/auth/register` now require.

    One fetch per test is enough: the token cookie stays in the client's jar
    for every subsequent request, so the same header value keeps verifying.
    """
    anon = await client.get("/api/v1/auth/csrf")
    token = anon.cookies[csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)]
    return {HEADER_NAME: token}


# --------------------------------------------------------------------------
# Bucket keys: the client must not choose its own.
# --------------------------------------------------------------------------


def test_a_forged_forwarded_header_cannot_mint_new_buckets() -> None:
    """The failure that makes a limiter worse than none.

    `X-Forwarded-For` is attacker-controlled. Reading it without a configured
    proxy in front gives an attacker one fresh bucket per forged value —
    unlimited attempts — while the dashboard still says rate limiting is on.

    Verified by defaulting `trusted_proxy_count` to 1: the forged value is then
    used and this fails.
    """
    for forged in ("1.2.3.4", "9.9.9.9, 8.8.8.8", "not-an-address"):
        assert (
            client_ip(socket_ip="203.0.113.7", forwarded_for=forged, trusted_proxy_count=0)
            == "203.0.113.7"
        )


def test_one_trusted_proxy_means_the_last_hop_is_believed() -> None:
    """An operator who states their topology gets the real client address.

    With one proxy, the rightmost entry is what that proxy saw. Anything
    further left was appended by something upstream of it — which is to say by
    the client.
    """
    assert (
        client_ip(
            socket_ip="10.0.0.1",
            forwarded_for="198.51.100.9, 203.0.113.7",
            trusted_proxy_count=1,
        )
        == "203.0.113.7"
    )
    # Two proxies: one further left.
    assert (
        client_ip(
            socket_ip="10.0.0.1",
            forwarded_for="198.51.100.9, 203.0.113.7, 10.0.0.2",
            trusted_proxy_count=2,
        )
        == "203.0.113.7"
    )


@pytest.mark.parametrize(
    "forwarded",
    ["", "   ", "garbage", "1.2.3.4.5", "<script>alert(1)</script>", "::not::an::ip::"],
)
def test_a_malformed_forwarded_value_falls_back_to_the_socket(forwarded: str) -> None:
    """Accepting arbitrary text would be a bucket per random string."""
    assert (
        client_ip(socket_ip="203.0.113.7", forwarded_for=forwarded, trusted_proxy_count=1)
        == "203.0.113.7"
    )


def test_fewer_hops_than_proxies_is_not_trusted() -> None:
    """A header that did not come through the expected chain is not evidence."""
    assert (
        client_ip(socket_ip="203.0.113.7", forwarded_for="1.2.3.4", trusted_proxy_count=3)
        == "203.0.113.7"
    )


def test_a_request_with_no_client_shares_one_bucket_rather_than_escaping() -> None:
    """Unattributable requests are limited more, not exempted."""
    assert client_ip(socket_ip=None, forwarded_for=None, trusted_proxy_count=0) == "unknown"


# --------------------------------------------------------------------------
# Identity keys: the store must not hold the thing being attacked.
# --------------------------------------------------------------------------


def test_an_identity_key_does_not_contain_the_identity() -> None:
    """The address under attack does not belong in the mitigation's storage.

    Verified by keying on the raw address: the assertion below fails.
    """
    key = identity_key("login", "Alice@Example.TEST", pepper="pepper")
    assert "alice" not in key.lower()
    assert "example" not in key.lower()
    assert key.startswith(f"{PREFIX}:login:id:")


def test_identity_keys_are_peppered_so_the_store_is_not_reversible() -> None:
    """An unkeyed hash of an email is reversible with a wordlist.

    Anyone who could read the counter store could otherwise recover every
    address that had attempted a login. The pepper makes that useless without
    also stealing a server-side secret.

    Verified by replacing the HMAC with `sha256(email)`: both keys become equal.
    """
    one = identity_key("login", "alice@example.test", pepper="pepper-one")
    two = identity_key("login", "alice@example.test", pepper="pepper-two")
    assert one != two


def test_case_and_whitespace_do_not_multiply_the_budget() -> None:
    """One identity is one bucket.

    Without normalization the limit is one wordlist-capitalization away from
    being doubled, then quadrupled.
    """
    assert normalize_identity("  Alice@Example.TEST ") == "alice@example.test"
    variants = {
        identity_key("login", value, pepper="p")
        for value in ("alice@example.test", "Alice@Example.TEST", "  ALICE@example.test  ")
    }
    assert len(variants) == 1


# --------------------------------------------------------------------------
# The policy itself.
# --------------------------------------------------------------------------


def test_login_is_limited_on_both_dimensions() -> None:
    """Either dimension alone is bypassable.

    Per-IP alone falls to a botnet; per-identity alone falls to spraying one
    password across many accounts. The policy must carry both.

    Verified by deleting the identity rule: this fails.
    """
    dimensions = {rule.dimension for rule in POLICY["login"]}
    assert dimensions == {Dimension.IP, Dimension.IDENTITY}


def test_registration_is_bounded_per_ip() -> None:
    """Unauthenticated and row-creating: without a bound it is a write primitive."""
    assert POLICY["register"]
    assert all(rule.dimension is Dimension.IP for rule in POLICY["register"])


def test_a_rule_that_would_block_everything_is_rejected() -> None:
    """A zero limit is a misconfiguration, not a very strict policy."""
    with pytest.raises(ValueError, match="blocks everything"):
        Rule(name="x", dimension=Dimension.IP, limit=0, window_seconds=60)
    with pytest.raises(ValueError, match="below one second"):
        Rule(name="x", dimension=Dimension.IP, limit=5, window_seconds=0)


async def test_the_budget_is_consumed_and_then_refused() -> None:
    limiter = RateLimiter(MemoryStore(), pepper="p")
    rule = next(r for r in POLICY["login"] if r.dimension is Dimension.IDENTITY)

    for _ in range(rule.limit):
        decision = await limiter.check("login", client_ip="203.0.113.1", identity="a@b.test")
        assert decision.allowed

    refused = await limiter.check("login", client_ip="203.0.113.1", identity="a@b.test")
    assert refused.allowed is False
    assert refused.retry_after_seconds > 0
    assert "identity" in refused.rule_name


async def test_a_success_clears_the_counters() -> None:
    """Only failures should accumulate.

    Counting successes would mean a busy legitimate user throttles themselves,
    which is how a rate limit gets switched off in production.

    Verified by making `clear` a no-op: the loop below refuses.
    """
    limiter = RateLimiter(MemoryStore(), pepper="p")
    for _ in range(40):
        decision = await limiter.check("login", client_ip="203.0.113.1", identity="a@b.test")
        assert decision.allowed, "a repeatedly successful login must never throttle"
        await limiter.clear("login", client_ip="203.0.113.1", identity="a@b.test")


async def test_one_identity_being_throttled_does_not_throttle_another() -> None:
    """Buckets are per identity, or the limiter is a lockout for everybody."""
    limiter = RateLimiter(MemoryStore(), pepper="p")
    for _ in range(40):
        await limiter.check("login", client_ip="203.0.113.1", identity="victim@b.test")

    other = await limiter.check("login", client_ip="203.0.113.9", identity="other@b.test")
    assert other.allowed


async def test_the_window_expires_so_a_throttle_is_never_a_lockout() -> None:
    """A throttle that never ends is an account lockout by another name.

    Lockout triggered by failed attempts is a denial-of-service primitive: an
    attacker who knows a colleague's address can keep them out indefinitely.
    This asserts the counter is bounded by a TTL rather than latched.

    Driven through the store directly rather than by sleeping fifteen minutes.
    """
    store = MemoryStore()
    key = "kervy:rl:login:id:deadbeef"
    assert await store.incr(key, 1) == 1
    assert await store.ttl(key) <= 1

    # Force the window past its expiry without waiting for it.
    store._counts[key] = (999, store._now() - 0.01)  # noqa: SLF001
    assert await store.incr(key, 60) == 1, "an expired window must start over"
    assert await store.ttl(key) > 0


# --------------------------------------------------------------------------
# Degradation: the one boundary on this platform that fails open.
# --------------------------------------------------------------------------


class _BrokenStore:
    async def incr(self, key: str, window_seconds: int) -> int:
        raise StoreUnavailable("redis is down")

    async def ttl(self, key: str) -> int:
        raise StoreUnavailable("redis is down")

    async def reset(self, key: str) -> None:
        raise StoreUnavailable("redis is down")


async def test_an_unavailable_store_allows_the_request_and_says_so() -> None:
    """Deliberately fail-open, and deliberately loud.

    Every other boundary here fails closed. This one does not, because a rate
    limiter sits on top of authentication rather than being it: Argon2id still
    stands behind it, and failing closed would turn a Redis blip into a total
    lockout of the product.

    What must never happen is failing open *silently*. The decision carries
    `degraded`, which the caller logs — an operator whose rate limiting stopped
    counting has a control that exists only on paper.

    Verified by making `degraded` default to False and dropping it from the
    degraded path: the second assertion fails.
    """
    limiter = RateLimiter(_BrokenStore(), pepper="p")
    decision = await limiter.check("login", client_ip="203.0.113.1", identity="a@b.test")
    assert decision.allowed is True
    assert decision.degraded is True
    assert decision.enforced is False


async def test_a_failed_reset_does_not_break_a_successful_login() -> None:
    limiter = RateLimiter(_BrokenStore(), pepper="p")
    await limiter.clear("login", client_ip="203.0.113.1", identity="a@b.test")


def test_a_normal_decision_is_not_marked_degraded() -> None:
    """The flag has to mean something, so the happy path must not set it."""
    assert Decision(allowed=True, rule_name="login").enforced is True


# --------------------------------------------------------------------------
# End to end, through the real endpoints.
# --------------------------------------------------------------------------


async def test_repeated_bad_passwords_are_eventually_refused_with_retry_after(
    client: AsyncClient, strong_password: str
) -> None:
    """The point of the whole exercise.

    Verified by setting `rate_limit_enabled` to False: every attempt returns
    401 and this fails.
    """
    headers = await _anon_headers(client)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "rl-victim@example.test", "full_name": "V", "password": strong_password},
        headers=headers,
    )

    saw_429 = False
    for _ in range(30):
        response = await client.post(
            "/api/v1/auth/login",
            # pragma: allowlist nextline secret
            json={"email": "rl-victim@example.test", "password": "wrong-password-entirely"},
            headers=headers,
        )
        if response.status_code == 429:
            saw_429 = True
            assert int(response.headers["Retry-After"]) > 0
            break
        assert response.status_code == 401

    assert saw_429, "unlimited password guessing was permitted"


async def test_a_throttled_response_cannot_tell_you_whether_the_account_exists(
    client: AsyncClient, strong_password: str
) -> None:
    """The limiter must not become the enumeration oracle.

    Budget is consumed before the user lookup and identically for every
    address, so the 429 for a real account and for one that was never
    registered are indistinguishable — same status, same body, same headers
    apart from the timing-dependent `Retry-After`.

    Verified by moving `enforce` after the lookup and skipping it when the user
    is absent: the two responses then differ.
    """
    headers = await _anon_headers(client)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "rl-real@example.test", "full_name": "R", "password": strong_password},
        headers=headers,
    )

    async def throttle(email: str) -> tuple[int, dict[str, object], set[str]]:
        last: tuple[int, dict[str, object], set[str]] = (0, {}, set())
        for _ in range(30):
            response = await client.post(
                "/api/v1/auth/login",
                # A password that is deliberately wrong — the point of the test
                # is that it is rejected. `pragma` because detect-secrets reads
                # any literal after a "password" key as a credential.
                json={"email": email, "password": "nope-nope-nope"},  # pragma: allowlist secret
                headers=headers,
            )
            error = response.json().get("error", {})
            # `request_id` is unique per request by design, so it is dropped
            # before comparing. Everything a caller could learn *about the
            # account* from the response is what must match.
            last = (
                response.status_code,
                {k: v for k, v in error.items() if k != "request_id"},
                set(response.headers) - {"x-request-id", "date", "content-length"},
            )
            if response.status_code == 429:
                break
        return last

    real = await throttle("rl-real@example.test")
    fake = await throttle("rl-never-registered@example.test")

    assert real[0] == fake[0] == 429
    assert real[1] == fake[1], "the throttled body differs between a real and a fake account"
    assert real[2] == fake[2], "the throttled headers differ between a real and a fake account"


async def test_a_successful_login_after_failures_is_not_throttled(
    client: AsyncClient, strong_password: str
) -> None:
    """Someone who mistypes a few times then gets it right must not be stopped."""
    headers = await _anon_headers(client)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "rl-typo@example.test", "full_name": "T", "password": strong_password},
        headers=headers,
    )
    for _ in range(5):
        await client.post(
            "/api/v1/auth/login",
            # pragma: allowlist nextline secret
            json={"email": "rl-typo@example.test", "password": "mistyped"},
            headers=headers,
        )

    good = await client.post(
        "/api/v1/auth/login",
        json={"email": "rl-typo@example.test", "password": strong_password},
        headers=headers,
    )
    assert good.status_code == 200

    # And the counter is clear, so the next few mistakes do not land them at
    # the limit immediately.
    again = await client.post(
        "/api/v1/auth/login",
        # pragma: allowlist nextline secret
        json={"email": "rl-typo@example.test", "password": "mistyped"},
        headers=headers,
    )
    assert again.status_code == 401


async def test_registration_is_bounded_from_one_address(
    client: AsyncClient, strong_password: str
) -> None:
    rule = POLICY["register"][0]
    headers = await _anon_headers(client)
    statuses = []
    for index in range(rule.limit + 3):
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": f"rl-reg-{index}@example.test",
                "full_name": "R",
                "password": strong_password,
            },
            headers=headers,
        )
        statuses.append(response.status_code)
    assert 429 in statuses, "unlimited account creation was permitted from one address"


async def test_the_limiter_is_on_by_default(client: AsyncClient) -> None:
    """A control that ships off is a control nobody has.

    Verified by defaulting `rate_limit_enabled` to False.
    """
    assert get_settings().rate_limit_enabled is True


async def test_forging_a_forwarded_header_does_not_escape_the_registration_limit(
    _fresh_rate_limit_store: MemoryStore, strong_password: str
) -> None:
    """The header attack, end to end against a real app.

    A fresh app rather than the shared `client` fixture, because this asserts
    behaviour about the default configuration rather than about a request.
    """
    from app.db.session import get_db
    from app.main import create_app
    from tests.conftest import TestSessionLocal

    app = create_app()

    async def _override_get_db():  # type: ignore[no-untyped-def]
        async with TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        anon_headers = await _anon_headers(ac)
        statuses = []
        for index in range(POLICY["register"][0].limit + 3):
            response = await ac.post(
                "/api/v1/auth/register",
                json={
                    "email": f"rl-forge-{index}@example.test",
                    "full_name": "F",
                    "password": strong_password,
                },
                # A different forged address every time. With the default
                # `trusted_proxy_count=0` these must all share one bucket.
                headers={"X-Forwarded-For": f"198.51.100.{index}", **anon_headers},
            )
            statuses.append(response.status_code)
    assert 429 in statuses, (
        "a forged X-Forwarded-For minted a fresh bucket per request; the limiter "
        "is enabled but enforcing nothing."
    )
