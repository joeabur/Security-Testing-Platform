"""CSRF protection (docs/BUILD_SPEC.md §18, §22).

§18 requires "CSRF protection where cookie-based sessions are used"; §22
repeats it for browser sessions. `docs/security-review.md` carried its absence
as a gap, and it is why the dashboard was built read-only.

Two mistakes make a CSRF control worthless, and they point in opposite
directions:

* **Too narrow** — skipping cookie-authenticated state changes leaves the
  attack completely open, because the browser attaches the session for the
  attacker.
* **Too wide** — demanding a token from Bearer-authenticated callers breaks
  every CLI invocation and CI gate, for callers who were never at risk. A
  cross-site page cannot attach an `Authorization` header to a request the
  browser sends by itself.

A third mistake is subtler and defeats the scheme entirely: **plain
double-submit**, where the token is any value present in both a cookie and a
header. Anything able to *write* a cookie for the site — a sibling subdomain,
a MITM on a plain-HTTP subdomain — supplies both halves and they match. The
token here is signed against the session it was issued for, so a planted pair
does not verify.

Each is asserted, and each was checked by breaking the control.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.config import get_settings
from app.core.csrf import anon as csrf_anon
from app.core.csrf.enforce import (
    ANONYMOUS_CSRF_PATHS,
    COOKIE_NAME,
    EXEMPT_PATHS,
    HEADER_NAME,
    SAFE_METHODS,
)
from app.core.csrf.tokens import issue, verify

# A signing key for the tests, not a credential: it authenticates nothing
# and exists only so `issue` and `verify` agree. `pragma` because
# detect-secrets reads any literal named like a secret as one.
SECRET = "test-csrf-secret"  # pragma: allowlist secret


# --------------------------------------------------------------------------
# The token itself.
# --------------------------------------------------------------------------


def test_a_token_verifies_only_for_the_session_it_was_issued_for() -> None:
    """The property that makes this more than plain double-submit.

    An attacker who can plant cookies still cannot produce a token that
    verifies against the *victim's* session, because the signature needs the
    server's secret.

    Verified by dropping the session value from the signature: the second
    assertion then passes and the scheme degrades to plain double-submit.
    """
    token = issue("session-alpha", secret=SECRET)
    assert verify(token, "session-alpha", secret=SECRET) is True
    assert verify(token, "session-beta", secret=SECRET) is False


def test_a_planted_cookie_pair_does_not_verify() -> None:
    """The subdomain-injection attack, at the token level.

    An attacker controlling `blog.example.com` can set a cookie for
    `.example.com` and send the same value in the header. Both halves match
    each other; neither matches the victim's session.
    """
    attacker_chosen = "attacker-picked-value.deadbeef"
    assert verify(attacker_chosen, "victims-session", secret=SECRET) is False


def test_a_token_signed_with_another_secret_does_not_verify() -> None:
    # Two deliberately different fake keys; the point is that they disagree.
    assert verify(issue("s", secret="one"), "s", secret="two") is False  # pragma: allowlist secret


@pytest.mark.parametrize(
    "token", [None, "", "no-separator", ".", "nonce.", ".signature", "nonce.wrong"]
)
def test_malformed_tokens_are_refused_rather_than_raising(token: str | None) -> None:
    """A caller that had to distinguish absent from malformed from invalid
    would be a caller with three chances to let one through."""
    assert verify(token, "session", secret=SECRET) is False


def test_each_issued_token_is_distinct() -> None:
    """A token seen once — in a referrer, a log, a screenshot — must not be
    the only token that will ever work."""
    tokens = {issue("session", secret=SECRET) for _ in range(20)}
    assert len(tokens) == 20


def test_the_token_is_not_the_session_token() -> None:
    """Reusing the session value would put a credential where a page's
    JavaScript must read it, turning any injection bug into session theft."""
    session = "a-real-session-jwt-value"
    token = issue(session, secret=SECRET)
    assert session not in token


# --------------------------------------------------------------------------
# Scope: where the check applies, and where it must not.
# --------------------------------------------------------------------------


def _anon_cookie_name() -> str:
    return csrf_anon.cookie_name(secure=get_settings().session_cookie_secure)


async def _register(client: AsyncClient, email: str, password: str) -> dict[str, str]:
    # Registration itself now needs the pre-session token (see the
    # login/register tests below); every other test in this file uses
    # registration only as a way to get a real session, so it goes through
    # the same front door a real client would.
    anon = await client.get("/api/v1/auth/csrf")
    anon_token = anon.cookies[_anon_cookie_name()]
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "C", "password": password},
        headers={HEADER_NAME: anon_token},
    )
    assert response.status_code == 201, response.text
    return {
        "bearer": response.json()["access_token"],
        "session": response.cookies[get_settings().session_cookie_name],
        "csrf": response.cookies[COOKIE_NAME],
    }


async def test_registering_issues_a_csrf_cookie_alongside_the_session(
    client: AsyncClient, strong_password: str
) -> None:
    """A session without a token would be a browser that can read but never act.

    Verified by removing the `set_cookie` call: `_register` raises KeyError.
    """
    creds = await _register(client, "csrf-issue@example.test", strong_password)
    assert creds["csrf"]
    assert verify(creds["csrf"], creds["session"], secret=get_settings().effective_csrf_secret)


async def test_a_cookie_authenticated_write_without_a_token_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    """The attack itself: the browser attaches the session, the attacker's page
    supplies the rest.

    Verified by disabling the middleware: this returns 201.
    """
    creds = await _register(client, "csrf-victim@example.test", strong_password)

    forged = await client.post(
        "/api/v1/organizations",
        json={"name": "Attacker Org"},
        cookies={get_settings().session_cookie_name: creds["session"]},
    )
    assert forged.status_code == 403
    assert "CSRF" in forged.text


async def test_the_same_write_succeeds_with_the_token(
    client: AsyncClient, strong_password: str
) -> None:
    """The control must not simply break the product."""
    creds = await _register(client, "csrf-ok@example.test", strong_password)

    allowed = await client.post(
        "/api/v1/organizations",
        json={"name": "Legitimate Org"},
        cookies={get_settings().session_cookie_name: creds["session"]},
        headers={HEADER_NAME: creds["csrf"]},
    )
    assert allowed.status_code == 201, allowed.text


async def test_a_token_from_another_session_is_refused(
    client: AsyncClient, strong_password: str
) -> None:
    """Swapping in a token minted elsewhere must not work.

    This is the end-to-end form of the signing property: an attacker who
    obtains *a* valid token (their own, from their own account) cannot use it
    against a victim's session.

    Verified by dropping the session binding: this returns 201.
    """
    victim = await _register(client, "csrf-swap-victim@example.test", strong_password)
    attacker = await _register(client, "csrf-swap-attacker@example.test", strong_password)

    response = await client.post(
        "/api/v1/organizations",
        json={"name": "Swapped"},
        cookies={get_settings().session_cookie_name: victim["session"]},
        headers={HEADER_NAME: attacker["csrf"]},
    )
    assert response.status_code == 403


async def test_a_bearer_authenticated_write_needs_no_token(
    client: AsyncClient, strong_password: str
) -> None:
    """The half that breaks the product if got wrong.

    Every CLI invocation and CI gate authenticates with a Bearer token, and
    none of them is forgeable from another site: a cross-origin page cannot
    make the browser attach an `Authorization` header. Demanding a token here
    would break them for no security gain.

    Verified by making `authenticated_by_cookie` always return True: this
    returns 403 and the CLI is broken.
    """
    creds = await _register(client, "csrf-bearer@example.test", strong_password)

    response = await client.post(
        "/api/v1/organizations",
        json={"name": "CLI Org"},
        headers={"Authorization": f"Bearer {creds['bearer']}"},
    )
    assert response.status_code == 201, response.text


async def test_a_bearer_token_wins_even_when_a_session_cookie_is_present(
    client: AsyncClient, strong_password: str
) -> None:
    """A browser that also holds a session must not force the API path to fail.

    An explicit `Authorization` header is a deliberate act by client code, so
    it decides. A request carrying both is a developer using curl in a browser
    profile, not an attack.
    """
    creds = await _register(client, "csrf-both@example.test", strong_password)

    response = await client.post(
        "/api/v1/organizations",
        json={"name": "Both Org"},
        cookies={get_settings().session_cookie_name: creds["session"]},
        headers={"Authorization": f"Bearer {creds['bearer']}"},
    )
    assert response.status_code == 201, response.text


async def test_reads_need_no_token(client: AsyncClient, strong_password: str) -> None:
    """Safe methods are exempt — and that assumption is enforced elsewhere.

    `tests/test_web.py::test_every_dashboard_route_is_a_get` and the
    authorization matrix are what keep "GET does not mutate" true. A GET that
    changed state would slip past this check, which is why those exist.
    """
    creds = await _register(client, "csrf-read@example.test", strong_password)
    jar = {get_settings().session_cookie_name: creds["session"]}

    for path in ("/api/v1/auth/me", "/app"):
        response = await client.get(path, cookies=jar)
        assert response.status_code in (200, 303), f"{path} -> {response.status_code}"


async def test_login_and_register_require_the_anonymous_token(
    client: AsyncClient, strong_password: str
) -> None:
    """Login CSRF is closed, not merely accepted.

    Login and register are no longer flatly exempt — `docs/csrf.md` used to
    record this as an open gap; `app/core/csrf/anon.py` is the fix. Verified
    end to end: without calling `GET /auth/csrf` first, both are refused.
    """
    assert "/api/v1/auth/login" not in EXEMPT_PATHS
    assert "/api/v1/auth/register" not in EXEMPT_PATHS
    assert "/api/v1/auth/login" in ANONYMOUS_CSRF_PATHS
    assert "/api/v1/auth/register" in ANONYMOUS_CSRF_PATHS

    unprotected_register = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "csrf-anon-missing@example.test",
            "full_name": "C",
            "password": strong_password,
        },
    )
    assert unprotected_register.status_code == 403
    assert "CSRF" in unprotected_register.text

    await _register(client, "csrf-anon-existing@example.test", strong_password)
    unprotected_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "csrf-anon-existing@example.test", "password": strong_password},
    )
    assert unprotected_login.status_code == 403


async def test_the_csrf_endpoint_issues_a_usable_anonymous_token(client: AsyncClient) -> None:
    """The happy path a login or registration page actually takes."""
    issued = await client.get("/api/v1/auth/csrf")
    assert issued.status_code == 204
    token = issued.cookies[_anon_cookie_name()]

    registered = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "csrf-anon-ok@example.test",
            "full_name": "C",
            "password": "correct-horse-battery-9",
        },
        cookies={_anon_cookie_name(): token},
        headers={HEADER_NAME: token},
    )
    assert registered.status_code == 201, registered.text


async def test_a_self_obtained_anonymous_token_does_not_help_without_the_cookie(
    client: AsyncClient,
) -> None:
    """The double-submit half: knowing a valid token is not enough.

    An attacker can call `GET /auth/csrf` themselves and get a genuinely
    valid token — the endpoint hands one to anybody who asks. What must still
    fail is using that token as the header/field *without also controlling
    the victim's cookie jar*, since a real cross-site request would not carry
    it.

    Verified by dropping the cookie-equality check from `anon.verify`: this
    then returns 201.
    """
    issued = await client.get("/api/v1/auth/csrf")
    token = issued.cookies[_anon_cookie_name()]
    # The client fixture persists cookies across requests, so the GET above
    # already left this one sitting in the jar — clear it to actually
    # simulate a request that never held it.
    client.cookies.delete(_anon_cookie_name())

    forged = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "csrf-anon-bare@example.test",
            "full_name": "C",
            "password": "correct-horse-battery-9",
        },
        headers={HEADER_NAME: token},
        # Deliberately no matching cookie in the jar.
    )
    assert forged.status_code == 403


async def test_a_planted_anonymous_cookie_pair_does_not_verify() -> None:
    """The naive-double-submit break, at the anonymous-token level.

    An attacker who can write *some* cookie for the site (not necessarily
    this one) still cannot pick an arbitrary matching cookie+header pair,
    because the cookie half must also carry this server's signature.
    """
    attacker_chosen = "attacker-picked-value.deadbeef"
    assert (
        csrf_anon.verify(
            cookie_value=attacker_chosen, provided_value=attacker_chosen, secret=SECRET
        )
        is False
    )


def test_anonymous_tokens_from_different_secrets_do_not_cross_verify() -> None:
    token = csrf_anon.issue(secret="one")  # pragma: allowlist secret
    assert csrf_anon.verify(cookie_value=token, provided_value=token, secret="two") is False


@pytest.mark.parametrize("cookie_value", [None, "", "no-separator", ".", "nonce.", ".sig"])
def test_malformed_anonymous_tokens_are_refused_rather_than_raising(
    cookie_value: str | None,
) -> None:
    assert (
        csrf_anon.verify(cookie_value=cookie_value, provided_value=cookie_value, secret=SECRET)
        is False
    )


def test_the_secure_anonymous_cookie_name_is_host_prefixed() -> None:
    """`__Host-` is what stops a sibling subdomain from overwriting it —
    browsers reject a `Set-Cookie` with that prefix unless it has no `Domain`
    attribute, which host-locks it to the exact origin that set it."""
    assert csrf_anon.cookie_name(secure=True) == "__Host-kervy_csrf_anon"
    assert csrf_anon.cookie_name(secure=False) == "kervy_csrf_anon"


def test_only_side_effect_free_methods_are_safe() -> None:
    """A POST slipping into the safe set would disable the control silently."""
    assert set(SAFE_METHODS) == {"GET", "HEAD", "OPTIONS", "TRACE"}
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert method not in SAFE_METHODS


def test_protection_is_on_by_default() -> None:
    """A control that ships off is a control nobody has."""
    assert get_settings().csrf_protection_enabled is True


async def test_logging_out_clears_the_csrf_cookie_too(
    client: AsyncClient, strong_password: str
) -> None:
    """A token outliving its session would be a token bound to nothing."""
    creds = await _register(client, "csrf-logout@example.test", strong_password)
    response = await client.post(
        "/api/v1/auth/logout",
        cookies={get_settings().session_cookie_name: creds["session"]},
        headers={"Authorization": f"Bearer {creds['bearer']}"},
    )
    assert response.status_code == 204
    assert COOKIE_NAME in response.headers.get("set-cookie", "") or any(
        COOKIE_NAME in value for value in response.headers.get_list("set-cookie")
    )
