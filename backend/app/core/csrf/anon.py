"""A pre-session CSRF token for `/auth/login` and `/auth/register`.

`app/core/csrf/tokens.py` binds a token to the session cookie's value, which
is exactly what is missing before login: there is no session yet, so nothing
exists to bind to. `docs/csrf.md` recorded this as "login CSRF is open" and
named the fix as a deferral. This module is that fix.

## What actually defeats a sibling-subdomain attacker here

A token that is merely self-signed (an HMAC over a nonce, with no per-visitor
binding) is not enough on its own: the server would issue the *same kind* of
valid token to anyone who asks, including the attacker, who could then plant
that self-obtained, genuinely-valid token as both the cookie and the
accompanying header/field in a forged cross-site request. Self-signing only
proves the token came from this server at some point — it says nothing about
whose browser it was issued to.

The property this needs is that **the value the victim's browser echoes back
must be the exact value planted in the victim's own cookie jar**, and an
attacker must not be able to control that cookie. Signing does defend against
the classic naive-double-submit break (attacker picks an arbitrary matching
cookie+header pair with no help from the server), but a subdomain that can
set cookies for the whole registrable domain can still overwrite this cookie
with a token it legitimately obtained by calling `GET /auth/csrf` itself.

That is what `COOKIE_NAME` being `__Host-`-prefixed is for: browsers refuse to
honour a `Set-Cookie` for a `__Host-`-prefixed name unless it has no `Domain`
attribute, `Path=/`, and `Secure` — which makes it host-locked to the exact
origin that set it. A sibling subdomain cannot set it at all, `__Host-` or
not, because setting *without* `Domain` scopes a cookie to the setting host
only. That closes the gap signing alone cannot.

## The cost, stated rather than hidden

`__Host-` mandates `Secure`, so it only works over HTTPS. `KERVY_SESSION_COOKIE_SECURE`
already exists as this platform's one on/off switch for "are we serving HTTPS
today", so this module reuses it: secure deployments get the `__Host-` cookie
and the real protection above; plain-HTTP deployments (local dev, by default)
get an unprefixed cookie of the same shape, which still blocks the naive
double-submit break via signing but **not** the sibling-subdomain one — the
same residual `docs/csrf.md` already named, just narrowed from "no
protection" to "no protection against a subdomain attacker specifically, in
plain-HTTP deployments only". A deployment that sets
`KERVY_SESSION_COOKIE_SECURE=true` (as any deployment reachable over the
public internet should) gets the full guarantee.
"""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256

_NONCE_BYTES = 16
_SEPARATOR = "."

#: `__Host-` cookies are host-locked by browsers (no `Domain` attribute
#: allowed) — the mechanism that stops a sibling subdomain from overwriting
#: it. Only usable when the cookie is also `Secure`, hence the two names.
COOKIE_NAME_SECURE = "__Host-kervy_csrf_anon"
COOKIE_NAME_INSECURE = "kervy_csrf_anon"


def cookie_name(*, secure: bool) -> str:
    return COOKIE_NAME_SECURE if secure else COOKIE_NAME_INSECURE


def _signature(nonce: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), nonce.encode("utf-8"), sha256).hexdigest()


def issue(*, secret: str) -> str:
    """A fresh, self-signed anonymous token. Not bound to any session."""
    nonce = secrets.token_urlsafe(_NONCE_BYTES)
    return f"{nonce}{_SEPARATOR}{_signature(nonce, secret)}"


def _is_validly_signed(token: str, secret: str) -> bool:
    nonce, separator, provided = token.partition(_SEPARATOR)
    if not separator or not nonce or not provided:
        return False
    return hmac.compare_digest(provided, _signature(nonce, secret))


def verify(*, cookie_value: str | None, provided_value: str | None, secret: str) -> bool:
    """Whether `provided_value` is this request's genuine anonymous token.

    Two things must both hold: the header/field echoes exactly what this
    browser's cookie jar holds (the double-submit half — an attacker who
    cannot read or overwrite that cookie cannot supply a matching value), and
    that cookie value is one this server actually signed (the half that
    blocks an attacker who *can* write cookies from picking an arbitrary
    matching pair).
    """
    if not cookie_value or not provided_value:
        return False
    if not hmac.compare_digest(cookie_value, provided_value):
        return False
    return _is_validly_signed(cookie_value, secret)
