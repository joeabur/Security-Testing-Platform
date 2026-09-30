# CSRF protection

Cookie-authenticated, state-changing requests must carry a CSRF token
(`docs/BUILD_SPEC.md` §18, §22).

## Where the check applies

| Request | Token required? | Why |
|---|---|---|
| `POST` with a session cookie | **yes** | The browser attaches the session for whoever asks; this is the attack |
| `POST` with `Authorization: Bearer` | no | A cross-site page cannot attach that header |
| `GET`, `HEAD`, `OPTIONS` | no | Required to be side-effect-free |
| `POST /auth/login`, `/auth/register`, `/auth/login/2fa` | **yes** — a pre-session, anonymous token | No ordinary session exists yet to bind a token to; see "Login CSRF is closed" below |
| `POST /auth/logout` | no | Forcing a logout is an annoyance, not a compromise — and a stale page must still be able to do it |
| `POST /auth/forgot-password`, `/auth/reset-password` | no | Neither reads a session cookie; each takes its entire authority from its own body, so there is no victim session to ride |

Getting the *scope* wrong ruins it in either direction. Too narrow and the
attack is wide open. Too wide — demanding a token from Bearer callers — breaks
every CLI invocation and CI gate, for callers who were never at risk.
`tests/security/test_csrf.py` asserts both halves, because a control that is
merely present is not one applied where it matters.

## The token is bound to the session

Textbook double-submit sets a random value in a cookie and requires the same
value in a header. It rests on an attacker being unable to **read** the cookie
— which same-origin policy gives you — but **not** on an attacker being unable
to **write** one. Anything that can set a cookie for the site supplies both
halves and they trivially match:

- a sibling subdomain setting a cookie for the parent domain, which is a
  cookie-scoping quirk rather than an XSS;
- a MITM on a plain-HTTP subdomain, since cookies ignore ports and are only
  origin-bound by the `Secure` flag.

So the token here carries an **HMAC over the session cookie's own value**:

```
token = <nonce>.<HMAC(secret, nonce + session_value)>
```

An attacker who plants cookies cannot produce a token that verifies against
*the victim's* session, because the HMAC needs the server's secret. A token
minted for a different session fails the same way — asserted end to end by
taking a valid token from one account and using it against another.

It is deliberately **not** the session token reused. That would put a
credential somewhere a page's JavaScript must read it, turning any
content-injection bug into session theft. This token is derived,
single-purpose, and useless for authentication.

## Using it

Both cookies are set together at login and registration, so a session can never
exist without a token:

```
Set-Cookie: kervy_session=...; HttpOnly; SameSite=Lax
Set-Cookie: kervy_csrf=<nonce>.<signature>; SameSite=Lax
```

`kervy_csrf` is deliberately **not** `HttpOnly` — the page has to read it to
echo it back. That is safe precisely because the token authenticates nothing on
its own.

```js
fetch("/api/v1/organizations", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": readCookie("kervy_csrf"),
  },
  body: JSON.stringify({ name: "Acme" }),
});
```

Server-rendered forms cannot set a header, so a `csrf_token` form field is
accepted too.

A missing or invalid token is **403** with a message naming the header. No
attacker learns anything from it, and a developer who has got it wrong learns
exactly what to send.

## Enforced as middleware, not a decorator

A per-route dependency protects the routes somebody remembered to decorate, and
the one they forget is the one that matters. The check runs as middleware over
every route, narrowing by the *request* — unsafe method, cookie-authenticated,
not exempt — rather than by a list that has to be maintained.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KERVY_CSRF_ENABLED` | `true` | Off only when an operator says so |
| `KERVY_CSRF_SECRET` | `JWT_SECRET` | Signing key for tokens |

## What this does not cover

Stated rather than implied:

- **The constant-time comparison is not covered by a test.** Replacing
  `hmac.compare_digest` with `==` leaves the whole suite green, because a
  timing property is not observable from a functional assertion. The code is
  correct; the passing suite is not evidence of it.
- **`SameSite=Lax` still does most of the work in practice** for top-level
  navigations. This is defence in depth, not a replacement for it.
- **The dashboard has no write actions.** It is read-only because none are
  built, not because of CSRF any more. That reason was removed from the
  disabled controls when it stopped being true.

## Regression found and fixed: the browser client never sent the header

When middleware enforcement shipped, `frontend/lib/api-client.ts`'s
`clientApiFetch` (the fetch helper every Client Component uses) was never
updated to read the `kervy_csrf` cookie and echo it back as `X-CSRF-Token`.
Every cookie-authenticated write from the browser — starting with
`POST /organizations` from the "Create Organization" form — has been
silently returning 403 since that middleware landed. No test caught it
because the existing form-level tests mock `clientApiFetch` outright and
never exercise its real header logic.

Fixed by teaching `clientApiFetch` to read `document.cookie` for
`kervy_csrf` and set the header on any non-safe method that doesn't already
carry one, matching `SAFE_METHODS` in `app/core/csrf/enforce.py` exactly.
`frontend/lib/api-server.ts` (the Server Component / Route Handler fetch
helper) got the same treatment pre-emptively, even though its only two
current callers are GETs, so the same gap can't reopen the moment a
server-side mutation is added.

Covered by `frontend/lib/__tests__/api-client.test.ts`, which exercises the
real `clientApiFetch` (not a mock) against a stubbed `fetch` and a seeded
`document.cookie`: it asserts the header is attached for unsafe methods with
a cookie present, omitted for safe methods and for the pre-session case, and
never overridden when a caller already supplies one. Verified to fail
(header missing) with the fix reverted and pass with it restored.

## Login CSRF is closed: a pre-session token

"Login CSRF is open" above used to be permanent, not merely current — closing
it needs a token issued before any session exists, and a merely self-signed
one does not actually solve the problem (see the analysis in
`app/core/csrf/anon.py` for why). That module, plus a new
`GET /api/v1/auth/csrf` endpoint, is the fix: `/auth/login` and
`/auth/register` moved out of `EXEMPT_PATHS` into `ANONYMOUS_CSRF_PATHS` and
now require the same header the session-bound flow does, verified against a
cookie that is itself both self-signed and, where the deployment serves
HTTPS, `__Host-`-prefixed — the part that actually stops a sibling subdomain
from planting one (browsers refuse a `__Host-` `Set-Cookie` without `Secure`,
no `Domain`, and `Path=/`, which host-locks it to the exact origin that set
it).

**The cost, named rather than hidden:** `__Host-` requires HTTPS. A
deployment running over plain HTTP — local dev, by default — gets an
unprefixed cookie of the same shape instead, which still blocks the naive
double-submit break (signing) but not the sibling-subdomain one. Set
`KERVY_SESSION_COOKIE_SECURE=true` for the full guarantee, which any
deployment reachable over the public internet should be doing already.

Both the frontend (`clientApiFetch` in `lib/api-client.ts`, via a new
`ensureAnonCsrfToken` that calls the endpoint lazily) and the CLI
(`ApiClient.fetch_anon_csrf_token` in `kervy_cli/client.py`, called from
`cmd_login`) go through this same front door now — closing the enforcement
gap without it meant either would 403 on their next login.

`POST /auth/login/2fa` sits in the same `ANONYMOUS_CSRF_PATHS` set and needs
the identical pre-session token. Its `challenge` and `code` are both
attacker-suppliable (from the attacker's own 2FA-protected account), so
forging this request signs the victim's browser into the attacker's account
exactly the way a forged `/auth/login` would — the second factor narrows who
can *complete* a particular login, not who can attempt the CSRF, so it needs
the same closed door `/auth/login` and `/auth/register` do.

## `forgot-password` / `reset-password` are exempt, deliberately

Both were added to `EXEMPT_PATHS` — no token at all, not even the anonymous
one — rather than `ANONYMOUS_CSRF_PATHS`, because neither reads a session
cookie in the first place. `forgot-password` takes its whole authority from
an email address in the body; `reset-password` from the one-time reset token
mailed to that address plus a new password. A forged request to either
achieves nothing a direct call to the same endpoint would not already
achieve, because there is no victim session for either one to ride.
`logout-all`, by contrast, **is** cookie-authenticated and is not exempt —
see `docs/revocation.md`.
