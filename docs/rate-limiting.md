# Rate limiting

Authentication endpoints are rate limited (`docs/BUILD_SPEC.md` §18, §22). This
was the oldest open gap in `docs/security-review.md` and the one it named as
most likely to matter first in a real deployment.

## What is limited

| Route | Dimension | Budget |
|---|---|---|
| `POST /auth/login` | per identity | 10 failures / 15 min |
| `POST /auth/login` | per IP | 60 failures / 15 min |
| `POST /auth/register` | per IP | 10 / hour |
| `POST /auth/login/2fa` | per identity | 10 / 15 min |
| `GET /auth/oauth/{provider}/callback` | per IP | 30 / hour |
| `POST /auth/forgot-password` | per IP | 10 / hour |

`login/2fa` is keyed on the *user id* the already-verified challenge names
(`app/auth/security.py`'s `TotpChallenge`, decoded before this budget is
charged), not on anything attacker-supplied — a six-digit TOTP code is only
10^6 possibilities per account, tighter than `login`'s own password budget on
purpose, because a correct password should not buy unlimited guesses at the
second factor. It clears on a correct code the same way `login`'s own
identity bucket clears on a correct password.

`forgot-password` and the OAuth callback are IP-only, for a reason distinct
from "the per-IP budget is enough": neither has an identity to key a second
bucket on without breaking its own non-enumeration property.
`forgot-password` never looks up the address until *after* the budget is
already charged — same ordering as `login`, for the same reason — so there is
nothing to key an identity dimension on that would not itself leak whether
the address exists. The callback's "identity" is a one-time authorization
code, never reused, so an identity bucket on it would never accumulate
anything; the budget instead bounds how many token-exchange calls this
server will make to the provider on one IP's behalf, since even a doomed
attempt with a forged `code` costs a real outbound request.

`login` itself is the one route that consumes from **both** dimensions,
because either alone is bypassable. Per-IP alone falls to a botnet — a
thousand hosts making three attempts each against one account is a thousand
times the budget. Per-identity alone falls to spraying — one host trying one
common password against ten thousand accounts never exceeds any account's
budget. Every other route above has only one dimension available to it in
the first place — `register`, `forgot-password` and the OAuth callback have
no pre-lookup identity to key a second bucket on (see above); `login/2fa`'s
identity comes from an already-decoded challenge rather than anything an
attacker chooses freely, so a per-IP bucket on top of it would add little.

The numbers are chosen against what each attack needs. Ten failures per
15 minutes makes a thousand-word list take about a day per account, by which
time the audit log has been recording failures for hours. A person who has
forgotten which password they used gets about ten tries before waiting.

The per-IP budget is deliberately looser: an office behind one NAT is many
legitimate people sharing an address.

## It throttles; it never locks out

A refusal is **429 with `Retry-After`**, and the window expires on its own.
There is no lockout state and no administrative unlock.

That is a security decision, not a convenience one. An account lockout
triggered by failed attempts is a denial-of-service primitive aimed at whoever
the attacker names: knowing a colleague's email address would be enough to keep
them out of the product indefinitely. Throttling costs an attacker the same
time and costs the victim a wait that ends by itself.

**Only failures accumulate.** A successful login clears the counters. Counting
successes would mean a busy legitimate user throttles themselves, which is how
a rate limit gets switched off in production.

## It cannot tell you whether an account exists

Budget is consumed **before** the user lookup and identically for every
address, so the 429 for a real account and for one that was never registered
are indistinguishable — same status, same body, same headers.

This matters because the login handler is already careful not to leak existence
(one message for "no such user" and "wrong password"). A rate limiter bolted on
afterwards is the classic way that care gets undone:
`throttled` vs `not throttled` becomes the oracle.
`tests/security/test_rate_limit.py` asserts the two responses match, and the
assertion was checked by moving the enforcement after the lookup.

## A client cannot choose its own bucket

`X-Forwarded-For` is attacker-controlled. A limiter that reads it without
thinking gives an attacker one fresh bucket per forged value — unlimited
attempts — which is **worse than having no limiter**, because the configuration
still says the control is on.

So the header is ignored unless an operator states how many proxies sit in
front:

```bash
KERVY_TRUSTED_PROXY_COUNT=1   # one load balancer in front
```

The default is `0`: the socket address and nothing else. With N trusted
proxies, the Nth entry from the right is used — everything to its left was
appended by something upstream of the operator's own proxies, which is to say
by the client. A value that is not an IP address falls back to the socket,
because accepting arbitrary text would be a bucket per random string.

## The counter store does not hold email addresses

An identity bucket keyed on `login:alice@example.test` puts the address under
attack into Redis, into every `KEYS` dump and into any log line that prints a
key. Identity keys are an **HMAC** over the normalized address under a
server-side pepper.

HMAC rather than a plain hash because email addresses are enumerable: an
unkeyed digest is reversible with a wordlist by anyone who can read the store.
Normalizing first (trimmed, lower-cased) matters as much — without it the limit
is one capitalization away from being doubled.

The pepper defaults to `JWT_SECRET`; set `KERVY_RATE_LIMIT_PEPPER` to separate
them. Requiring a second secret to be configured is how a deployment ends up
with neither.

## It fails open, and says so

Every other boundary in this platform fails **closed** — the scope engine, the
authorization check, the CI gate. This one does not.

A rate limiter is a mitigation layered on top of authentication, not the thing
that decides whether a credential is valid. Argon2id still stands behind it. If
the counter store is unreachable and this failed closed, a Redis blip would
lock every user out of the product — trading a bounded, already-mitigated risk
for a total outage.

So an unavailable store allows the request **and logs at error level**:

```json
{"event": "rate_limit_store_unavailable", "route": "login", "rule": "login:identity", ...}
```

Failing open silently would be the real failure. An operator who never learns
their rate limiting stopped counting has a control that exists only on paper.
Alert on that event.

## The general ceiling over the rest of the API

Everything above this line is a tight, attack-specific budget for one
unauthenticated route. The rest of `/api/v1` — every authenticated route,
which used to have no throttle at all beyond RBAC — now sits behind one
coarse ceiling, `api_default`, applied by `app/main.py`'s
`api_rate_limit_middleware` rather than a per-route `enforce()` call: the
same "covers every route, including any added later, narrowed by the
request rather than by a list somebody has to remember" reasoning the CSRF
middleware right above it in that file already gives for being middleware.

| Dimension | Budget |
|---|---|
| per IP | 1200 requests / 5 min |
| per identity (when free to read) | 600 requests / 5 min |

Per-IP always applies. Per-identity applies only when the request carries a
bearer JWT whose subject decodes without a database round trip
(`app.auth.security.decode_access_token` checks only the signing secret) —
middleware runs before a route's own DB-backed identity resolution
(`app.auth.dependencies.get_current_user`), so a JWT's own subject claim is
the one identity available this cheaply. An API-key-authenticated request,
or one with no credential at all, falls back to the IP rule alone. This is
deliberately not authentication: a forged or expired token simply fails to
decode, the request proceeds to the route's own real auth check exactly as
before, and the only consequence is which bucket the request's *budget* is
counted against.

`GET /health` is exempt — an orchestrator's liveness probe is not the
traffic this exists to bound, and throttling it would turn a rate limit
into a self-inflicted outage detector.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KERVY_RATE_LIMIT_ENABLED` | `true` | Off only when an operator says so, in their environment |
| `KERVY_TRUSTED_PROXY_COUNT` | `0` | Proxies in front; `0` ignores `X-Forwarded-For` entirely |
| `KERVY_RATE_LIMIT_PEPPER` | `JWT_SECRET` | Pepper for identity bucket keys |
| `REDIS_URL` | `redis://localhost:6379/0` | Where the counters live |

## What is not limited

Stated rather than implied:

- **The attack-specific per-route budgets above are still only the
  unauthenticated, identity-adjacent routes: `login`, `register`,
  `login/2fa`, `forgot-password`, and the OAuth callback.** Every other
  route sits behind the coarser `api_default` ceiling instead (see above) —
  generous enough not to bound ordinary use, not a tight budget tuned to one
  attack's shape the way `login`'s is. Giving a specific route its own
  tighter rule beyond that ceiling is a table entry in
  `app/core/ratelimit/policy.py` plus an `enforce()` call in its handler —
  the machinery is general.
- **Two more rules are registered but not yet wired to a route:**
  `agent_tool_call` (60/5 min per identity) and `agent_sensitive_tool_call`
  (10/10 min per identity), added to `policy.py` alongside the native agent's
  tool registry ahead of the phase that calls them, the same way a policy
  entry is meant to be added — not because a route already needs it today.
  `docs/agent.md`'s own roadmap section lists per-tool rate limiting as still
  deferred; nothing in `app/core/agent/runtime.py` calls `RateLimiter.check`
  yet, so a tool's `rate_limit_rule` field is presently a declared intent, not
  an enforced one. Do not cite this as "agent tool calls are rate limited"
  until a route actually consumes it.
- **Fixed window, not sliding.** An attacker can land up to `2 × limit`
  attempts across a window boundary. A sliding log would close that, at the
  cost of a sorted set per key and a read of every entry — which, under exactly
  the spraying attack this defends against, is the memory profile that takes
  the store down. The slack is bounded and known; the blow-up is not.
- **`MemoryStore` is not for multi-process deployments.** Two API workers would
  each enforce the full limit, doubling it. It exists for tests and for a
  single-process run that says so.
- **No CAPTCHA, no progressive delay, no device fingerprinting.**
