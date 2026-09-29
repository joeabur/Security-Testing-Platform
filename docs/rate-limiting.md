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
| `GET /auth/oauth/{provider}/callback` | per IP | 30 / hour |
| `POST /auth/forgot-password` | per IP | 10 / hour |

`forgot-password` and the OAuth callback are IP-only, for a reason distinct
from "the per-IP budget is enough": neither has an identity to key a second
bucket on without breaking its own non-enumeration property.
`forgot-password` never looks up the address until *after* the budget is
already charged — same ordering as `login`, for the same reason — so there is
nothing to key an identity dimension on that would not itself leak whether
the address exists. The callback's "identity" is a one-time authorization
code, never reused, so an identity bucket on it would never accumulate
anything.

Every other listed route consumes from **both** dimensions, because either
alone is bypassable. Per-IP alone falls to a botnet — a thousand hosts making three
attempts each against one account is a thousand times the budget. Per-identity
alone falls to spraying — one host trying one common password against ten
thousand accounts never exceeds any account's budget.

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

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `KERVY_RATE_LIMIT_ENABLED` | `true` | Off only when an operator says so, in their environment |
| `KERVY_TRUSTED_PROXY_COUNT` | `0` | Proxies in front; `0` ignores `X-Forwarded-For` entirely |
| `KERVY_RATE_LIMIT_PEPPER` | `JWT_SECRET` | Pepper for identity bucket keys |
| `REDIS_URL` | `redis://localhost:6379/0` | Where the counters live |

## What is not limited

Stated rather than implied:

- **Only `login` and `register`.** §22 asks for per-route rate limiting across
  the API; the authenticated routes are not limited, because they already
  require a credential and are bounded by RBAC. Extending the policy is a table
  entry in `app/core/ratelimit/policy.py` — the machinery is general.
- **Fixed window, not sliding.** An attacker can land up to `2 × limit`
  attempts across a window boundary. A sliding log would close that, at the
  cost of a sorted set per key and a read of every entry — which, under exactly
  the spraying attack this defends against, is the memory profile that takes
  the store down. The slack is bounded and known; the blow-up is not.
- **`MemoryStore` is not for multi-process deployments.** Two API workers would
  each enforce the full limit, doubling it. It exists for tests and for a
  single-process run that says so.
- **No CAPTCHA, no progressive delay, no device fingerprinting.**
