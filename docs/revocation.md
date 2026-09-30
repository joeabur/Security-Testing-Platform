# Server-side JWT revocation

A JWT is normally valid until it expires — there is no way to make one stop
working early. That leaves two real gaps: "logout" only clears the client's
cookie while the token underneath (default lifetime: 12 hours) keeps working
anywhere it was copied, and there is no response to "this token may have
leaked" short of waiting out its lifetime. `docs/BUILD_SPEC.md` §18 asks for
real session/token management; this closes it.

## Two mechanisms, different shapes

| | Trigger | Scope | Storage | Survives a Redis restart? |
|---|---|---|---|---|
| Per-token revocation | `POST /auth/logout` | one token | Redis, TTL = token's own remaining lifetime | No — bounded loss, see below |
| Per-user cutoff | `POST /auth/logout-all` | every token ever issued to that user | Postgres (`users.tokens_valid_after`) | Yes |
| Per-token revocation, by name | `DELETE /auth/sessions/{id}` | one token, chosen from a list rather than only "this one" | Same deny-list as `/auth/logout` | No — same bounded loss |

**Per-token** is a deny-list keyed by the token's own `jti` claim, so logging
out kills exactly the session that called it and nothing else. Losing an
entry to a Redis restart means a logged-out token becomes valid again for at
most its own remaining lifetime — bounded, and acceptable for the same reason
the rate limiter accepts bounded loss elsewhere.

**Per-user** is a single timestamp: any token whose `iat` precedes it is
rejected, regardless of how many tokens exist or whether this platform ever
tracked them. It is durable in Postgres rather than Redis-only *on purpose*:
losing a "log out everywhere" cutover to a restart would silently undo a
compromise response, which is the one case this mechanism exists for.

## `iat` truncation, and why there is a second timestamp claim

RFC 7519 defines a JWT's `iat` as an integer-second `NumericDate`, and PyJWT
truncates a `datetime` claim to that on encode. Comparing a truncated `iat`
against a microsecond-precision Postgres column is ambiguous whenever the two
events land in the same wall-clock second — which local test suites do
constantly, and which a "log out everywhere, then immediately log back in"
flow does too.

Rounding either side to match the other only moves the race: floor `iat` down
and a token issued a moment *before* the cutoff in the same second can survive
it; floor the cutoff instead and a token issued a moment *after* can read as
revoked the instant it is minted.

The fix is a second claim, `iat_us` — whole microseconds since the epoch,
carried alongside the standard `iat` purely for this one comparison. It is
required on every token this process issues, checked the same way `jti` is: a
token missing it is treated as malformed, not as exempt from the check. A
forger who stripped the claim to dodge revocation must not be rewarded with a
token nothing can kill.

This was found by writing the test for "log back in immediately after
logout-all" and watching it fail intermittently — the failure mode this
section exists to explain.

## This control fails closed

Every other Redis-backed control on this platform — the rate limiter, the run
kill switch — fails **open** on an unreachable store, deliberately: each sits
on top of a decision something else still makes correctly (Argon2id, the
scope engine's own budget checks), so a Redis blip must not turn into a wider
outage than the risk it mitigates.

Revocation is not that shape. It **is** the authorization decision for a
token that was deliberately killed. If the store cannot be consulted, this
platform does not know whether the token in hand is one of the dead ones, and
"could not tell, so let it through" is exactly the failure a
revoked-but-still-working token represents. So an unreachable revocation store
means every JWT-authenticated request is refused — a wider blast radius than
the rate limiter accepts, and the correct trade for what this control is for.

API keys are entirely unaffected either way: they carry their own revocation
(`ApiKey.revoked_at`, checked from Postgres) and never touch this store.

## A third table: `user_sessions`, a record rather than a decision

The two mechanisms above answer "kill this" and "kill everything", but until
now neither could answer "what is currently active" — `logout-all` works by
cutoff, not by enumeration, so this platform never had to track which tokens
existed, only which were dead. `app/models/user_session.py` adds that
tracking: one row per token issued at `/auth/register` or `/auth/login`,
read by `GET /auth/sessions` and acted on by `DELETE /auth/sessions/{id}`.

This table does not change where the authorization decision is made.
Revoking a session by id still writes its `jti` to the same per-token
deny-list `/auth/logout` uses; `logout-all` still works by cutoff and bulk-
updates this table's rows only so the listing stays honest about what
happened, not because the cutoff needs them. Losing this table entirely —
a botched restore, for instance — makes past sessions invisible but revokes
nothing that was already revoked and un-revokes nothing that was not.

Both new endpoints are scoped to the caller's own account: there is no
admin view of another user's sessions, and revoking someone else's returns
404, the same non-disclosure `require_membership` already uses elsewhere on
this API.

## Using it

```bash
# End this session only. Other tokens for this user keep working.
curl -X POST "$KERVY/auth/logout" -H "Authorization: Bearer $TOKEN"

# End every session — the response to "I think this leaked".
curl -X POST "$KERVY/auth/logout-all" -H "Authorization: Bearer $TOKEN"

# What is currently active, and end one specific *other* one by id.
curl "$KERVY/auth/sessions" -H "Authorization: Bearer $TOKEN"
curl -X DELETE "$KERVY/auth/sessions/$SESSION_ID" -H "Authorization: Bearer $TOKEN"
```

Both clear the session and CSRF cookies when called with a cookie-
authenticated session; `logout-all` requires the same CSRF token every other
cookie-authenticated write does (it is not in the CSRF exemption list —
`docs/csrf.md` — because unlike plain logout it has no "must work from a
stale page" requirement to justify carrying the exemption).

## What this does not cover

- **A token revoked and a Redis restart in between:** the per-token deny-list
  entry is lost; the token is valid again until its own `exp`, at most 12
  hours later by default. The durable `logout-all` cutoff is not affected by
  this, which is the whole reason it lives in Postgres.
- **A self-service password *change* flow (already logged in, know the old
  password) does not exist yet** to hang a "revoke everything on password
  change" rule from — `logout-all` was, and remains, the deliberate stand-in
  for that case specifically.

  What now exists is the different case: `POST /auth/reset-password`
  (`docs/authentication.md` §"Forgot / reset password"), reached only by
  someone who has proven control of the account's email inbox, not the
  browser making the request. It sets `tokens_valid_after` and bulk-revokes
  every row in `user_sessions` — the exact same two writes `logout-all`
  makes — because a password reset *is* the "I think this account was
  compromised" case this mechanism exists for, whether or not the person
  hitting "forgot password" is still signed in anywhere.
