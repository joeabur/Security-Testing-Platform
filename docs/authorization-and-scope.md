# Authorization and scope

This is the document to read if you read only one. Everything else in the
platform is downstream of the rule stated here: **nothing reaches a target
without a recorded human authorization and a rules-of-engagement envelope, and
every outbound request passes one gate.**

## The two objects

**An authorization grant** records a human act: who authorized testing, in what
role, with what reference, and for what window. It is not a checkbox — the API
requires `authorized_by_name`, `authorized_by_role`, `authorized_by_email`, a
`reference`, `valid_from` and `valid_until`. A run outside that window is
refused, and the refusal is a halt rather than a skipped request.

**Rules of engagement** bound what may be done inside that window: allowed and
excluded domains, allowed IP ranges, allowed and excluded paths, allowed
methods, forbidden headers, blackout windows, safe mode, and budgets.

A run needs both. Asking for a run without a grant returns `409` — verified in
`docs/installation.md`, and the first thing the quickstart demonstrates.

## A third, distinct grant: exploitation authorization

The two objects above authorize *assessment* — discovery, vulnerability
scanning, validation. Real exploit execution (`TestDepth.EXPLOITATION`,
pentest-module Phase 12) needs more than that, and reusing the general
authorization for it would silently broaden every existing grant's
meaning to include live exploit code, which nobody who granted one under
the old shape agreed to. So it is a separate object,
`ExploitationAuthorization` (`PUT .../targets/{id}/exploitation-
authorization`, `Role.ADMIN`, same "replace wholesale on re-grant" shape
as the general grant), naming its own `approved_script_names` and its own
validity window.

Firing is a two-step, and each step is its own concrete artifact:

1. **Simulate** happens automatically inside an ordinary scan run once
   the target's `asset_scope.max_depth=exploitation` and
   `approved_modules` names `nmap-exploitation`. It never executes
   anything real — it only records an informational marker in that run's
   `scan_results` naming what would be eligible to fire.
2. **Fire** (`POST .../runs/{run_id}/exploitation-fires`,
   `Role.SECURITY_ENGINEER`, an explicit `authorization_confirmed: true`)
   references that completed run's own simulate marker and only proceeds
   if three independent allowlists all agree: the deployment-wide
   `KERVY_EXPLOITATION_ALLOWED_NSE_SCRIPTS` operator setting (empty by
   default), the live `ExploitationAuthorization`'s own
   `approved_script_names`, and the target's `asset_scope.approved_
   modules`. See `docs/roadmap.md`'s Phase 12 write-up for the full design
   and why none of the three alone is sufficient.

### Dual control: the fire step needs two different people

A follow-up whole-system review found that the three-allowlist gate above
still let one person single-handedly both decide a real exploit should run
and be the one whose click ran it. `POST .../exploitation-fires` no longer
queues anything — it creates the fire `awaiting_approval` and stops there.
A second, distinct action, `POST .../exploitation-fires/{fire_id}/approve`
(`Role.SECURITY_ENGINEER`-or-above), refuses with `409` if the approver is
the same person who requested it, or if the fire is not still
`awaiting_approval`; only after it succeeds does the worker task actually
run. `POST .../exploitation-fires/{fire_id}/reject` lets the requester, or
anyone else at that tier, stand a fire down instead, recording a reason.
The worker re-checks the same three-allowlist gate again at execution
time — never trusting that a check made at request time is still true
seconds or minutes later, the same reasoning `GatedTransport` re-resolves
DNS per request rather than trusting an earlier resolution. See
`docs/dashboard.md`'s "Exploitation tier" section for how this surfaces
in the Next.js run detail page.

## The gate

`app/core/scope/engine.py` decides, and `app/core/scope/transport.py` is the
only place in `app/` where an HTTP client is constructed. A static test greps
the whole package to keep it that way, because a second client would be a second
policy.

Every request is checked in this order, and the first failure wins:

1. Has the run halted, or has the kill switch tripped?
2. Is the current time inside the authorization window?
3. Is it inside a blackout window?
4. Does the URL contain userinfo (`user@host`)? Refused — it is a common way to
   make a URL look like it points somewhere it does not.
5. Is the hostname excluded? Is it allowlisted?
6. Is the path excluded? If `allowed_paths` is set, is it allowlisted?
7. Is the method allowed? Is a forbidden header present?
8. **Resolve DNS, then check every resolved address.**
9. Is there budget left?

## Why DNS is re-resolved at send time

Because a hostname that passed a policy check five seconds ago can point
somewhere else now. The engine resolves at the moment of sending and checks
every address that comes back, so a DNS-rebind attack fails at the gate rather
than at the socket.

A hostname that does not resolve is **refused**, not skipped: without an address
there is no way to prove it is not internal. It is deliberately not a *halt* —
one dead host should not abort an entire assessment.

## Blocked addresses

Refused by default: loopback, link-local, RFC1918 and the other private ranges.

**Cloud metadata addresses — `169.254.169.254` and `fd00:ec2::254` — are
refused unconditionally.** They were previously excusable via
`allowed_ip_ranges`, which meant an entry of `0.0.0.0/0` would have reached
them; that was found and fixed in Phase 12. Private and loopback ranges *remain*
overridable, deliberately: assessing a service on a private network is a
legitimate engagement, and the opt-in is explicit and recorded in the rules of
engagement.

This is why the demo lab needs `allowed_ip_ranges: ["127.0.0.0/8"]`. The default
refuses it, and that is the correct default.

## Redirects are never followed

`follow_redirects=False`, always. A 3xx `Location` is re-checked through the
same engine as a fresh target, and refused if it leaves scope. A redirect is the
simplest way to turn an in-scope request into an out-of-scope one.

## Budgets

Requests, concurrency, requests per second, tokens sent and received, estimated
cost, and wall-clock minutes. Budget is reserved before the request and the
reservation is what bounds concurrency. Exceeding one stops the run cleanly with
a reason rather than failing it.

## Safe mode

`safe_mode: true` is the default. Under it, probes that would change state run
in analysis mode and say so — a mass-assignment finding reported from a spec
carries `DESIGN_REVIEW` confidence, which is a different claim from a confirmed
one and is presented as such.

## The kill switch

A Redis-backed flag, checked at every gate decision, so a run can be stopped
from a different process than the one executing it. Tripping it halts the run;
it does not merely cancel the next request.

## The same gate for everything else

Four subsystems reach hosts that are not targets: the AI provider,
notification channels, code-host connections, and the social-login OAuth
flow. None of them opens its own client. Each builds a `RunContext` whose
allowlist is **derived from configuration** and holds exactly one host,
with empty `allowed_ip_ranges`:

| Subsystem | Allowed host | Methods |
|---|---|---|
| AI provider (`assistant/egress.py`) | the configured provider host | POST |
| Notifications (`integrations/egress.py`) | the resolved channel host | POST |
| Code host (`vcs/egress.py`) | `api.github.com` or a sanctioned Enterprise host | GET, POST |
| OAuth login (`oauth/egress.py`) | the one provider host (`accounts.google.com`/`github.com`) for this login round trip | GET, POST |

There is no parameter on any of them through which a caller could pass a target
hostname, which is what stops them becoming an authorization bypass. And because
`allowed_ip_ranges` is empty, a notification channel or code-host connection
pointed at the metadata service is refused exactly as a target would be.

SMTP is the one honest exception — it is not HTTP, so it cannot travel through
`GatedTransport`. The same `ScopeEngine` adjudicates the relay host before
`smtplib` is touched, and `smtplib` is statically pinned to that one module. The
engine does not see the socket; that is a smaller guarantee and is written down
rather than glossed over.

## Evidence

Every decision — allow or refuse — is auditable. The audit log is append-only
and hash-chained, mirrored from a file log into the database; the service module
has no update or delete function, which is how the invariant is enforced.

## Testing this

`backend/tests/security/test_scope_controls.py` covers every case in
`docs/BUILD_SPEC.md` §6.3, plus the static checks that no ungated client and no
second socket-level egress path exists.
`backend/tests/security/test_authorization_matrix.py` walks every route and pins
its required role, so a privilege downgrade fails the suite by name.
