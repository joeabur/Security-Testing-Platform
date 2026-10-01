# Security review

A self-review of Kervy Security, written for someone deciding whether to
run it. It states what the controls are, how each one was verified, and what is
deliberately not covered. Where a control is weaker than it might appear, that
is said here rather than left to be discovered.

Reviewed on branch `claude/ai-risk-security-platform-vc1nch`, through Phase 18.
The test count moves with every phase; `docs/roadmap.md` records what each one
added and what it deliberately left out.

## What this thing is, and why that matters

Kervy launches network requests on behalf of its caller and runs third-party
scanners against source it was pointed at. **It is SSRF-shaped by design.** The
scope engine is the only thing between it and abuse, so most of this document
is about that engine and the ways it could be circumvented.

Deploy it on a restricted network segment. `docs/threat-model.md` says the same
thing at more length.

## The controls, and how each was verified

### The scope engine is the single outbound control point

Every outbound request — API, worker, CLI, plugin, AI provider — goes through
`GatedTransport`. Verified three ways:

- a static test greps `app/` for `httpx.Client(`/`httpx.AsyncClient(` and fails
  on any construction outside `app/core/scope/transport.py`;
- the platform's own Semgrep rule (`kervy.ungated-http-client`) runs against
  this repository in `security.yml`, with exactly two annotated suppressions —
  the transport itself and the CLI's client, which talks to the Kervy API
  rather than to a target;
- the plugin tests assert that nothing reachable from the plugin contract is an
  HTTP client, that a plugin pointed at an out-of-scope host gets nothing, and
  that a plugin's requests count against the run's budget.

**Order matters and is tested:** exclusions are evaluated before allowlists,
DNS is re-resolved per request (so a name that resolved in-scope once cannot be
re-pointed), and redirects are never followed automatically.

### Private ranges are blocked; metadata endpoints cannot be unblocked

RFC1918, loopback, link-local and `0.0.0.0/8` are refused unless an operator
lists the range in `allowed_ip_ranges`. That override exists because scanning an
internal staging host is a real engagement, and so is scanning the demo lab on
its internal Docker network.

`169.254.169.254` and `fd00:ec2::254` are **not overridable**. They are not
targets; they are what hands out the credentials of the machine this platform
runs on, and leaving that behind a configuration flag would make one mistyped
allowlist the difference between a scanner and a credential thief. Tested with
allowlists as broad as `0.0.0.0/0`.

This was found during this review. Until then a wide `allowed_ip_ranges` would
have permitted the metadata endpoint.

### Authorization is a hard gate, checked per request

A run cannot start without an `Authorization` record naming a person, a role
and a validity window, and the window is checked on every request rather than
once at run start. Only Admin and Owner may grant one — asserted against the
route table, not by inspection.

### Tenant isolation and RBAC

`tests/security/test_authorization_matrix.py` walks the real route table and,
for every organization-scoped route:

- asserts it declares a minimum role (a new endpoint cannot join the API
  without one, because the test enumerates rather than reading a list);
- calls it unauthenticated and expects 401;
- calls it as a member of a different organization and expects **404, not 403**
  — 403 would confirm the organization exists;
- calls it as a role below its declared minimum and expects 403.

114 assertions, 2 skipped (the SSE stream, covered separately).

It also pins the route→role table. That was added after breaking the test on
purpose: downgrading a route from analyst to viewer passed every other
assertion, because a weakened route enforces its weaker declaration perfectly
well. A privilege change now has to be made deliberately, where a reviewer sees
it.

### Secrets are redacted before anything is written

`build_bundle` is the only sanctioned way to make an evidence bundle, and it
redacts headers by name, bodies, judge transcripts and the detector's own
verdict. `EvidenceStore.write` re-scans the serialized bytes and refuses,
naming what tripped it. A Hypothesis property test plants each of nine
credential shapes in arbitrary surrounding text and asserts the serialized
bundle discloses none of them.

Two real defects came out of that test:

- the patterns anchored on `\b`, so `AKIAIOSFODNN7EXAMPLE0` — a complete AWS key <!-- pragma: allowlist secret -->
  id plus one character — passed through unredacted. Adjacency is no longer a
  way past the detector;
- a run's canary is random, so whether it happened to clear the entropy
  threshold decided whether the run could store evidence at all. Markers are
  now exempt, which also means marker-based findings keep the evidence that
  makes them checkable.

### Evidence is content-addressed and hash-chained

Each bundle is named by its digest; each manifest entry carries the previous
entry's chain value. `verify` re-walks the chain *and* re-hashes every file, so
a bundle edited in place fails as loudly as one removed. Both failure modes are
tested by performing the tampering.

**Not encrypted at rest.** Filesystem permissions and pre-write redaction are
what protect a bundle. `.env.example` and the compose volume say so where an
operator will read them.

### API keys cannot escalate

A key's scopes are its authority and the role is derived from them, capped at
security engineer. A key therefore cannot create a target, amend an
authorization, add a member, or mint another key — tested by minting an owner's
key and attempting all four. Without that cap every CI key an owner created
would have been an owner key.

### The AI layer cannot act

`AIService` has no `execute`. It drafts; a human accepts. Capabilities are a
closed set, target-touching actions are refused at the type level, and evidence
is fenced as data before it reaches a model — the material this layer
summarises is harvested from injection probes, so passing it unfenced would
repeat the mistake the platform tests its clients for. A boundary test asserts
nothing in `core/` outside `core/assistant` imports the assistant, so the
platform works with the whole layer absent.

### Plugins are not sandboxed, and this is said everywhere

A plugin is Python in the worker process. Discovery is off until an operator
names a package; an optional hash pins the installed build. What is guaranteed
is that the contract offers no ungated route to a target, that metadata is
validated at load, that a plugin's attribution is overwritten so it cannot file
findings under a native probe's name, and that a plugin-supplied evidence
bundle is discarded.

### The demo lab cannot reach anything

Behind `--profile demo`, on a network declared `internal: true` (no gateway),
no published ports, `read_only`, `cap_drop: ALL`, no `env_file`. It refuses to
start if any of thirteen provider credential variables is set, binds loopback
unless told otherwise, uses a stub with no HTTP library, and prints a banner.
Each of those is a test, plus all ten seeded flaws, plus the compose
declarations.

## What is not covered

Stated plainly, because a review that lists only strengths is marketing.

| Gap | Consequence |
|---|---|
| Rate limiting fails open when Redis is unavailable | Guessing is then bounded only by Argon2's cost; logged at error level, alert on it |
| Evidence encryption at rest is opt-in, not the default | `KERVY_EVIDENCE_ENCRYPTION_KEY` unset (the out-of-the-box state) means a bundle is protected only by filesystem permissions and redaction, same as before this existed |
| No signature verification for plugins | The allowlist and an optional hash are the controls |
| DAST scanners are not gated at the socket | Nuclei and ZAP open their own connections — see the Phase 15 section below |
| Advisory lookup off by default | SCA reports what is installed, not what is vulnerable, unless enabled |
| No inbound webhook endpoint | Workflows and PR publishing are driven by CI, never by an event from a code host |
| No release has been cut | `release.yml` is written and structurally asserted, but has never run end to end |
| No container image signing | Images are scanned; none is published, so none is signed |
| No runtime-protection measurement | Claimed WAF/RASP controls are recorded and explicitly marked "not tested" |
| A duplicate-linked finding still appears in a PR check run | `findings_for_run` (`app/core/vcs/service.py`) carries no filter on `duplicate_of_finding_id`; only a run's own report excludes it. See `docs/pull-requests.md` |

Three rows that stood here through Phase 15 have been removed because the gaps
were closed, not because they got quieter: container, licence and end-of-life
scanning landed with the Aikido-parity engines; DAST landed in Phase 15 (with
its own, narrower gap now listed above); and `mapping_versions` is populated
from pinned framework editions as of Phase 13.

### Malware scanning of dependencies

Closed, at the scope stated below. `appsec.supplychain.malware`
(`app/core/appsec/supplychain/malware_engine.py`) matches declared dependency
names against `malware.py`, a vendored snapshot of published GHSA "type:
malware" advisories (25 PyPI, 25 npm, compiled 2026-09-25 from
`github.com/advisories?query=type:malware`). A match is reported at CRITICAL —
this is a name match against a curated, already-confirmed report, not the
name-similarity signal `typosquat_engine.py` reports, so unlike that engine
this one is allowed to use the word "malware".

The honest limit, stated on every run whether or not it finds anything: the
table is a few dozen entries against a real feed's tens of thousands, so
absence means "not in this small sample", never "checked and safe" — the
same distinction `eol_engine.py` draws for a runtime outside its table. This
is a vendored, offline mechanism, not a live feed; a deployment that wants
current coverage extends `TABLE` from OSV's `MAL-` advisories or a
continuously-updated GHSA query, or wires in an opt-in network lookup the way
`pip_audit_engine.py` already models for ordinary advisories. Like the other
three supply-chain engines, it reaches no network on its own — sending a
client's dependency list to a third party is a disclosure decision an
operator makes, not one this platform makes quietly.

`docs/roadmap.md` carries the reasoning for each.

## Things that would worry me most

1. **An operator who allowlists a broad private range.** It is a legitimate
   feature and it is the widest door in the product. The metadata carve-out
   closes the worst case; nothing closes "I allowlisted 10.0.0.0/8 and scanned
   my own database".
2. **A plugin.** No sandbox, by design and by admission. The allowlist is only
   as good as the review of what goes on it.
3. **Rate limiting that fails open.** Authentication endpoints are now limited
   (`docs/rate-limiting.md`), but an unreachable Redis means they stop counting
   and the requests are allowed. That is the deliberate choice — failing closed
   would turn a Redis blip into a total lockout — and it means the control is
   only as reliable as the alert on `rate_limit_store_unavailable`.

## How to re-run this review

The scanner binaries (`semgrep`, `bandit`, `checkov`, `pip-audit`) must be on
`PATH`, not merely installed in the virtualenv directory. Without them the
AppSec engines correctly emit `not tested` markers rather than silent passes —
which is the designed behaviour, but it reads as nine test failures if you did
not mean it. Activate the environment first.

```bash
cd backend
source .venv/bin/activate                    # so the scanners are on PATH
pytest -q                                    # everything
pytest tests/security -q                     # scope, authz, tenant isolation
pytest -m lab_e2e -q                         # a real assessment against the lab
semgrep --config app/core/appsec/sast/rules --error app kervy_cli
bandit -r app kervy_cli -ll
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

## Phase 15 additions: DAST

Two new controls, and one new gap stated plainly.

**Pre-queue scope checking.** The crawler checks a discovered URL through the
scope engine before it enters the queue, not before it is fetched. This is
stronger than the phase required, and the reasoning is in `docs/dast.md`. The
test asserts on the queue rather than on requests made, and was verified by
replacing the check with "queue everything" and watching it fail.

**Template policy derived from the rules of engagement.** Destructive Nuclei
tags and ZAP's active scan are unreachable unless `allow_state_mutation` is set.
Out-of-band callback templates are excluded even then, with `-no-interactsh`
passed as well so the tag exclusion is not a single point of failure. Verified
by weakening the policy to include the mutating tags unconditionally.

**The gap: the scanner adapters are not scope-gated at the socket.** Nuclei and
ZAP open their own connections. This is the weakest point in the phase.

- *Nuclei* is handed explicit `-target` URLs, each of which passed the scope
  engine during the crawl, and is not asked to discover more. It runs offline
  (`-disable-update-check`) and at the RoE's rate limit.
- *ZAP* spiders on its own and cannot be bounded that way. It therefore runs
  only when the rules of engagement name exactly one concrete host, and emits a
  visible `not tested` marker otherwise. Its report is written to a temporary
  directory and removed, because it contains response excerpts from the target.

If this platform grows a requirement that *all* outbound traffic be observable,
these two adapters are what would have to change — most likely by running them
behind a local proxy this platform controls, which is not built.

## Phase 17 additions: workflows and the dashboard

One new attack surface, handled by removing it; one gap closed; one gate
hardened.

**The dashboard is read-only, and that is the CSRF answer.** `/app` is a new
cookie-authenticated surface, and this platform has no CSRF token. Rather than
ship state-changing page routes behind `SameSite=Lax` alone, every route under
`/app` is a `GET`, and a test walks the route table and fails if that ever
stops being true. Actions are rendered as disabled controls carrying the reason
and the API call that performs them, so the limitation is visible to the
operator rather than discovered.

Verified by adding a `POST` handler and watching the test fail. The same
enumeration asserts every organization-scoped page declares a minimum role
through `require_membership`, so a non-member gets the same **404** the API
gives — proved by removing the dependency from one page and watching both that
test and the tenant-isolation test fail.

**Autoescaping is asserted, not assumed.** A findings page renders a probe's
own payload as echoed back by the target. Rendering that raw would make this
platform's dashboard the stored-XSS sink it tests its clients for.

**No third-party script on the findings page.** HTMX is not committed and there
is no CDN tag; the `<script>` element renders only if an operator vendored the
file into `app/web/static/`. A test asserts every script a template loads is
served by this application. This is a deliberate supply-chain position, and
`docs/dashboard.md` says how to vendor it and what to check.

**A gate that cannot be parsed is refused twice.** On write (422, through the
same `load_config` the CLI gate uses) and on evaluation (the run is `refused`,
never a pass, never the default). The first closes a real window: a malformed
gate stored today is a release that ships ungated next month.

**A test that passed when it should not have, and what it cost.** The first
version of the "every number is a real query" test asserted against the query
object rather than the page. Replacing a dashboard card's value with a literal
`0` did not break it. It was rewritten to read the rendered HTML and compare
every card and severity row to the query's output. The original would have
shipped a green suite around a guarantee that was not being checked — which is
the failure mode this whole document exists to catch.

## Phase 18 additions: runtime-protection extension points

One new surface, and it is deliberately inert.

**This platform does not run inside a customer's process, and that is checked.**
A RASP agent would be code loaded into a running application — which §2 forbids
outright, whatever the configuration. `tests/test_rasp.py` scans every Python
file under `app/` for the ways an agent gets into a process (`sys.meta_path`,
`sys.settrace`, `sitecustomize`, `LD_PRELOAD` and the rest) and fails on any,
including a file merely *named* `sitecustomize.py`.

The scan reads parsed source with docstrings removed. Its first version was a
substring scan and fired on the contract's own docstring explaining the rule —
the grep-versus-prose failure this project has now made twice, in both
directions. There is a test *of the scanner*: prose describing instrumentation
must not trip it, and code performing it must.

**A claim cannot be stored as a measurement.** Every declared control carries a
required `evidenced` field, and the constructor raises on anything but
`claimed` — nothing here has measured runtime protection, and the API has no
`evidenced` input field. A target that declares controls gets an explicit "not
tested" line in every run, with impact stated as *Unknown*, so a clean
assessment against a target claiming a WAF does not read as a WAF that held.

**No unsafe-mode path for the interface.** `RuntimeProtectionContext` carries
no `safe_mode`, `force`, `allow_*`, `bypass_*` or `disable_*` field, and the
protocol's methods take the context alone, so a future engine cannot be handed
its own transport. Verified by adding `safe_mode: bool = False` and watching
the test fail.

**The framework-drift checker makes no network requests.** The fetch lives in
the workflow, where the job log shows it; the Python compares. A maintenance
script with its own HTTP client would be a second outbound path placed just
outside the directory the static check scans, which is worse than an obvious
one because it looks compliant. A test asserts the checker imports no HTTP
library, and that a failed upstream lookup is reported as a gap rather than as
"current".

## Post-Phase-18: a gap this platform created for itself

**The coverage section did not name DAST or RASP.** §27 requires the report's
framework-coverage section to name every pillar that did not run. It was
derived from the engines' own "not tested" markers, which cannot satisfy that:
a pillar that never ran emits no marker. DAST was missing from every report for
three phases and RASP for one — both added by this project's own later phases,
neither appearing in the one section whose job is to say what was not covered.

It is now enumerated: a fixed pillar list, one verdict each, every time, in
every format. An engine that degraded to a "not tested" marker does not count
as coverage — that would move the same lie somewhere else in the report.

Worth stating plainly because it is the failure mode this document exists to
catch: **coverage honesty derived from what produced output degrades to silence
exactly when coverage is worst.**

**A test-isolation race that only appeared under CI's own flags.** Five tests
failed in a full run with `--cov` — which is how CI runs — while passing alone
and passing in a full run without it. The autouse `TRUNCATE` ran as teardown,
took an ACCESS EXCLUSIVE lock, waited on a session an earlier test had left
open, and could complete in the middle of the *next* test, wiping its user. It
now runs at setup, where a blocked truncate delays the waiting test instead of
sabotaging the running one.

**The coverage gate now fails the build.** §24's three floors were reported and
not enforced. The overall floor is the weakest of the three on its own, so the
per-package floors are checked separately, with `core/scope/` held to its own
95% rather than diluted into `core/`. Measured first, met with headroom: 97.8%
scope, 91.6% core, 91.8% overall.

**The ML-BOM ships separately and is nearly empty.** No weights, no
checkpoints, no training data, no fine-tune. The demo lab's "assistant" is a
string function and the AI layer calls an operator-supplied endpoint named by
environment variable — both recorded as what they are rather than padded into a
model inventory.

## Rate limiting (§18, §22)

The oldest open gap in this document is closed. `docs/rate-limiting.md` has the
detail; the parts that bear on a deployment decision:

**Two dimensions, because either alone is bypassable.** Per-IP falls to a
botnet, per-identity falls to spraying. An attempt consumes from both.

**Throttle, never lockout.** A lockout triggered by failed attempts is a
denial-of-service primitive aimed at any user whose address an attacker knows.
A 429 with `Retry-After` costs an attacker the same time and costs the victim a
wait that ends by itself. Only failures accumulate; a success clears the
counters, because a limiter that throttles legitimate users is a limiter that
gets switched off.

**It does not become an enumeration oracle.** Budget is consumed before the
user lookup and identically for every address, so a throttled response cannot
distinguish a real account from one that was never registered. The login
handler was already careful about this; a limiter bolted on afterwards is the
usual way that care is undone. Asserted, and checked by moving the enforcement
after the lookup.

**A client cannot choose its own bucket.** `X-Forwarded-For` is ignored unless
an operator declares how many proxies sit in front. Reading it by default would
give an attacker one fresh bucket per forged value — unlimited attempts, with
the configuration still reporting the control as on. That is worse than no
limiter, and it is the single most common way this control is shipped broken.

**The counter store holds no email addresses.** Identity keys are an HMAC under
a server-side pepper, because an unkeyed hash of an enumerable identifier is
reversible with a wordlist by anyone who can read the store.

**It fails open, loudly, and that is the one asymmetry here.** Everything else
on this platform fails closed. A rate limiter sits on top of authentication
rather than being it, Argon2id still stands behind it, and failing closed would
trade a bounded risk for a total outage. The degradation is logged at error
level; an operator who does not alert on it has a control that exists only on
paper.

**One real bug found on the way.** The application's `HTTPException` handler
rebuilt every error response and silently dropped `exc.headers`, so the 429
arrived with no `Retry-After` — telling a client it was throttled but not for
how long. Pre-existing, and it would have applied equally to
`WWW-Authenticate` or `Allow`.

**§22's "per-route" reading was still partly open.** The above covered only
the unauthenticated, identity-adjacent routes; every authenticated route had
no rate limit at all beyond RBAC. A coarse `api_default` ceiling
(`docs/rate-limiting.md`) now sits under the rest of `/api/v1`, applied by
middleware rather than a per-route call so it covers a route added later the
same way the CSRF middleware beside it does — deliberately generous next to
`login`'s attack-shaped budget, since it exists to bound a scripted loop
rather than to be a tight limit tuned to one endpoint's own risk.

## CSRF protection (§18, §22)

Cookie-authenticated state changes now require a token. `docs/csrf.md` has the
detail; three points bear on a deployment decision.

**The scope is the control.** A token is required for unsafe methods
authenticated by cookie, and for nothing else. Demanding one from
Bearer-authenticated callers would break every CLI invocation and CI gate for
callers who were never at risk — a cross-site page cannot attach an
`Authorization` header. Both halves are asserted; requiring a token everywhere
was checked by doing it and watching the API-client test fail.

**It is not plain double-submit.** The textbook version rests on an attacker
being unable to *read* a cookie, not on being unable to *write* one — so a
sibling subdomain, or a MITM on a plain-HTTP subdomain, supplies both halves
and they match. The token here carries an HMAC over the session cookie's own
value, so a planted pair does not verify against the victim's session. Checked
by removing the session binding and watching the cross-session test fail.

**Enforced as middleware, not a per-route decorator.** A decorator protects the
routes somebody remembered to annotate. The check narrows by the request —
unsafe method, cookie-authenticated, not exempt — so a route added later is
covered without anybody remembering.

Two things it does **not** do, stated because a reader would otherwise assume
them:

- **Login CSRF remains open**, since `/auth/login` and `/auth/register` have no
  session to bind a token to. An attacker can sign a victim into the attacker's
  account. It is now the residual in the gap table above.
- **The constant-time signature comparison is not covered by a test.**
  Replacing `hmac.compare_digest` with `==` leaves the suite green — a timing
  property is not observable from a functional assertion. The code is correct;
  the passing suite is not evidence of it. Said plainly rather than left for a
  reader to infer from the test names.

**The dashboard's disabled controls no longer cite CSRF.** They said "this
platform has no CSRF token", which became false the moment this shipped. A
stale reason on a disabled control is a false statement in the product, so it
was replaced: the dashboard is read-only because no write handlers are built,
which is a scope decision rather than a security constraint.

## Server-side JWT revocation (§18)

The gap this row used to describe is closed: a JWT is no longer valid for its
full 12-hour default lifetime regardless of what happens to it.
`docs/revocation.md` is the reference; two points bear on a deployment
decision.

**This is the one Redis-backed control on this platform that fails closed.**
The rate limiter and the run kill switch both fail open on an unreachable
store, deliberately — each sits on top of a decision something else still
makes correctly. Revocation *is* the decision for a token that was
deliberately killed, so "could not check" must mean "refused", not "allowed
through". An unreachable revocation store therefore refuses every
JWT-authenticated request, a wider blast radius than the rate limiter accepts
and the correct trade for what this control is for. Both halves — the rate
limiter's fail-open and this control's fail-closed — are asserted in the same
test file so a future refactor cannot let them silently converge.

**A subtle timestamp bug was caught before it shipped.** The per-user "log out
everywhere" cutoff compares against a token's issuance time, and the obvious
implementation — using the JWT's standard `iat` claim — is ambiguous within
whichever wall-clock second the cutover happens to land in, because RFC 7519
truncates `iat` to whole seconds. Rounding either side to match the other only
moves the race: a fresh login immediately after "log out everywhere" could
read as revoked, or a token that should have died could survive. It was found
by writing exactly that scenario as a test and watching it fail intermittently
during development. The fix is a dedicated microsecond-precision claim used
only for this comparison, required the same way `jti` is — a token forged
without it is refused, not silently exempted from revocation.

## Frontend CSRF regression, found and fixed (§18)

The backend's CSRF middleware (§ CSRF protection above) went live requiring
`X-CSRF-Token` on unsafe, cookie-authenticated requests, but the browser
fetch helper every Client Component uses — `clientApiFetch` in
`frontend/lib/api-client.ts` — was never updated to read the `kervy_csrf`
cookie and send it. Every cookie-authenticated write from the browser has
been silently 403ing since that middleware shipped; `POST /organizations`
is the first one a user would hit. This was a genuine, previously-unnoticed
regression: the existing frontend tests mock `clientApiFetch` outright and
never touched its real header logic, so nothing caught it.

Fixed by attaching the header in `clientApiFetch` for any request whose
method isn't in the same safe-method set the backend exempts, and applying
the identical treatment pre-emptively to `serverApiFetch`
(`frontend/lib/api-server.ts`) even though its current callers are all
GETs. Proven with `frontend/lib/__tests__/api-client.test.ts`, which drives
the real function against a stubbed `fetch` and a seeded `document.cookie`
rather than a mock, and was confirmed to fail with the fix reverted before
being confirmed to pass with it restored.

## Login CSRF closed (§18)

This report used to carry "login CSRF is open" as an accepted gap:
`/auth/login` and `/auth/register` were exempt from CSRF checking because no
session exists yet for the ordinary session-bound token to bind to. Closed
with a pre-session token (`app/core/csrf/anon.py`, `GET /api/v1/auth/csrf`);
both routes now require it the same way every other cookie-authenticated
write requires the session-bound one.

**A naive fix — a token that is merely self-signed, with no per-visitor
binding — would not have closed anything.** The server would hand a
genuinely valid one to anybody who asked, attacker included, and an
attacker able to plant a cookie for the site (the sibling-subdomain case)
could plant that self-obtained token as both halves of the request. The
property that actually matters is that the value echoed back has to be the
one sitting in *this specific browser's* cookie jar, with the attacker
unable to set it — which is what the `__Host-` cookie prefix provides
(browsers enforce it, refusing a `Set-Cookie` under that name unless it
carries no `Domain`, `Path=/`, and `Secure`, host-locking it to the exact
origin). That requires HTTPS; a plain-HTTP deployment gets a same-shaped
but unprefixed cookie, immune to the naive double-submit break but not to a
sibling-subdomain one specifically — a narrower, stated residual rather
than the "no protection" it replaces.

**A regression I caught before it shipped, not after:** the first version
gated both routes unconditionally, on the same "no Bearer header means
check the cookie" logic every other route uses. That logic does not apply
here — login is the request that *produces* the Bearer token, so no caller,
browser or CLI, can ever present one when calling it. Shipped as written,
it would have 403'd `kervy-ai login` on its very next invocation. Fixed by
giving the CLI the same token round trip a browser gets
(`ApiClient.fetch_anon_csrf_token` in `kervy_cli/client.py`).

Closing this touched 66 call sites across 24 test files that had relied on
the old exemption. That migration — fetch the token, send the header,
verified against the full suite — was delegated to a background agent under
a precise brief; the result (all files fixed, lint/type/test clean, 1379
passed / 2 skipped / 0 failed) was verified independently afterward rather
than accepted on report alone.

## Evidence encryption at rest, made available (§13)

The "no encryption at rest" gap row above used to have no mitigation to
point to at all. There is now one, opt-in: `KERVY_EVIDENCE_ENCRYPTION_KEY`
(`app/core/config.py`) turns on AES-256-GCM for every bundle written from
then on (`app/core/evidence/crypto.py`, wired into
`app/core/evidence/store.py`). Unset — the out-of-the-box state, and what
every existing deployment already has — nothing changes: a bundle is
written exactly as it always was, protected by filesystem permissions and
the redaction that already ran before it was built.

**This is deliberately not a general secrets-management feature.** One
static key, read from an environment variable exactly the way `JWT_SECRET`
and `KERVY_CSRF_SECRET` already are; no rotation, no per-tenant key, no KMS
integration, and no tool to re-encrypt bundles that already exist on disk
before the key was set. `docs/roadmap.md`'s account of this explains why
that is the honest scope rather than an omission: a half-built key-rotation
or multi-tenant-key story would be worse than none, because an operator
would believe more was protected than actually is. This applies the same
trade the platform already made for every other secret it holds to one
more thing, not a new model invented just for it.

A misconfigured key (not valid base64, or not exactly 32 bytes) is refused
at settings construction — `Settings.model_post_init` accesses
`evidence_encryption_key_bytes` for its side effect, so a typo fails at
process startup rather than on the first evidence write during a run, by
which point the probe's observation would already be gone. Covered end to
end in `tests/test_evidence.py` (encrypted bytes never touch disk in
plaintext, the wrong key cannot read a bundle written under the right one,
a single flipped byte fails to decrypt at all rather than producing
corrupted plaintext, two writes of identical content never share
ciphertext) and `tests/test_config.py` (the key-validation failure modes).

## Dashboard pagination

The "dashboard has no pagination" gap row is removed: `/app/.../findings`
and `/app/.../runs` now take a `page` query parameter (`app/web/router.py`'s
`PAGE_SIZE`, 50 rows), with "Previous"/"Next" and "Newer"/"Older" links
rendered only when there is a page on that side to go to —
`queries.has_more_findings` / `has_more_runs` ask that question directly
with a cheap existence query rather than over-fetching and trimming.
`workflows` was left as a fixed, capped list: it was not named in the
original gap and stays a smaller, well-scoped change rather than one that
crept to cover everything on the page.

Digests are unaffected, and so is every other dashboard property this
report already asserts: `offset` only changes *which* rows a page selects,
not their order or the risk-score-first ranking `open_findings` already
used — a filter and a page number compose without either widening the
other's result set, which `tests/test_web.py` checks directly by seeding
one page's worth of matching rows plus one more and asserting the extra
row appears on page 2, under a filter, and nowhere on page 1. Verified to
fail (page 2 duplicating page 1) with `.offset()` reverted, before
restoring the fix.

## Session visibility and revocation by name

The last row this report carried under "what is not covered": only "this
session" (`/auth/logout`) or "every session" (`/auth/logout-all`) was
expressible. `docs/revocation.md`'s own account of that design said why
plainly — "this platform does not track which tokens exist, only which are
dead" — because a per-user cutoff needs neither. Closing this meant giving
up that simplicity deliberately: a new `user_sessions` table
(`app/models/user_session.py`) now records one row per issued token, and
`GET /auth/sessions` / `DELETE /auth/sessions/{id}` read and act on it.

**The table is a record for a human to read, not a second authorization
decision.** Revoking a session still means writing its `jti` to
`app/core/revocation/`'s deny-list — the exact mechanism `/auth/logout`
already used — and the new endpoint's own docstring says so: losing this
table (a botched restore, a truncated table) makes past sessions invisible,
but revokes nothing that was already revoked and un-revokes nothing that
was not, because the deny-list and `users.tokens_valid_after` are what a
request is actually checked against. `/auth/logout-all` was deliberately
left as a bulk cutover rather than rewritten as a loop over tracked rows —
the cutoff invalidates a token by *when* it was issued, which still works
for a token whose row was lost and for one issued the instant before the
request commits, neither of which a loop over rows fetched slightly
earlier could reach.

Scoped to the caller's own account, the same boundary `/auth/logout-all`
already drew — there is no admin view here of another user's sessions.
Revoking someone else's session by id returns 404, the same non-disclosure
`require_membership` already uses for another organization's resource.

Proven at the level that matters: `tests/security/test_sessions.py`'s
central test does not stop at the row disappearing from the list, it
checks the token itself is refused afterward — verified to fail with
`revoke_session` updating only `revoked_at` and never calling
`revocation.revoke`, which would leave the list looking right while the
token underneath kept working, before restoring the real fix.

## Social OAuth login and TOTP two-factor authentication

Two new ways to establish a session, both reviewed for the same failure
mode: does the new path quietly reuse or weaken an existing control.

**OAuth identity is matched by `(provider, provider_user_id)`, never by
email.** `app/models/oauth.py` links `OAuthIdentity` to a `User` by that
pair only. A callback whose email matches an existing password-only
account refuses with `409` rather than linking silently — matching by
email would let anyone who controls an address at a provider that does not
itself verify ownership claim an existing account, the same account-
takeover shape `POST /auth/register`'s duplicate-email case already
guards against.

**The OAuth flow gets its own egress context and its own CSRF nonce.**
`app/core/oauth/egress.py` is the fourth instance of this platform's
"fresh `RunContext`, one host in `allowed_domains`, through the sole
`GatedTransport`" pattern — the same shape `app/core/vcs/egress.py` and
`app/core/assistant/egress.py` already use. The authorization-code flow's
CSRF protection is a single-use, Redis-backed state nonce
(`app/core/oauth/state.py`), fail-closed like every other Redis-backed
store on this platform except the rate limiter — it plays the role the
anonymous CSRF token (`app/core/csrf/anon.py`) plays for `/auth/login`,
since there is no session yet to bind an ordinary token to.

**A TOTP challenge cannot be replayed as a session, and cannot be presented
as an access token.** `POST /auth/login` returns a `TotpChallenge` — a
short-lived JWT deliberately missing the `iat_us`/`jti` claims
`decode_access_token` requires — instead of a session once `totp_enabled`
is true. That omission means it structurally cannot be accepted as a
Bearer token by anything else in the platform, whatever it is presented
as. `POST /auth/login/2fa` redeems it exactly once through a Redis-backed
store (`app/core/twofactor/challenge_store.py`), fail-closed: an
unreachable store refuses the login attempt rather than treating an
unconfirmed challenge as fresh.

**The TOTP secret is encrypted, not merely hashed, and unset key means
refuse, not store plaintext.** `User.totp_secret_encrypted` follows
`webhook_secret_encryption_key`'s exact "not optional encryption"
pattern: `KERVY_TOTP_ENCRYPTION_KEY` unset means enabling 2FA refuses with
`503`, never stores a secret in cleartext. Ten recovery codes are minted
at enable time, shown once, and stored as SHA-256 digests — the same shape
`ApiKey` already uses.

**`/auth/login/2fa` needed the anonymous CSRF token; `forgot-password` and
`reset-password` did not, and that is a real distinction, not an
inconsistency.** `/auth/login/2fa` establishes a new session, so it carries
the same login-CSRF exposure `/login` and `/register` already have, and is
in `ANONYMOUS_CSRF_PATHS`. `forgot-password`/`reset-password` never read the
caller's session — their entire authority is the request body — so a forged
request achieves nothing a direct call would not, and they sit in
`EXEMPT_PATHS` instead. Found by a genuine test failure during this work (a
shared test client already carrying a session cookie from an earlier
`register()` call), not assumed correct by design review alone.

Verified: `tests/test_oauth.py`, `tests/test_password_reset.py`,
`tests/test_twofactor.py`, plus the existing `test_auth.py`/`test_csrf.py`/
`test_rate_limit.py`/`test_authorization_matrix.py` suites re-run against the
new routes. OAuth's outbound calls never touch a real network in tests — a
`FakeDnsResolver` satisfies the scope engine's allowlist check and `respx`
replaces the socket. The TOTP flow was additionally verified live against
the running application (backend, frontend, Postgres, Redis together, not
build/test output alone): register, enable 2FA, scan the real rendered QR
code, confirm, sign out, sign back in with the password alone (refused —
stays on the login page), a fresh TOTP code completes sign-in, sign out
again, a recovery code also completes sign-in, disable 2FA. Every step
passed.

## Membership control: an owner-only ceiling on owner grants

Found during a direct request to confirm an organization owner has full
membership control without global or cross-tenant privileges. Cross-tenant
isolation was already true; membership control was not, in two ways at
once. `app/api/v1/routers/organizations.py` had no route to remove a member
or change an existing member's role — regardless of who was asking. And the
one membership-write route that did exist, `invite_member`, had `Role.ADMIN`
as its floor, which meant an Admin — not only an Owner — could grant
`Role.OWNER` to anyone, including an account they controlled themselves. That
is a real privilege-escalation path: `Role.OWNER` is the most senior role in
`seniority_order()`, so nothing above it exists to check the grant.

New `PATCH`/`DELETE /organizations/{organization_id}/members/{member_id}`,
both `Role.ADMIN` like `invite_member` — an Admin still manages ordinary
membership day to day. The carve-out: granting, changing away from, or
removing `Role.OWNER` additionally requires the caller's own membership to
already be `Role.OWNER`. The same check was added retroactively to
`invite_member`'s grant side.

**The last remaining owner cannot be demoted or removed, even by another
owner.** Refused with `409`, not merely discouraged. Without that rail, the
owner-only check above would still pass for the last owner acting on
themselves, and the organization would be left with no one able to perform
an owner-only action ever again — including undoing the mistake.
`_owner_count()` is a single `COUNT(*) WHERE role = 'owner'`, scoped to the
organization and checked before the write.

Verified: new tests in `tests/test_organizations.py` — an admin cannot grant
or revoke owner, an owner can change a member's role, the last owner cannot
be demoted or removed, a second owner then can be, an admin can remove a
non-owner member, and removing a member by id from another organization is
`404`, the same cross-tenant non-disclosure every other route in this
platform uses. `tests/security/test_authorization_matrix.py` updated with
both new routes.

## Agent provider provisioning, and the private-network gap it exposed

Found by a live runtime audit — starting the API, the frontend and a Celery
worker, not reading source alone. The native agent's own engine (planner,
tool runtime, `POST .../agent/investigate`) was fully built and correctly
returned `409` when unconfigured, but nothing anywhere in the codebase —
no endpoint, no CLI command, no UI — could ever create the `AgentProvider`
row that clears that `409`. The only place one was ever constructed was a
test fixture.

A second, deeper gap sat behind the first: even once provisioning existed,
`platform_egress_context` (`app/core/assistant/egress.py`) hardcoded an
empty `allowed_ip_ranges`, so `GatedTransport` refused any provider endpoint
at a private or loopback address — exactly where a self-hosted model server
(`AgentProviderKind.OPENAI_COMPATIBLE`, covering Ollama/vLLM/llama.cpp)
almost always lives. A local, free provider the agent framework's own design
already anticipated would have been non-functional the moment someone tried
to point at one.

Six new endpoints on `app/api/v1/routers/agent.py`:
`POST`/`GET`/`PATCH`/`DELETE .../agent/providers` and `GET`/`PUT .../agent`,
admin to write and analyst to read — configuring what the agent may reach is
a configuration change, not itself a scan, the same split `docs/workflows.md`
draws between admin and security-engineer tiers. A new
`AgentProvider.allowed_ip_ranges` column threads into
`platform_egress_context`'s own `RulesOfEngagement.allowed_ip_ranges` — the
same mechanism a scan target's own rules of engagement already use to
authorize a private-network target, applied here to a provider endpoint for
the first time. **The cloud-metadata address stays blocked unconditionally
regardless of this setting** — `hostmatch.py`'s metadata check ignores the
allowlist entirely, the same absolute carve-out §"Private ranges are
blocked" above describes for an ordinary target.

Verified: `tests/test_agent_provisioning.py` — creating a provider never
returns a secret, creating a default provider enables the agent and clears
`investigate`'s `409`, an invalid CIDR is rejected at write time (`422`), a
local `openai_compatible` provider's `allowed_ip_ranges` survives the round
trip into the actual `RunContext` `platform_egress_context` builds, deleting
the default provider leaves the agent cleanly unconfigured rather than
pointing at a row that no longer exists, and a default-provider id from
another organization is refused with `404`. RBAC and tenant isolation for
all six routes are covered by `tests/security/test_authorization_matrix.py`.

## `AgentTool.enabled` and `minimum_role_override`: enforced, not merely stored

`AgentTool.enabled` and `AgentTool.minimum_role_override` had existed in the
schema since the agent's earliest phase with no code anywhere that ever read
or wrote either column — `grep -rn "AgentTool(" --include "*.py" .` returned
only test-fixture instantiations. An organization admin who believed they
had disabled a tool, or raised its minimum role, was silently unprotected:
the exact "looks enforced but isn't" shape this review exists to catch.

New `app/core/agent/tool_config.py`: `load_tool_config` (one query per
request or plan, not one per tool call), `effective_minimum_role` and
`is_tool_enabled`. **`effective_minimum_role` enforces the "never lower the
bar" invariant a second time, at read time** — a stored override that would
lower a tool's effective minimum role below its code default is ignored,
not trusted, even though `validate_role_override` already refuses to write
one at `PUT` time. The same defence-in-depth reasoning
`exploitation_service.py`'s three-allowlist gate applies to what can be
fired is applied here to what a stored row is allowed to mean.
`app/core/agent/permissions.py` gained a third independent check —
`authorize_enabled` raises `ToolDisabledError`, a subclass of the existing
`ToolPermissionError` rather than a sibling, so every caller that already
catches the parent handles a disabled tool with no new branch.

New `GET`/`PUT .../agent/tools/{tool_name}/config` (analyst read, admin
write), upserting the whole `AgentTool` row per call rather than a `PATCH`
that could leave a stale field. Both `call_tool` (the direct single-tool
surface `backend/mcp_server/` uses) and `run_plan` now check
`is_tool_enabled`/`effective_minimum_role` before permitting a call. **A
resumed, post-approval-pause investigation reloads this configuration
fresh** rather than trusting a decision made when the plan was first
enqueued — a tool disabled or raised during the pause window is caught at
resume time, mirroring the pentest exploitation-fire task's own
re-validation-at-execution-time pattern below.

Verified: `tests/test_agent_tool_config.py` (pure-function coverage, plus a
DB-backed test proving `load_tool_config` is scoped per organization),
additions to `tests/test_agent_permissions.py`, and integration tests in
`tests/test_agent_api.py` — a `PUT`/`GET` round trip, `PUT` rejecting a
lowering override with `422`, disabling a tool refusing even the
organization's own `OWNER` on a direct call with `403`.
`tests/security/test_authorization_matrix.py` extended for both new routes.

## The pentest module's exploitation tier: a dual-control gate

The exploitation tier (`TestDepth.EXPLOITATION`) is simulate-then-fire: an
ordinary run only ever emits an eligibility marker (`KERVY-PENTEST-108`);
firing a real exploit — a live `nmap -Pn --script <exploit>` invocation — is
a separate, deliberate action, gated by its own `ExploitationAuthorization`
(`docs/authorization-and-scope.md`) and, as of this section, by a second
human.

**One person holding `Role.SECURITY_ENGINEER` was never meant to be
sufficient to both decide a real exploit should run and be the one whose
click ran it**, given the blast radius a live exploit carries — closer to a
missing control than an accepted trade-off, and found by re-reading the
exploitation tier's own stated deferrals rather than by a new report.
`request_fire` now creates every fire `AWAITING_APPROVAL`, never `QUEUED`,
so `POST .../exploitation-fires` no longer dispatches the worker itself.
`approve_fire` (`app/core/pentest/exploitation_service.py`) is where dual
control actually lives: it refuses with `409` if the approver is the same
person as the requester — the one check that makes "a second approver" mean
a second *person*, not a second click by the same one. `reject_fire` carries
no such restriction, deliberately: calling off a live exploit is the safe
direction dual control does not need to slow down.

**The three-allowlist gate runs three times, not once — at request, at
approval, and again inside the worker task immediately before the real
`nmap` invocation.** Never trust that an earlier check is still true later,
the same reasoning `GatedTransport` re-resolves DNS per request rather than
trusting an earlier resolution. An authorization can expire, or an operator
can narrow the allowlist, in whatever time a fire sits awaiting approval; the
worker re-checks the dual-control invariant itself too, rather than trusting
that the API route only ever dispatches it after `approve_fire` ran.

New endpoints on `app/api/v1/routers/runs.py`:
`POST .../exploitation-fires/{fire_id}/approve` and `.../reject`, both
`Role.SECURITY_ENGINEER` — the second approver needs to be at least as
senior as the first, not a lower bar. No configurable approver list or
four-eyes-per-target policy: any `SECURITY_ENGINEER`-or-above who did not
request the fire may approve it, the same flat role check every other
sensitive action on this platform uses.

Verified: `tests/test_pentest_exploitation.py`'s dual-control section — a
created fire is `awaiting_approval` and never self-queued; the requester's
own approve attempt is refused with `409`; a second, distinct
`SECURITY_ENGINEER` approving moves it to `queued` and dispatches the worker
task; approving an already-approved fire is refused; an analyst cannot
approve; rejecting records the reason and moves it to `rejected`. Both new
routes are in `tests/security/test_authorization_matrix.py`'s pinned table.

## Cross-engine duplicate linking is human-verified, never automatic

"No cross-engine deduplication" was a stated, honest gap since the AppSec
engine's earliest phase: a SAST finding and a DAST finding describing the
same underlying defect get different `probe_id` prefixes and therefore
different fingerprints (`app/core/findings/fingerprint.py` hashes
`probe_id + surface + evidence signature`), so they have always been two
separate `Finding` rows, inflating counts. **Closing it did not mean
building a similarity heuristic** — that was explicitly rejected earlier as
something that "would be worse than the honest gap," and nothing about that
reasoning changed. It means giving a human a structural way to record a
judgment they were already making informally.

`Finding` gains `duplicate_of_finding_id` (nullable, self-referential FK,
`ondelete="SET NULL"`), `duplicate_note`, `duplicate_linked_by_user_id` and
`duplicate_linked_at`. The column is written only by a human's explicit
say-so through `app/core/findings/service.py::link_duplicate` — never
inferred. `AIService.correlate_findings()` still only offers a read-only,
AI-drafted correlation *suggestion*; nothing was changed to let that
suggestion write to this column, and closing the loop from suggestion to
structural link is explicitly not what this did.

**Kept two levels deep by construction, not by walking a graph.**
`link_duplicate` refuses a self-link, refuses linking to a finding that is
itself already a duplicate of something else (no chains), and refuses
making a finding a duplicate of anything once other findings already point
at it as their primary (no finding is ever both a primary and a duplicate).
`unlink_duplicate` carries no such restriction, the safe direction.

**The fix reaches every reader of the findings count the same way.**
`GET .../findings` gained `include_duplicates: bool = Query(default=False)`
— a linked duplicate drops out of the default listing the same way it drops
out of `build_report`'s own findings-by-severity section
(`Finding.duplicate_of_finding_id.is_(None)`, `app/core/reporting/build.py`).
Both defaults are backward compatible: no finding had this column set before
this shipped, so every existing caller sees exactly what it always did until
an analyst starts linking duplicates. The one place this fix does *not*
reach is a PR check run — see the gap table above and `docs/pull-requests.md`.

New `POST`/`DELETE .../findings/{finding_id}/duplicate` (`Role.ANALYST`, the
same tier that already changes a finding's lifecycle status) and
`GET .../findings/{finding_id}/duplicates` (`Role.VIEWER`).

Verified: new tests in `tests/test_findings_api.py`, run against real
findings promoted from a real vulnerable-lab scan rather than fabricated
rows — linking a duplicate removes it from the default list and total count,
`include_duplicates=true` still shows it, unlinking restores it, self-linking
is refused, both two-level-only directions are refused, a viewer is refused
and an analyst is not, and a linked duplicate is excluded from a run's own
JSON report with the finding count dropping by one. Both new routes are in
`tests/security/test_authorization_matrix.py`'s pinned table.

