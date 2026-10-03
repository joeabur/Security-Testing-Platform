# Dynamic application security testing

DAST is the first engine here that **discovers its own targets**. Every other
engine works from something a human supplied — an OpenAPI document, a declared
adapter, a checkout path. A crawler follows links, which means the set of URLs
it might request is chosen by the application under test rather than by the
operator. That inverts the usual trust relationship, and the design follows from
it.

It runs only for `kind: web_app`. Not for every HTTP target: turning a crawler
loose on an API or an LLM app whose owner authorized a bounded, spec-driven
assessment would widen the scan past what they agreed to. Declaring the kind is
how an operator says "this is a site, crawl it".

## A discovered URL is checked before it is queued

The obvious implementation satisfies the requirement by accident: queue
everything, and let `GatedTransport` refuse the bad ones when their turn comes.
This platform deliberately does not, for three reasons.

**A queue of out-of-scope URLs is itself a defect.** It means the crawl's own
state holds a list of places the engagement does not cover. Anything that later
iterates it — a retry, a progress display, a debug log, a future adapter handed
"the discovered URLs" — reaches them.

**"It would have been refused later" is not a testable control.** A test
asserting no out-of-scope *request* was made passes equally whether the check
happens early or late. A test asserting no out-of-scope URL was ever *queued*
only passes when it happens early. So that is what `tests/test_dast.py` asserts,
and the assertion was verified by weakening the check and watching it fail.

**Budget is finite.** A crawl of a site linking to a thousand external URLs
should not spend its request budget discovering they are all out of scope.

The pre-queue check is an *additional* gate, never a replacement. Everything
that reaches the network still goes through `GatedTransport`, so a host that
passed at queue time and then rebinds is still refused at send time.

## Refused, deferred, and unvisited

Three different things, kept apart because conflating them misreports coverage:

| | Meaning | Where it lands |
|---|---|---|
| **Refused** | Out of scope. Not ever. | `refused`, reported as `KERVY-DAST-001` |
| **Deferred** | In scope, but budget ran out or the run halted | queued, then `unvisited` |
| **Unvisited** | In scope, queued, never fetched | `unvisited`, reported as `KERVY-DAST-009` |

Budget says "not now"; scope says "not ever". Filing an in-scope URL under
`refused` would tell a reader the engagement did not cover it, which is a
different and wrong claim.

## Bounds

| Bound | Default | Why |
|---|---|---|
| `max_pages` | 200 | A crawl is reconnaissance, not enumeration |
| `max_depth` | 5 | |
| `max_links_per_page` | 100 | A page with 10,000 links is a trap |
| `max_body_bytes` | 2 MiB parsed | A 200 MB file is fetched but not parsed |
| request budget | from the RoE | The rate the target's owner agreed to |

Link extraction uses a bounded regex, not an HTML parser. The input is an
adversarial response body, and a regex over a bounded prefix cannot be made to
allocate unboundedly or recurse the way a lenient DOM parser can. It misses
links a browser would find — JavaScript-built URLs especially — and that is a
stated limitation rather than a hidden one.

URLs are normalized before comparison: fragment dropped, host lowercased,
`mailto:`/`javascript:`/`data:`/`tel:` dropped, userinfo refused outright,
static asset extensions skipped. Without this, `/a`, `/a#x` and `/a?` are three
queue entries and three requests for one page.

## State mutation

`allow_state_mutation` lives on the rules of engagement, defaults to **false**,
and is separate from `safe_mode` on purpose: safe mode bounds how a probe
behaves, this decides whether state-changing tooling may run at all.

**The crawler never submits a form**, under either setting. It records form
actions (`KERVY-DAST-002`) because their existence is useful to a reviewer, and
issues `GET` only — a test greps the module to confirm there is no code path
sending anything else.

What the flag controls is the tool policy:

| | `false` (default) | `true` |
|---|---|---|
| Nuclei tags | passive/detection only | plus `intrusive`, `rce`, `sqli`, `injection`, `traversal`, … |
| ZAP script | `zap-baseline.py` (passive) | `zap-full-scan.py` (active) |
| Finding says | `passive` mode | `active` mode |

**Out-of-band callback templates are excluded either way.** An `interactsh`,
`oast` or `blind` template makes the target contact a third-party server the
engagement never authorized — an egress path the scope engine cannot see.
Enabling it needs a collaborator the operator controls, which is not built.
`-no-interactsh` is passed as well as the tag exclusion, so it is not a single
point of failure.

## The tool adapters, and their honest limits

**Neither Nuclei nor ZAP is routed through `GatedTransport`** — it only wraps
`httpx`, and both tools are subprocesses that open their own sockets. Both are
instead pointed at a per-run `EgressGateway`
(`app/core/dast/egress_proxy.py`), a local proxy that re-resolves DNS and
re-checks every destination either tool connects to against this run's rules
of engagement immediately before the connection is allowed. `docs/egress-security.md`
has the full model, including what the gateway cannot see inside an
established HTTPS tunnel (method, path, headers) — only the domain
allowlist and the private/loopback/link-local/metadata/CIDR IP-blocking
rules apply there. This closes the DNS-rebinding/SSRF gap that existed when
neither tool's own connections were checked at all; it is still a narrower
guarantee than the crawler's full request-shape check, and that narrowing is
recorded rather than glossed over.

*Nuclei* is given explicit `-target` entries — URLs that have each already been
through the scope engine at crawl time — rather than being allowed to discover
more. It runs with `-disable-update-check` (offline, so the scan uses the
template set that was reviewed) and a `-rate-limit` taken from the RoE budget.

*ZAP* spiders on its own; every connection it makes while doing so, not only
the seed, now goes through the egress gateway. As an independent, second
safeguard it still runs **only when the rules of engagement name exactly one
concrete host**, and declines with a visible `not tested` marker otherwise —
kept rather than relaxed, since the gateway's HTTPS path cannot see the
method or path ZAP sends inside the tunnel, only the host it connects to. Its
JSON report is written to a temporary directory and removed: the report contains
response excerpts from the target, and leaving it on the worker would put
unredacted target data somewhere nothing manages.

Every Nuclei and ZAP identifier is shape-verified before it reaches a finding.
A template's `classification` block is frequently absent or malformed, and an
identifier that had to be repaired is one the tool did not actually report.

## Findings

| Code | Meaning |
|---|---|
| `KERVY-DAST-001` | The application links outside the rules of engagement |
| `KERVY-DAST-002` | State-changing forms found and not submitted |
| `KERVY-DAST-009` | **Not tested** — the crawl stopped at a bound |
| `KERVY-DAST-<template>` | A Nuclei template matched |
| `KERVY-DAST-ZAP-<rule>` | A ZAP rule matched |
| `KERVY-APPSEC-000` | A tool did not run, naming which |
| `KERVY-DAST-099` | The engine raised |

`KERVY-DAST-001` is not a vulnerability and does not claim to be — nothing was
sent to those URLs. It is reported because an application linking outside the
engagement is worth a human's attention: a third-party tracker nobody authorized
testing of, or a sign the authorization covers less than the application spans.

## The lab

`demo-target/lab/web_app/` exists to exercise all of this: two `.invalid`
off-site links (RFC 2606, never resolves, so even total failure of the control
reaches nothing real), a destructive form, a link loop, a nine-deep chain, and a
reflected-input page. `tests/test_dast_e2e.py` runs the engine against it over a
real socket.

```bash
cd demo-target && LAB_HOST=127.0.0.1 python -m lab.main web-app --port 8084
```

Under compose it is the `lab-web-app` service in the `demo` profile, on the same
`internal: true` network as the rest of the lab — no gateway, no published
ports, read-only filesystem, all capabilities dropped.

## What is not built

- **No JavaScript.** No headless browser, so a single-page application's routes
  are invisible to the crawler. This is the largest gap.
- **No authenticated crawling.** No login sequence, no session handling, so
  anything behind a login is not reached.
- **No form submission at all**, even with `allow_state_mutation` — the flag
  opens the tool policy, not the crawler's behaviour.
- **Neither scanner is scope-gated at the socket**, per above.
- **No ZAP daemon mode**, so no context configuration or session reuse. The
  one-shot script keeps the surface small; the trade is less control.
- **Nuclei and ZAP are not installed in CI**, so their parsing is exercised
  against fixtures and their absence against the `not tested` path. Nothing in
  CI runs a real scanner against a real site.
- **No API-aware DAST.** The API engine covers that from the OpenAPI document.
