# Egress security: GatedTransport and the DAST egress gateway

This platform has exactly one rule for outbound network traffic: nothing
leaves a run's process without being checked against that run's
`RulesOfEngagement` first, with DNS re-resolved immediately before the
check so a result can't be stale by the time the connection happens. Two
mechanisms enforce that rule today, because two different kinds of outbound
traffic exist in this codebase.

## `GatedTransport` — every `httpx` call

`app/core/scope/transport.py` is the only place in `app/` allowed to
construct an `httpx.Client`/`httpx.AsyncClient`. A static test,
`tests/security/test_no_ungated_httpx_client_construction_outside_transport`
in `tests/security/test_scope_controls.py`, greps every `.py` file under
`app/` for that construction and fails the build on any hit outside
`transport.py` (one pinned exception for the SMTP integration, which isn't
`httpx`-based). Every outbound request from the API, a Celery worker, a
probe, or the CLI goes through `GatedTransport.send()`, which:

1. Calls `ScopeEngine.check()` — domain allowlist/exclusion, path/method/
   header rules, and a **fresh DNS resolution** of the hostname, checked
   against the private/loopback/link-local/metadata/CIDR blocking rules in
   `app/core/scope/hostmatch.py`. DNS is never cached
   (`app/core/scope/dns.py`'s `SystemDnsResolver` resolves on every call),
   specifically so a host that rebinds between two requests in the same run
   is caught on the second one, not trusted because it was fine on the
   first.
2. Refuses to send if the check denies, raising `ScopeBlockedError` rather
   than silently skipping.
3. Never auto-follows a redirect. A 3xx `Location` header is re-run through
   the same domain/IP check (`check_redirect_target`) before it is reported
   back to the caller — a redirect to an out-of-scope or rebound host is
   refused, not followed.
4. Blocks the cloud metadata endpoints (`169.254.169.254`,
   `fd00:ec2::254`) unconditionally — unlike the private/loopback ranges,
   no `allowed_ip_ranges` entry can re-enable them. The private ranges are
   overridable because reaching one is a legitimate thing to authorize (an
   internal staging host, the demo lab's own Docker network); the metadata
   endpoint is not a target, it is the thing that hands out this
   platform's own host's credentials, and leaving it behind a
   configuration flag means one mistyped allowlist is the difference
   between a scan and a credential theft.

This is airtight for anything using `httpx`. It is not airtight for a tool
that makes its own network calls from outside the Python process.

## `EgressGateway` — Nuclei and ZAP

Nuclei and ZAP are launched as OS subprocesses
(`app/core/appsec/tooling.py`, `asyncio.create_subprocess_exec`). Once
either binary starts, it performs its own DNS resolution and opens its own
TCP sockets — `GatedTransport` cannot see or constrain that traffic at all,
because `GatedTransport` only wraps `httpx` calls made from inside this
process. Historically (`docs/dast.md`, `docs/security-review.md`'s Phase 15
section) this was a stated, honest gap: a host that cleared the scope
engine when the crawler checked it could rebind to a private IP or the
cloud metadata endpoint by the time the scanner actually connected minutes
later, and the scanner would follow it with nothing in the way.

`app/core/dast/egress_proxy.py`'s `EgressGateway` closes that gap the way a
corporate TLS-forward-proxy would, reusing the scope engine's own
hostname/IP logic rather than re-implementing it:

```
Authorization → Scope (RulesOfEngagement) → EgressGateway → Nuclei / ZAP
                                                 │
                                   fresh DNS resolve + re-check
                                   on every CONNECT, independently
```

- `DastEngine.run()` starts one `EgressGateway` per run, bound to
  `127.0.0.1` on an OS-assigned port, for the duration of the Nuclei and
  ZAP calls, and stops it afterward.
- Nuclei is pointed at it with `-proxy <url>`; ZAP is pointed at it with
  `-config network.connection.httpProxy.{host,port,enabled}` appended to
  its existing `-z` configuration string.
- Every `CONNECT` (for HTTPS) or absolute-URI request (for plain HTTP) the
  tool sends is held at the gateway while it:
  1. Checks the host against `excluded_domains` and `allowed_domains`.
  2. Resolves DNS fresh — no caching, same reasoning as `SystemDnsResolver`.
  3. Checks every resolved address against the same
     private/loopback/link-local/metadata/CIDR rules `GatedTransport` uses
     (`app/core/scope/hostmatch.py`, imported and called directly — not
     reimplemented).
  4. On success, connects to the **exact IP address that was just
     checked**, not to the hostname again — so nothing can rebind between
     the check and the connection.
  5. On failure, returns `403` and never opens an upstream connection at
     all.
- A redirect, or a link ZAP's own spider discovers, that points at a
  *different* host triggers its own fresh `CONNECT` through the same
  gateway, which is independently checked — a scanner cannot pivot to an
  unauthorized host mid-run.

### What this does not do, stated as plainly as the gap it replaces

**It cannot see inside an HTTPS tunnel.** Once a `CONNECT` is approved, the
gateway relays opaque encrypted bytes between the scanner and the real
target — that is what lets it avoid terminating TLS itself. It therefore
cannot enforce `allowed_paths`, `excluded_paths`, `allowed_methods`, or
`forbidden_headers` against HTTPS traffic; only the domain allowlist and
the IP-blocking rules apply there. Enforcing path/method/header rules too
would require intercepting the TLS connection with a locally-trusted CA and
a certificate generated per target — a materially larger, and separately
risky, change that was deliberately not made as part of closing the
socket-level SSRF/rebinding gap. Plain HTTP (non-TLS) requests through the
gateway *are* fully visible, since no tunnel is established for them.

**It does not reserve budget.** `BudgetTracker` (`app/core/scope/budgets.py`)
was designed around accounting for one request at a time from this
process; an opaque third-party tool's full request stream was never its
target use case. Nuclei's own `-rate-limit` and ZAP's own scan-window
flags (`-m 5` — a short spider/passive window) already bound how much
traffic either tool generates, which is the mitigation this platform
relies on here instead.

**ZAP's single-host restriction stays, independently.** `zap.py`'s
`single_allowed_host()` still refuses to run ZAP unless the rules of
engagement name exactly one concrete host, even though the gateway's own
domain-allowlist check now also constrains where ZAP can connect while
spidering. The two checks test different things — "may this engagement
touch more than one host at all" versus "does this one connection resolve
somewhere it shouldn't" — and relaxing a tested restriction in the same
change that adds a new, narrower-scoped one is avoided on purpose.

### Why a local proxy, not TLS interception or a sandbox

Three alternatives were available and rejected for being a larger, riskier
change than the problem needed:

- **TLS interception** (MITM with a locally-trusted CA) would let the
  gateway enforce path/method/header rules against HTTPS traffic too, at
  the cost of generating and trusting a certificate authority inside the
  platform's own infrastructure and re-signing every target's certificate
  on the fly — a supply-chain and key-management surface this platform
  does not currently have, and should not acquire just to close a
  DNS-rebinding gap that doesn't need it.
- **A network namespace or firewall rule per run** would need root/CAP_NET
  privileges in the worker container and platform-specific plumbing
  (`iptables`/`nftables`/network namespaces aren't portable across every
  deployment target this platform supports). A userspace proxy needs
  neither.
- **Patching Nuclei or ZAP's own source** would mean carrying a fork of two
  actively-developed third-party tools. Both already support pointing at a
  proxy through ordinary, documented flags, so no fork is needed.

### Verification

`backend/tests/test_dast_egress_proxy.py` runs the gateway as a real local
TCP server — no mocked sockets — and proves: an allowlisted, resolvable
host is tunneled and relays real bytes end to end; a non-allowlisted
domain is refused with the upstream connection never attempted; a host
that resolves to a private IP is refused; the metadata endpoint is refused
even under a wide-open `allowed_ip_ranges`; the *same* host checked twice
with a different DNS answer the second time is refused on the second
check (proving there is no gateway-level cache papering over a rebind); a
second, different host in the same run is checked independently of the
first; and a halted run or a tripped kill switch refuses every connection
immediately without even reaching the host check. Separate tests pin the
exact `-proxy` / `network.connection.httpProxy.*` command-line flags Nuclei
and ZAP receive, and that `DastEngine.run()` starts exactly one gateway per
run and hands the same `proxy_url` to both tools.
