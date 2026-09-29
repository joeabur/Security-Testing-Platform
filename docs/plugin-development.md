# Writing an Kervy plugin

> `docs/BUILD_SPEC.md` §16 is the contract; this page is how to satisfy it.

## What a plugin is, and what it is not

A plugin is Python code that runs **inside the Kervy worker process**. There is
no sandbox, and this project does not claim one. A plugin can import anything,
open a socket, and read the filesystem — exactly like any other package in the
environment.

What the platform does guarantee is narrower, and real:

- **Nothing loads unless an operator named it.** Discovery is off by default
  and every package has to be listed in `plugins.allowlist`.
- **The contract offers no ungated route to a target.** Your probe receives a
  `PluginContext` carrying the run context and a `GatedTransport`. Requests
  made through it are scope-checked against the target's Rules of Engagement,
  counted against the run's budget, and cancellable. There is no attribute on
  either object that hands back a raw HTTP client.
- **Invalid metadata fails loudly at load.** A probe whose results cannot be
  attributed to an id and a version is worse than a probe that is absent.

If you import `httpx` and make your own request, nothing stops you — you are
untrusted code doing untrusted things, and the allowlist is the control that
was supposed to prevent that from mattering. Do not do it: a finding produced
outside the scope engine is a finding produced against a host nobody
authorized, which is the one thing this platform exists to prevent.

## The interface

```python
class SecurityTest:
    id: str
    name: str
    category: str

    async def run(self, target, context): ...
```

- `id` — stable, namespaced to you (`example.header_reflection`). It becomes
  the `probe_id` on every finding you produce, and it is what an operator will
  search for.
- `category` — one of the platform's categories, as a string. Validated at
  load; an unknown value is refused.
- `run` — returns a list of `ScanResult`. The findings service adds the
  fingerprint, the risk score, the lifecycle and the mapping versions; you do
  not compute those.

`target` is a `ProbeTarget`: the base URL, the operations the operator left
enabled, and whether safe mode is on. You never see an endpoint the operator
disabled.

`context` is a `PluginContext`: `ctx` (the run context — check
`ctx.halted` and `ctx.kill_switch.tripped` in any loop), `transport`, and
`safe_mode`.

## A complete example

This is a working probe, and it is the file `backend/tests/plugins/example_probe.py`
in this repository — a test asserts that the code below and that file are
identical, so what you are reading cannot drift from what actually runs.

```python
"""An example Kervy probe plugin.

Reports endpoints that reflect an arbitrary request header back to the caller.
Reflection is not itself a vulnerability, but it is the primitive behind
cache-poisoning and header-injection bugs, and it is cheap to check.
"""

import secrets

from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.probes.protocol import ProbeTarget
from app.core.scope.transport import ScopeBlockedError
from app.plugins.contract import PluginContext


class HeaderReflectionProbe:
    """One check, using the simplified interface from BUILD_SPEC §16."""

    id = "example.header_reflection"
    name = "Request header reflected in the response"
    category = Category.API_SECURITY.value

    HEADER = "X-Kervy-Example"

    async def run(self, target: ProbeTarget, context: PluginContext) -> list[ScanResult]:
        # A fresh marker per run, so a reflection found here cannot be a stale
        # value cached from an earlier assessment.
        marker = "kervy-" + secrets.token_hex(8)
        findings: list[ScanResult] = []

        for operation in target.operations:
            if operation.method != "GET":
                continue
            if context.ctx.halted or context.ctx.kill_switch.tripped:
                break

            url = target.base_url.rstrip("/") + "/" + operation.path.lstrip("/")
            try:
                # The only way out. `context.transport` is already gated: this
                # request is scope-checked, budget-counted and cancellable, and
                # there is no other route to the network in the contract.
                observation = await context.transport.send(
                    context.ctx, method="GET", url=url, headers={self.HEADER: marker}
                )
            except ScopeBlockedError:
                # The scope engine refused. Not a finding, and not something a
                # plugin should work around.
                continue
            except Exception:  # noqa: BLE001 - an unreachable endpoint is not a finding
                continue

            reflected_in = [name for name, value in observation.headers.items() if marker in value]
            if marker in observation.body.decode("utf-8", errors="replace"):
                reflected_in.append("response body")
            if not reflected_in:
                continue

            findings.append(
                ScanResult(
                    id="EXAMPLE-001",
                    title="Request header is reflected in the response",
                    category=Category.API_SECURITY,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    endpoint=f"{operation.method} {operation.path}",
                    description=(
                        f"{self.HEADER} was sent with a random value and came back in "
                        f"{', '.join(reflected_in)}. Reflected input is the primitive "
                        "behind cache poisoning and header injection."
                    ),
                    evidence=f"GET {url} -> HTTP {observation.status_code}; reflected in "
                    f"{', '.join(reflected_in)}",
                    impact=(
                        "Where a reflected value reaches a cache key or another header, "
                        "it becomes a way to influence what other clients receive."
                    ),
                    remediation=(
                        "Do not copy request headers into responses. Where a value must "
                        "be echoed, allowlist which headers and validate them."
                    ),
                    probe_id=self.id,
                    probe_version="1.0.0",
                    frameworks=("OWASP-API-2023:API8", "CWE-113"),
                    reproduction=(
                        f"Send GET {url} with {self.HEADER}: <random value>.",
                        f"Observe the value returned in {', '.join(reflected_in)}.",
                    ),
                )
            )
        return findings
```

## Packaging it

```toml
# pyproject.toml
[project]
name = "kervy-plugin-example"
version = "0.1.0"
dependencies = ["kervy-security-backend"]

[project.entry-points."kervy.probes"]
header-reflection = "kervy_plugin_example:HeaderReflectionProbe"
```

The four groups from §16:

| Group | For |
|---|---|
| `kervy.probes` | checks that produce findings |
| `kervy.detectors` | verdicts on an observation |
| `kervy.adapters` | ways to reach a target, or third-party tool wrappers |
| `kervy.reporters` | additional report formats |

Only `kervy.probes` is wired into a run today; the other three are discovered
and listed but nothing consumes them yet. `docs/roadmap.md` says so rather
than leaving you to find out.

## Allowing it to load

```yaml
# plugins.yaml, pointed at by PLUGINS_CONFIG
plugins:
  enabled: true
  allowlist:
    - name: kervy-plugin-example
      sha256: 3f786850e387550fdab836ed7e6dc881de23001b…   # optional
```

- A name-only entry trusts the package by name. That is weaker, and it is a
  legitimate choice — it is documented rather than forbidden.
- A `sha256` pins the installed build. It is a digest over the distribution's
  `RECORD`, so a package silently replaced after you pinned it is refused.
  Get it with:

  ```bash
  python -c "from app.plugins.allowlist import distribution_hash; \
      print(distribution_hash('kervy-plugin-example'))"
  ```

- `KERVY_NO_PLUGINS=1` turns discovery off regardless of any configuration.
  When something has gone wrong there should be exactly one thing to set.

Every run that loads a plugin records a banner in its own event log, and files
an informational `KERVY-PLUGIN-900` result naming what loaded — so a report
reader can see that non-native code contributed to it.

## Attribution is not yours to set

The platform overwrites `probe_id` and `probe_version` on everything you
return, with your plugin's own id and the installed version. A plugin cannot
file a finding under a native probe's name: an operator reading the report
would otherwise draw conclusions about code that never ran.

Anything you put in `evidence_bundle` is discarded for the same reason. The
contract gives you no way to build a sealed bundle, so a bundle arriving from a
plugin came from somewhere the platform cannot vouch for.

## Testing it

Your probe is an ordinary object; test it with a fake transport and a run
context, exactly as this repository tests its own probes
(`backend/tests/test_plugins.py` is the working example). Two things worth
asserting:

- your probe honours `ctx.halted`, so a cancelled run stops promptly;
- your probe treats `ScopeBlockedError` as "not tested", never as "clean".
