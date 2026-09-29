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
