"""ZAP adapter — baseline (passive) or full (active) scan.

The choice between the two is the whole of this module's security content, and
it is not the caller's to make: `zap_scan_mode` derives it from
`allow_state_mutation`.

* **Baseline** spiders the application and applies ZAP's *passive* rules. It
  observes what the application already returns.
* **Full** additionally runs the *active* rules, which submit forms and send
  attack payloads. That changes state by definition, so it needs an
  authorization that said state may change.

ZAP is invoked through its packaged scan scripts rather than the daemon REST
API. The daemon would let this platform configure a context and reuse a session,
which is nicer — but it also means a long-lived process holding the target's
cookies, and a second HTTP client inside the worker talking to it. The one-shot
script keeps the surface small. `docs/dast.md` records the trade.

**ZAP is not routed through `GatedTransport`** — `GatedTransport` only wraps
`httpx`, and ZAP is a subprocess that opens its own sockets and spiders on its
own. Every connection it makes is now pointed at
`app.core.dast.egress_proxy.EgressGateway` via ZAP's own
`network.connection.httpProxy.*` configuration, which re-resolves DNS and
re-checks each destination's host and IP against this run's rules of
engagement immediately before ZAP is allowed to connect — including
connections to pages ZAP discovers on its own while spidering, not only the
seed. See `docs/egress-security.md` for exactly what that gateway does and
does not see (it cannot inspect method/path/headers inside an HTTPS tunnel,
so path/header-level rules of engagement still do not apply to ZAP's
traffic). The engine still only runs ZAP when the rules of engagement allow
exactly one host, and says so in the finding — kept as an independent,
second safeguard rather than relaxed now that the gateway exists, since the
two controls check different things (which *host* ZAP may reach as a
single named engagement, versus whether *any* individual connection it
makes resolves to somewhere it shouldn't).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from app.core.appsec.contract import EngineMeta, Pillar, tool_unavailable
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.dast.policy import ToolPolicy, zap_scan_mode
from app.core.probes.models import Category, Confidence, ScanResult, Severity

ZAP_TIMEOUT_SECONDS = 1800

#: ZAP's own risk vocabulary.
_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}

META = EngineMeta(
    id="dast.zap",
    version="1.0.0",
    name="OWASP ZAP (baseline/full scan)",
    pillar=Pillar.DAST,
    tool="zap-baseline.py",
    description=(
        "Spiders and tests a web application. Active rules run only when the "
        "rules of engagement allow state mutation."
    ),
)


def binary_for(policy: ToolPolicy) -> str:
    """`zap-baseline.py` or `zap-full-scan.py`.

    Two different binaries rather than a flag, because that is how ZAP ships
    them — and it means the active scan cannot be reached by a typo in an
    argument.
    """
    return "zap-full-scan.py" if zap_scan_mode(policy) == "full" else "zap-baseline.py"


def command_for(
    policy: ToolPolicy, seed: str, report_path: str, *, proxy_url: str | None = None
) -> tuple[str, ...]:
    """The exact command line, extracted so a test can assert on it."""
    zap_config = "-config api.disablekey=true"
    if proxy_url:
        # Every connection ZAP makes — the seed, and anything it spiders to
        # on its own — now goes through the scope-checking egress gateway
        # instead of straight to the network.
        proxy = urlsplit(proxy_url)
        zap_config += (
            f" -config network.connection.httpProxy.host={proxy.hostname}"
            f" -config network.connection.httpProxy.port={proxy.port}"
            " -config network.connection.httpProxy.enabled=true"
        )
    return (
        binary_for(policy),
        "-t",
        seed,
        "-J",
        report_path,
        # Short spider and passive-scan windows: this is reconnaissance inside a
        # budgeted assessment, not an overnight scan.
        "-m",
        "5",
        # No automatic framework/technology add-on installation: the scan must
        # use the rule set that was reviewed.
        "-z",
        zap_config,
    )


def single_allowed_host(allowed_domains: tuple[str, ...]) -> str | None:
    """The one host ZAP may be pointed at, or `None`.

    ZAP spiders on its own, outside the scope engine's view. If the rules of
    engagement name more than one host — or a wildcard — this platform cannot
    bound where ZAP goes, so it declines to run rather than hoping.
    """
    concrete = [domain for domain in allowed_domains if "*" not in domain]
    if len(allowed_domains) != 1 or len(concrete) != 1:
        return None
    return concrete[0]


def _finding(alert: dict[str, Any], policy: ToolPolicy, seed: str) -> ScanResult | None:
    plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or "").strip()
    name = str(alert.get("name") or alert.get("alert") or "").strip()
    if not plugin_id or not name:
        return None

    instances = alert.get("instances")
    first = instances[0] if isinstance(instances, list) and instances else {}
    uri = str(first.get("uri") or seed) if isinstance(first, dict) else seed
    cwe = str(alert.get("cweid") or "").strip()

    return ScanResult(
        id=f"KERVY-DAST-ZAP-{plugin_id}",
        title=f"{name} at {uri}",
        category=Category.API_SECURITY,
        severity=_SEVERITY.get(
            str(alert.get("riskdesc") or alert.get("risk") or "").split(" ")[0].lower(),
            Severity.INFORMATIONAL,
        ),
        # ZAP reports its own confidence; a passive match is not an exploit.
        confidence=Confidence.MEDIUM
        if str(alert.get("confidence") or "").lower() in ("low", "1")
        else Confidence.HIGH,
        endpoint=uri,
        description=(
            _text(alert.get("desc"))[:1000]
            + f"\n\nReported by ZAP rule {plugin_id} in {zap_scan_mode(policy)} mode."
        ),
        evidence=(
            f"rule: {plugin_id} ({name})\nuri: {uri}\n"
            f"risk: {alert.get('riskdesc')}\nconfidence: {alert.get('confidence')}\n"
            f"mode: {zap_scan_mode(policy)}"
        ),
        impact=_text(alert.get("desc"))[:400]
        or "As described by the ZAP rule. Exploitability was not established.",
        remediation=_text(alert.get("solution"))[:1000]
        or "Follow the referenced ZAP rule's guidance.",
        probe_id=META.id,
        probe_version=META.version,
        frameworks=(f"CWE-{cwe}",) if cwe.isdigit() and cwe != "0" else (),
        reproduction=(
            f"Run: {binary_for(policy)} -t {seed}",
            f"Observe rule {plugin_id} reported at {uri}.",
        ),
        fingerprint="sha256:" + hashlib.sha256(f"zap|{plugin_id}|{uri}".encode()).hexdigest(),
    )


def _text(value: object) -> str:
    """ZAP's JSON wraps descriptions in HTML paragraphs."""
    import re

    return re.sub(r"<[^>]{0,200}>", "", str(value or "")).strip()


def parse_report(payload: dict[str, Any], policy: ToolPolicy, seed: str) -> list[ScanResult]:
    findings: list[ScanResult] = []
    seen: set[str] = set()
    for site in payload.get("site") or []:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            finding = _finding(alert, policy, seed)
            if finding is None or finding.fingerprint in seen:
                continue
            seen.add(str(finding.fingerprint))
            findings.append(finding)
    return findings


async def run_zap(
    seed: str,
    policy: ToolPolicy,
    *,
    allowed_domains: tuple[str, ...],
    proxy_url: str | None = None,
) -> list[ScanResult]:
    """Run ZAP against one seed, or report why it did not run.

    `proxy_url` is the local address of this run's
    `app.core.dast.egress_proxy.EgressGateway`. Passed by the caller rather
    than constructed here, so this function stays a pure "build the command,
    run it, parse the output" adapter and does not itself own the gateway's
    lifecycle.
    """
    host = single_allowed_host(allowed_domains)
    if host is None:
        return [
            tool_unavailable(
                META,
                "ZAP spiders outside the scope engine's view, so it runs only when the "
                "rules of engagement name exactly one concrete host. These name "
                f"{len(allowed_domains)}: {', '.join(allowed_domains) or 'none'}.",
            )
        ]
    if (urlsplit(seed).hostname or "").lower() != host.lower():
        return [
            tool_unavailable(
                META,
                f"the seed URL's host does not match the single allowed host {host!r}",
            )
        ]

    import tempfile
    from pathlib import Path

    # A temporary directory, so the report cannot be left behind on the worker.
    # ZAP's JSON report contains response excerpts from the target; leaving it on
    # disk outside the evidence store would put unredacted target data somewhere
    # nothing manages.
    with tempfile.TemporaryDirectory(prefix="kervy-zap-") as workdir:
        report = Path(workdir) / "zap.json"
        result = await run_tool(
            ToolInvocation(
                command=command_for(policy, seed, str(report), proxy_url=proxy_url),
                cwd=Path(workdir),
                network=NetworkUse.DECLARED_SERVICE,
                timeout_seconds=ZAP_TIMEOUT_SECONDS,
            )
        )
        if not result.ran:
            return [tool_unavailable(META, result.reason or "zap did not run")]
        try:
            raw = report.read_text(encoding="utf-8") if report.exists() else ""
        except OSError as exc:
            return [tool_unavailable(META, f"could not read the zap report: {exc}")]

    try:
        payload = json.loads(raw or "{}")
    except ValueError as exc:
        return [tool_unavailable(META, f"zap output was not JSON: {exc}")]
    if not isinstance(payload, dict):
        return [tool_unavailable(META, "zap report was not a JSON object")]
    return parse_report(payload, policy, seed)
