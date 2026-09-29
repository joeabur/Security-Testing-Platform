"""Nuclei adapter — template-based detection against crawled URLs.

Nuclei is a subprocess, not a library, and the command line is the security
boundary: the tags, severities and flags below are what stop it doing something
the engagement did not authorize. So they are derived from `ToolPolicy`
(`policy.py`) and not passed in by a caller.

Four flags are load-bearing:

* `-exclude-tags` carries `NEVER_TAGS` on every run — out-of-band callback
  templates are excluded even when state mutation is allowed, because they make
  the target contact a server the engagement never authorized.
* `-no-interactsh` disables the out-of-band client entirely, so the exclusion
  above is belt and braces rather than a single point of failure.
* `-disable-update-check` keeps the run offline. Nuclei otherwise phones home
  and may fetch templates mid-run, which would mean the scan did not use the
  template set that was reviewed.
* `-duc` / rate limiting comes from the rules of engagement's budget, so a
  scanner cannot outrun the request rate the target's owner agreed to.

**Nuclei is not routed through `GatedTransport`.** It opens its own sockets, and
that is stated rather than glossed over: the URLs it is given have every one
been through the scope engine at crawl time, and it is invoked with `-target`
entries rather than being allowed to discover more. That is a weaker guarantee
than the crawler's and is recorded in `docs/dast.md` and
`docs/security-review.md`.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from app.core.appsec.contract import EngineMeta, Pillar, tool_unavailable
from app.core.appsec.identifiers import verified_advisories
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.dast.policy import ToolPolicy
from app.core.probes.models import Category, Confidence, ScanResult, Severity

NUCLEI_TIMEOUT_SECONDS = 900

#: How many crawled URLs are handed to one invocation. Bounded so the command
#: line cannot grow past the OS limit on a large crawl.
MAX_TARGETS = 200

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
    "unknown": Severity.INFORMATIONAL,
}

META = EngineMeta(
    id="dast.nuclei",
    version="1.0.0",
    name="Nuclei (template-based DAST)",
    pillar=Pillar.DAST,
    tool="nuclei",
    description=(
        "Runs Nuclei templates against URLs the crawler already cleared. "
        "Template set derived from the rules of engagement."
    ),
)


def command_for(policy: ToolPolicy, targets: Sequence[str], *, rate: int) -> tuple[str, ...]:
    """The exact command line, so a test can assert on it.

    Extracted rather than built inline because this command *is* the control: a
    test that checks the flags is checking the security property, and one that
    checks behaviour through a mocked subprocess is not.
    """
    command: list[str] = [
        "nuclei",
        "-jsonl",
        "-silent",
        # Offline: no template fetch, no version ping. The scan must use the
        # template set that was reviewed.
        "-disable-update-check",
        # Out-of-band client off entirely, on top of the tag exclusion.
        "-no-interactsh",
        "-severity",
        ",".join(policy.severities),
        "-tags",
        ",".join(policy.include_tags),
        "-exclude-tags",
        ",".join(policy.exclude_tags),
        # The target's owner agreed a request rate; a scanner does not get to
        # ignore it.
        "-rate-limit",
        str(max(1, rate)),
    ]
    for target in targets[:MAX_TARGETS]:
        command.extend(["-target", target])
    return tuple(command)


def _finding(entry: dict[str, Any], policy: ToolPolicy) -> ScanResult | None:
    raw_info = entry.get("info")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    template_id = str(entry.get("template-id") or entry.get("templateID") or "").strip()
    matched = str(entry.get("matched-at") or entry.get("host") or "").strip()
    if not template_id or not matched:
        # No rule id or no location means nothing a reader could act on or
        # verify, so it is dropped rather than reported as an unlocatable issue.
        return None

    severity = _SEVERITY.get(str(info.get("severity") or "unknown").lower(), Severity.INFORMATIONAL)
    name = str(info.get("name") or template_id)
    # Verified, not trusted: §28 forbids presenting an identifier that does not
    # have the shape of a real advisory. A template's `classification` block is
    # where nuclei puts CVEs, and it is frequently absent or malformed.
    raw_class = info.get("classification")
    classification: dict[str, Any] = raw_class if isinstance(raw_class, dict) else {}
    advisories = verified_advisories(classification.get("cve-id") or [])
    cwes = tuple(
        str(value)
        for value in (classification.get("cwe-id") or [])
        if str(value).upper().startswith("CWE-")
    )

    return ScanResult(
        id=f"KERVY-DAST-{template_id}",
        title=f"{name} at {matched}",
        category=Category.API_SECURITY,
        severity=severity,
        # Nuclei matched a response; it did not establish exploitability. HIGH
        # confidence in the match, which is a different claim from HIGH severity.
        confidence=Confidence.HIGH,
        endpoint=matched,
        description=(
            str(info.get("description") or name)[:1000]
            + f"\n\nReported by nuclei template {template_id!r} in {policy.mode} mode."
        ),
        evidence=(
            f"template: {template_id}\nmatched at: {matched}\n"
            f"severity (nuclei): {info.get('severity')}\n"
            f"mode: {policy.mode}\n"
            + (f"advisories: {', '.join(advisories)}\n" if advisories else "")
            + f"matcher: {entry.get('matcher-name') or entry.get('type') or 'n/a'}"
        ),
        impact=(
            "As described by the template. Exploitability was not established: "
            "nuclei matched a response pattern."
        ),
        remediation=str(info.get("remediation") or "").strip()
        or "Follow the referenced template's guidance and confirm the exposure.",
        probe_id=META.id,
        probe_version=META.version,
        frameworks=(*advisories, *cwes),
        reproduction=(
            f"Run: nuclei -target {matched} -id {template_id}",
            "Observe the template match.",
        ),
        # Template + location, not the response: a template that keeps matching
        # the same endpoint is one finding across runs.
        fingerprint="sha256:" + hashlib.sha256(f"{template_id}|{matched}".encode()).hexdigest(),
    )


async def run_nuclei(
    targets: Sequence[str], policy: ToolPolicy, *, rate: int = 10
) -> list[ScanResult]:
    """Run nuclei over already-cleared URLs, or report that it did not run."""
    if not targets:
        return []

    result = await run_tool(
        ToolInvocation(
            command=command_for(policy, targets, rate=rate),
            cwd=None,
            network=NetworkUse.DECLARED_SERVICE,
            timeout_seconds=NUCLEI_TIMEOUT_SECONDS,
        )
    )
    if not result.ran or result.failed:
        return [
            tool_unavailable(
                META,
                result.reason or f"nuclei exited {result.exit_code}: {result.stderr.strip()[:300]}",
            )
        ]

    findings: list[ScanResult] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        finding = _finding(entry, policy)
        if finding is None or finding.fingerprint in seen:
            continue
        seen.add(str(finding.fingerprint))
        findings.append(finding)
    return findings
