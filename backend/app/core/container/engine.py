"""The container engine: pull an authorized image, scan it offline, remove it.

Closes the gap `app.core.appsec.container.trivy_engine.ContainerScanEngine`
states plainly rather than fakes: that engine scans a code checkout's
filesystem and says outright it "did not pull or examine the base image
layers", because pulling one means "reaching a registry this engagement has
not authorized" — a decision that engine has no scope to make. This one
exists to be that decision, made explicitly through
`asset_scope.allowed_registries` and `asset_scope.allow_live_pull` on a
`TargetKind.CONTAINER` target, never assumed.

The pull is a subprocess (`docker pull`), not `GatedTransport` — see
`pull.py`'s own docstring for why, and for the allowlist/IP-block checks
applied before it runs. Once the image is local, scanning it is offline
(`trivy image`, `--skip-db-update --offline-scan`, reading the local Docker
daemon rather than making its own registry call) — a worker with no
vulnerability database produces a "not tested" result, never a clean one.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.appsec.identifiers import verified_advisories
from app.core.appsec.tooling import NetworkUse, ToolInvocation, ToolResult, run_tool
from app.core.container.contract import ContainerTarget, ToolInvocationRecord
from app.core.container.pull import (
    ContainerPullError,
    ImageRef,
    check_registry_allowed,
    parse_image_ref,
    pull_image,
    remove_image,
)
from app.core.probes.models import Category, Confidence, ScanResult, Severity

ENGINE_ID = "container.engine"
ENGINE_VERSION = "1.0.0"
TRIVY_TIMEOUT_SECONDS = 600

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFORMATIONAL,
}

PullFn = Callable[[ImageRef], Awaitable[ToolResult]]
RemoveFn = Callable[[ImageRef], Awaitable[ToolResult]]
ScanFn = Callable[[ImageRef], Awaitable[ToolResult]]


async def _scan_with_trivy(ref: ImageRef) -> ToolResult:
    return await run_tool(
        ToolInvocation(
            command=(
                "trivy",
                "image",
                "--format",
                "json",
                "--quiet",
                # Read the image the pull already placed on the local Docker
                # daemon — never trivy's own registry client, which would be
                # a second, unaudited network path to the same registry.
                "--image-src",
                "docker",
                "--skip-db-update",
                "--offline-scan",
                "--scanners",
                "vuln",
                ref.raw,
            ),
            cwd=None,
            network=NetworkUse.OFFLINE,
            timeout_seconds=TRIVY_TIMEOUT_SECONDS,
        )
    )


@dataclass
class ContainerEngine:
    """Injectable `pull`/`remove`/`scan` so tests exercise the engine's own
    control flow (gating, cleanup-always, finding shape) without a real
    Docker daemon or trivy binary — the same reason `DomainEngine` takes its
    transport and DNS resolver as constructor arguments rather than reaching
    for a default at call time."""

    pull: PullFn = field(default=pull_image)
    remove: RemoveFn = field(default=remove_image)
    scan: ScanFn = field(default=_scan_with_trivy)

    async def run(
        self, target: ContainerTarget
    ) -> tuple[list[ScanResult], list[ToolInvocationRecord]]:
        if not target.allow_live_pull:
            return (
                [
                    _coverage_marker(
                        "live image pull",
                        "asset_scope.allow_live_pull is false, or unstated. Pulling an "
                        "image is a live outbound action against a registry, so — like "
                        "every other pentest capability on this platform — it runs only "
                        "when explicitly authorized, never by default.",
                    )
                ],
                [],
            )

        try:
            ref = parse_image_ref(target.image_ref)
            check_registry_allowed(ref, target.allowed_registries)
        except ContainerPullError as exc:
            return [_coverage_marker(target.image_ref, str(exc))], []

        invocations: list[ToolInvocationRecord] = []

        pull_started = datetime.now(UTC)
        pull_result = await self.pull(ref)
        invocations.append(
            _invocation_record("docker", "pull", ref, pull_result, pull_started)
        )
        if not pull_result.ran or pull_result.exit_code != 0:
            reason = pull_result.reason or f"docker pull exited {pull_result.exit_code}: " + (
                pull_result.stderr.strip()[:300]
            )
            return [_coverage_marker(ref.raw, f"image pull failed: {reason}")], invocations

        try:
            scan_started = datetime.now(UTC)
            scan_result = await self.scan(ref)
            invocations.append(
                _invocation_record("trivy", "image", ref, scan_result, scan_started)
            )
        finally:
            remove_started = datetime.now(UTC)
            remove_result = await self.remove(ref)
            invocations.append(
                _invocation_record("docker", "rmi", ref, remove_result, remove_started)
            )

        if not scan_result.ran or scan_result.exit_code not in (0, 1):
            reason = scan_result.reason or (
                f"trivy exited {scan_result.exit_code}: {scan_result.stderr.strip()[:300]}"
            )
            return [_coverage_marker(ref.raw, f"image scan failed: {reason}")], invocations

        try:
            payload = json.loads(scan_result.stdout or "{}")
        except json.JSONDecodeError:
            return [
                _coverage_marker(ref.raw, "trivy produced output that is not JSON")
            ], invocations

        return _findings(ref, payload), invocations


def _invocation_record(
    tool_name: str,
    verb: str,
    ref: ImageRef,
    result: ToolResult,
    started_at: datetime,
) -> ToolInvocationRecord:
    return ToolInvocationRecord(
        tool_name=tool_name,
        tool_version=None,
        network_use=(
            NetworkUse.DECLARED_SERVICE.value if verb == "pull" else NetworkUse.OFFLINE.value
        ),
        # A redacted summary — the verb and the image reference, never the
        # full argv or the tool's raw output — the same "describe, don't
        # dump" rule `RunToolInvocation.command_summary` documents.
        command_summary=f"{tool_name} {verb} {ref.raw}",
        started_at=started_at,
        finished_at=datetime.now(UTC) if result.ran else started_at,
        exit_status=result.exit_code,
    )


def _findings(ref: ImageRef, payload: dict[str, Any]) -> list[ScanResult]:
    results: list[ScanResult] = []
    seen: set[str] = set()
    for group in payload.get("Results") or []:
        if not isinstance(group, dict):
            continue
        scanned_target = str(group.get("Target") or ref.raw)
        for entry in group.get("Vulnerabilities") or []:
            if not isinstance(entry, dict):
                continue
            advisories = verified_advisories([entry.get("VulnerabilityID")])
            if not advisories:
                continue
            advisory = advisories[0]
            package = str(entry.get("PkgName") or "unknown")
            installed = str(entry.get("InstalledVersion") or "unknown")
            key = f"{advisory}:{package}:{installed}"
            if key in seen:
                continue
            seen.add(key)

            fixed = str(entry.get("FixedVersion") or "")
            results.append(
                ScanResult(
                    id="AEGIS-CONTAINER-101",
                    title=f"{advisory} in {package} {installed} ({ref.raw})",
                    category=Category.INFRASTRUCTURE,
                    severity=_SEVERITY.get(
                        str(entry.get("Severity") or "").upper(), Severity.INFORMATIONAL
                    ),
                    confidence=Confidence.HIGH,
                    endpoint=f"{ref.raw}:{package}",
                    description=str(
                        entry.get("Title") or entry.get("Description") or advisory
                    )[:1000],
                    evidence=(
                        f"{scanned_target}\n{package} {installed}\n{advisory}\n"
                        + (f"Fixed in {fixed}" if fixed else "No fixed version published")
                    ),
                    impact=(
                        "The package ships in this image and runs with whatever "
                        "privileges a container started from it has."
                    ),
                    remediation=(
                        f"Upgrade {package} to {fixed}."
                        if fixed
                        else (
                            f"No fix is published for {package} {installed}. Assess "
                            "whether the vulnerable code path is reachable, or replace "
                            "the package."
                        )
                    ),
                    probe_id=ENGINE_ID,
                    probe_version=ENGINE_VERSION,
                    frameworks=(
                        *advisories,
                        *(
                            str(value)
                            for value in (entry.get("CweIDs") or [])
                            if str(value).upper().startswith("CWE-")
                        ),
                    ),
                    reproduction=(
                        f"docker pull {ref.raw}",
                        f"trivy image --image-src docker --scanners vuln {ref.raw}",
                        f"Observe {package} {installed} reported as affected by {advisory}.",
                    ),
                    fingerprint="sha256:"
                    + hashlib.sha256(f"{advisory}|{ref.repository}|{package}".encode()).hexdigest(),
                )
            )
    return results


def _coverage_marker(surface: str, reason: str) -> ScanResult:
    return ScanResult(
        id="AEGIS-CONTAINER-109",
        title=f"Not tested: {surface}",
        category=Category.INFRASTRUCTURE,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint=f"container/{surface}",
        description=f"{reason}. This assessment says nothing about {surface}.",
        evidence=reason,
        impact="Unknown — not tested.",
        remediation="Authorize a live pull for this registry, or confirm the gap is expected.",
        probe_id=ENGINE_ID,
        probe_version=ENGINE_VERSION,
    )
