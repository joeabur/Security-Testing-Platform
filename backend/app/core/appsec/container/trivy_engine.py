"""Trivy adapter — OS packages and language dependencies inside the build.

**Filesystem scanning of the checkout, not `docker pull`.** Pulling the base
image a Dockerfile names would mean reaching a registry the operator has not
sanctioned, running as an outbound request this platform's transport would
never see, and materialising an untrusted image on the worker. So this engine
scans the workspace that was already cloned under the code scope, which covers
the lock files and vendored dependencies that make up most of what an image
contains — and it says, in its own finding, that it has not examined the base
image layers. An image scan proper needs a sanctioned registry and a decision
about where the pull happens; that is recorded as not built rather than faked.

Trivy is asked for offline operation (`--skip-db-update --offline-scan`), so it
matches against whatever database the worker already has. A worker with no
database produces a "not tested" result rather than a clean one.

Every vulnerability identifier is checked to be a real CVE/GHSA/OSV shape before
it reaches a finding.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.core.appsec.contract import EngineMeta, Pillar, tool_unavailable
from app.core.appsec.identifiers import verified_advisories
from app.core.appsec.supplychain.manifests import base_images
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

TRIVY_TIMEOUT_SECONDS = 600

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFORMATIONAL,
}


class ContainerScanEngine:
    meta = EngineMeta(
        id="appsec.container.trivy",
        version="1.0.0",
        name="Container dependency scan (Trivy, filesystem mode)",
        pillar=Pillar.SCA,
        tool="trivy",
        description=(
            "Scans the checked-out filesystem for vulnerable OS and language "
            "packages. Does not pull or scan base image layers."
        ),
    )

    def applies_to(self, workspace: Workspace) -> bool:
        # A Dockerfile is the signal that this checkout becomes an image. Without
        # one, `pip-audit` and the other SCA engines already cover the same
        # ground and a second scan is noise.
        return bool(base_images(workspace))

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        images = base_images(workspace)
        if not images:
            return []

        result = await run_tool(
            ToolInvocation(
                command=(
                    "trivy",
                    "filesystem",
                    "--format",
                    "json",
                    "--quiet",
                    # Offline: no database update, no upstream lookups for
                    # unfixed packages. A stale database is a visible gap; an
                    # unannounced network call is not.
                    "--skip-db-update",
                    "--offline-scan",
                    "--scanners",
                    "vuln",
                    ".",
                ),
                cwd=workspace.root,
                network=NetworkUse.OFFLINE,
                timeout_seconds=TRIVY_TIMEOUT_SECONDS,
            )
        )
        if not result.ran or result.failed:
            return [
                tool_unavailable(
                    self.meta,
                    result.reason
                    or f"trivy exited {result.exit_code}: {result.stderr.strip()[:300]}",
                )
            ]

        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return [tool_unavailable(self.meta, "trivy produced output that is not JSON")]

        findings = [*self._vulnerabilities(payload), self._base_image_gap(images)]
        return findings

    def _vulnerabilities(self, payload: dict[str, Any]) -> list[ScanResult]:
        results: list[ScanResult] = []
        seen: set[str] = set()
        for group in payload.get("Results") or []:
            if not isinstance(group, dict):
                continue
            target = str(group.get("Target") or "")
            for entry in group.get("Vulnerabilities") or []:
                if not isinstance(entry, dict):
                    continue
                # Verified, not trusted: §28 forbids presenting an identifier
                # that does not have the shape of a real advisory.
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
                        id="KERVY-CONTAINER-001",
                        title=f"{advisory} in {package} {installed}",
                        category=Category.INFRASTRUCTURE,
                        severity=_SEVERITY.get(
                            str(entry.get("Severity") or "").upper(), Severity.INFORMATIONAL
                        ),
                        confidence=Confidence.HIGH,
                        endpoint=f"{target}:{package}",
                        description=(
                            str(entry.get("Title") or entry.get("Description") or advisory)[:1000]
                        ),
                        evidence=(
                            f"{target}\n{package} {installed}\n{advisory}\n"
                            + (f"Fixed in {fixed}" if fixed else "No fixed version published")
                        ),
                        impact=(
                            "The package ships in the built image and runs with whatever "
                            "privileges the container has."
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
                        probe_id=self.meta.id,
                        probe_version=self.meta.version,
                        # Same convention as the SCA engine: verified advisory
                        # and CWE identifiers travel in `frameworks`, so the
                        # report's traceability section finds them in one place.
                        frameworks=(
                            *advisories,
                            *(
                                str(value)
                                for value in (entry.get("CweIDs") or [])
                                if str(value).upper().startswith("CWE-")
                            ),
                        ),
                        reproduction=(
                            f"Run: trivy filesystem --scanners vuln {target}",
                            f"Observe {package} {installed} reported as affected by {advisory}.",
                        ),
                        # Advisory + target + package, not the version: an
                        # unfixed package stays one finding across runs, and a
                        # patch bump that does not fix it is not a new issue.
                        fingerprint="sha256:"
                        + hashlib.sha256(f"{advisory}|{target}|{package}".encode()).hexdigest(),
                    )
                )
        return results

    def _base_image_gap(self, images: list[tuple[str, str, str]]) -> ScanResult:
        """State plainly what a filesystem scan does not cover.

        Without this, a clean result would read as "the image is clean", when
        the layers underneath the application were never looked at.
        """
        listed = "\n".join(
            f"{manifest}: FROM {name}{':' + tag if tag else ''}" for name, tag, manifest in images
        )
        return ScanResult(
            id="KERVY-CONTAINER-009",
            title="Not tested: base image layers",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint="container/base-image",
            description=(
                "This scan read the checked-out filesystem. It did not pull or examine "
                "the base images below, so packages that come only from those layers "
                "were not assessed. Pulling them would mean reaching a registry this "
                "engagement has not authorized."
            ),
            evidence=listed,
            impact=(
                "Unknown. A vulnerable package present only in a base layer would not "
                "appear in this run's results."
            ),
            remediation=(
                "Scan the built image in your build pipeline, where the registry is "
                "already authorized, and feed the result in through the SARIF import."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )
