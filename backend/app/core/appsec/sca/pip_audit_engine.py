"""pip-audit adapter — Python dependency analysis (Addendum v2.1 §4.3).

**This engine reaches a third-party service, and that is an opt-in.**
Matching a dependency graph against an advisory database means sending the
client's dependency list to whoever runs that database. That is a
disclosure decision an operator makes, not one a scanner makes quietly, so
the lookup runs only when `allow_advisory_lookup` is set and the finding
says which service was consulted.

With the lookup off, the engine still resolves and reports the dependency
inventory — which feeds the SBOM — and states plainly that no advisory
matching was performed. An empty result would otherwise read as "no
vulnerable dependencies", which is a very different claim.

Every advisory identifier is verified to be a real CVE/GHSA/OSV shape before
it reaches a finding: §28 forbids laundering an invented identifier through
normalization.
"""

import hashlib
import json
from typing import Any

from app.core.appsec.contract import EngineMeta, Pillar, code_evidence, tool_unavailable
from app.core.appsec.identifiers import verified_advisories
from app.core.appsec.reachability.python_imports import (
    reachability_impact_text as _reachability_impact,
)
from app.core.appsec.tooling import NetworkUse, ToolInvocation, run_tool
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

ADVISORY_SERVICE = "https://pypi.org/pypi (PyPI advisory database via pip-audit)"
PIP_AUDIT_TIMEOUT_SECONDS = 420

_PYTHON_MANIFESTS = ("requirements.txt", "pyproject.toml", "requirements.in")


class PipAuditEngine:
    meta = EngineMeta(
        id="appsec.sca.pip_audit",
        version="1.0.0",
        name="pip-audit (Python dependency analysis)",
        pillar=Pillar.SCA,
        tool="pip-audit",
        description="Resolves Python dependencies and matches them against advisories.",
    )

    def __init__(self, *, allow_advisory_lookup: bool = False) -> None:
        self._allow_lookup = allow_advisory_lookup

    def _manifests(self, workspace: Workspace) -> list[str]:
        declared = [
            str(path.relative_to(workspace.root))
            for path in workspace.manifests()
            if path.name in _PYTHON_MANIFESTS
        ]
        if declared:
            return declared
        # Fall back to in-scope manifests only. A manifest outside the
        # declared code scope is not scanned, however obvious it looks.
        return [
            str(path.relative_to(workspace.root))
            for path in workspace.files
            if path.name in _PYTHON_MANIFESTS
        ]

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(self._manifests(workspace))

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        manifests = self._manifests(workspace)
        if not manifests:
            return []

        if not self._allow_lookup:
            return [self._lookup_disabled(manifests)]

        findings: list[ScanResult] = []
        for manifest in manifests:
            result = await run_tool(
                ToolInvocation(
                    command=(
                        "pip-audit",
                        "--format",
                        "json",
                        "--progress-spinner",
                        "off",
                        "-r" if manifest.endswith((".txt", ".in")) else "--path",
                        manifest,
                    ),
                    cwd=workspace.root,
                    network=NetworkUse.DECLARED_SERVICE,
                    timeout_seconds=PIP_AUDIT_TIMEOUT_SECONDS,
                )
            )
            if not result.ran:
                findings.append(tool_unavailable(self.meta, result.reason))
                continue
            if result.failed:
                findings.append(
                    tool_unavailable(
                        self.meta,
                        f"pip-audit exited {result.exit_code} on {manifest}: {result.stderr[:400]}",
                    )
                )
                continue

            try:
                payload = json.loads(result.stdout or "{}")
            except ValueError as exc:
                findings.append(
                    tool_unavailable(self.meta, f"pip-audit output was not JSON: {exc}")
                )
                continue

            findings.extend(self._normalize(payload, manifest, workspace))
        return findings

    def _normalize(
        self, payload: dict[str, Any], manifest: str, workspace: Workspace | None = None
    ) -> list[ScanResult]:
        findings: list[ScanResult] = []

        for dependency in payload.get("dependencies", []):
            name = str(dependency.get("name", "")).strip()
            installed = str(dependency.get("version", "")).strip()
            for vulnerability in dependency.get("vulns", []) or []:
                advisories = verified_advisories(
                    [vulnerability.get("id"), *(vulnerability.get("aliases") or [])]
                )
                # No verifiable identifier means no finding. A "vulnerable
                # dependency" a reader cannot look up is not actionable, and
                # naming it something plausible would be worse than silence.
                if not advisories:
                    continue

                fixes = [str(version) for version in vulnerability.get("fix_versions", []) or []]
                primary = advisories[0]
                impact = _reachability_impact(workspace, name) if workspace else None
                findings.append(
                    ScanResult(
                        id=f"KERVY-SCA-{primary}",
                        title=f"{name} {installed} is affected by {primary}",
                        category=Category.INFRASTRUCTURE,
                        severity=Severity.HIGH if fixes else Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        endpoint=f"{manifest}:{name}",
                        description=(
                            f"{name} is resolved at {installed}, which the advisory "
                            f"{primary} identifies as affected. "
                            + (
                                f"First fixed in {', '.join(fixes)}."
                                if fixes
                                else "No fixed version is published yet, so mitigation "
                                "rather than upgrade may be required."
                            )
                            + f"\n\nAdvisory data retrieved from {ADVISORY_SERVICE}."
                        ),
                        evidence=(
                            f"manifest: {manifest}\npackage: {name}\n"
                            f"resolved version: {installed}\n"
                            f"advisories: {', '.join(advisories)}\n"
                            f"first patched: {', '.join(fixes) or 'none published'}"
                        ),
                        impact=impact
                        or (
                            "Reachability was not assessed. A vulnerable version being "
                            "present does not establish that the affected code path is "
                            "used by this application."
                        ),
                        remediation=(
                            f"Upgrade {name} to {fixes[0]} or later."
                            if fixes
                            else f"Track {primary} for a fixed release and apply the "
                            "advisory's mitigation in the meantime."
                        ),
                        probe_id=self.meta.id,
                        probe_version=self.meta.version,
                        frameworks=advisories,
                        reproduction=(
                            f"Run: pip-audit -r {manifest}",
                            f"Observe {name} {installed} reported as affected by {primary}.",
                        ),
                        # Advisory + manifest + package, not the version:
                        # the same unfixed dependency is one finding across
                        # runs, and a patch bump that does not fix it should
                        # not present as a brand new issue.
                        fingerprint="sha256:"
                        + hashlib.sha256(f"{primary}|{manifest}|{name}".encode()).hexdigest(),
                        # A dependency finding's "span" is the manifest entry
                        # that pinned the affected version, which is what a
                        # retest re-reads after an upgrade.
                        evidence_bundle=code_evidence(
                            self.meta,
                            rule_id=primary,
                            relative_path=manifest,
                            line=None,
                            snippet=f"{name}=={installed}",
                            message=(
                                f"{primary} affects {name} {installed}"
                                + (f"; fixed in {', '.join(fixes)}" if fixes else "")
                            ),
                        ),
                    )
                )
        return findings

    def _lookup_disabled(self, manifests: list[str]) -> ScanResult:
        return ScanResult(
            id="KERVY-APPSEC-000",
            title="Not tested: dependency advisory matching",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=Pillar.SCA.value,
            description=(
                "Dependency manifests were found but not matched against an advisory "
                "database, so this assessment says nothing about whether the "
                "dependencies are vulnerable."
            ),
            evidence=(
                f"in-scope manifests: {', '.join(manifests)}\n\n"
                "Advisory matching sends the resolved dependency list to a third-party "
                f"service ({ADVISORY_SERVICE}). That is a disclosure the operator opts "
                "into per assessment, so it is off unless enabled."
            ),
            impact="Unknown — no advisory matching was performed.",
            remediation=(
                "Enable advisory lookup for this assessment, or run pip-audit inside "
                "the client's own environment and import the results."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )
