"""Direct OSV.dev SCA coverage for npm, PyPI, Go, Rust, and Java dependencies
(`docs/competitive-gap-analysis.md`'s "Direct OSV/NVD/GHSA integration" gap,
and `docs/BUILD_SPEC.md`'s own Phase 14 table, which names `OSV-Scanner` as
part of the SCA tool set and was never built).

**Why this, and not a wrapper around the `osv-scanner` binary.** `pip-audit`,
Trivy and Checkov are all the same shape this platform already has: a
third-party tool that embeds its own copy of (or makes its own, unobserved
call to) an advisory database. The gap the competitive analysis names is
specifically that nothing in this codebase *itself* ever calls `osv.dev`,
`nvd.nist.gov` or GHSA's API — and wrapping `osv-scanner` as a fourth
subprocess would be the exact same architecture already critiqued, just
with OSV's name on the binary. This engine instead parses the lockfile
itself and calls `osv.dev` directly through the platform's own
`GatedTransport`, which is also strictly *more* constrained than every
existing SCA/container engine's own network reach: `pip-audit`'s and
Trivy's outbound calls are declared (`NetworkUse.DECLARED_SERVICE`) but not
actually scope-checked, because a subprocess's own sockets are outside what
a Python-level gate can intercept. This client's calls go through the real
`ScopeEngine`, the same way the DAST pillar's `EgressGateway` brought real
containment to Nuclei and ZAP's subprocess traffic.

**Why npm, then PyPI, then Go/Rust/Java.** Node/npm dependencies had zero
SCA coverage of any kind when this engine first shipped — not delegated,
not direct, simply absent — so that pass closed a real coverage gap.
Python already had coverage through `pip-audit`'s own embedded advisory
data, so the PyPI path is framed differently: a second, *live* source
alongside `pip-audit`, not a replacement and not closing a zero-coverage
gap. `pip-audit` keeps resolving the dependency inventory that feeds the
SBOM (`docs/supply-chain.md`) and can audit a constraint `pip-audit`
resolves from a real environment that a direct query cannot — an unpinned
requirement has no single resolved version to query here
(`pypi_requirements.py`'s own docstring). Go, Rust, and Java had zero SCA
coverage, the same zero-coverage framing as the original npm pass — each
gets a thin subclass parsing its own fully-resolved manifest format
(`go.sum`, `Cargo.lock`, Gradle's `gradle.lockfile`) into the same
`PackageQuery` shape, exactly as this module's own earlier revision
predicted would be all that's needed. The rest of OSV's supported
ecosystems (and Maven's `pom.xml`, which has no fully-resolved-version
lockfile of its own to parse — see `gradle_lockfile.py`'s own docstring)
remain uncovered, left for a later increment rather than attempted
speculatively here.

**Why not NVD or GHSA's own API too.** NVD's API is keyed by CVE id, not by
package-and-version — useful for enriching a CVE a finding already names
with CVSS/description detail, but not for discovering which CVEs apply to a
lockfile, and it needs an API key for usable rate limits. GHSA's REST/
GraphQL API needs a GitHub token and, for npm specifically, publishes
exactly the same advisories `osv.dev` already re-serves without
authentication as the npm ecosystem's native identifier scheme — calling
OSV directly already gets GHSA's npm coverage through one unauthenticated
client rather than two. Both remain not integrated, stated here rather
than approximated.
"""

import hashlib
from pathlib import Path
from typing import Any

from app.core.appsec.contract import EngineMeta, Pillar, code_evidence, severity_from
from app.core.appsec.identifiers import verified_advisories
from app.core.appsec.reachability.python_imports import reachability_impact_text
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.transport import GatedTransport

from .cargo_lock import cargo_lock_packages
from .client import OsvClient, OsvClientError, PackageQuery
from .egress import OSV_HOST, osv_egress_context
from .go_sum import go_sum_packages
from .gradle_lockfile import gradle_lockfile_packages
from .npm_lockfile import npm_lockfile_packages
from .pypi_requirements import pypi_requirements_packages

ADVISORY_SERVICE = f"https://{OSV_HOST} (OSV.dev, direct)"
_NPM_LOCKFILES = ("package-lock.json",)


class _OsvEngineBase:
    """Everything about querying osv.dev directly that does not depend on
    which ecosystem a concrete subclass covers: batching, verification,
    severity/fix-version extraction, and finding shape are all already
    generic over `PackageQuery.ecosystem`. A subclass supplies only which
    manifests to look for, how to parse one into `(name, version)` pairs,
    what text names its ecosystem in a gap finding, and — since only Python
    has a reachability module today — whether and how to decorate a finding
    with reachability evidence.
    """

    meta: EngineMeta
    _manifest_names: tuple[str, ...]
    _ecosystem: str
    _display_name: str

    def __init__(
        self, *, allow_advisory_lookup: bool = False, client: OsvClient | None = None
    ) -> None:
        self._allow_lookup = allow_advisory_lookup
        # Injectable the same way `GitHubClient` takes an optional transport:
        # a test double here still goes through the real `OsvClient`'s own
        # request construction, or replaces it outright with something
        # exposing the same two methods — neither can change which host the
        # client talks to, since that is fixed in `client.py`, not passed in.
        self._client = client

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        raise NotImplementedError

    def _reachability_impact(self, workspace: Workspace, package_name: str) -> str | None:
        return None

    def _manifests(self, workspace: Workspace) -> list[str]:
        declared = [
            str(path.relative_to(workspace.root))
            for path in workspace.manifests()
            if path.name in self._manifest_names
        ]
        if declared:
            return declared
        return [
            str(path.relative_to(workspace.root))
            for path in workspace.files
            if path.name in self._manifest_names
        ]

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(self._manifests(workspace))

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        manifests = self._manifests(workspace)
        if not manifests:
            return []

        if not self._allow_lookup:
            return [self._lookup_disabled(manifests)]

        ctx = osv_egress_context()
        client = self._client or OsvClient(transport=GatedTransport())

        findings: list[ScanResult] = []
        for manifest in manifests:
            packages = self._packages_for(workspace.root / manifest)
            if not packages:
                continue
            queries = [
                PackageQuery(name=name, version=version, ecosystem=self._ecosystem)
                for name, version in packages
            ]
            try:
                vulnerable = await client.query_vulnerable_ids(ctx, queries)
            except OsvClientError as exc:
                findings.append(self._query_failed(manifest, str(exc)))
                continue
            if not vulnerable:
                continue

            all_ids: set[str] = set()
            for ids in vulnerable.values():
                all_ids.update(ids)
            try:
                details = await client.get_vulnerability_details(ctx, all_ids)
            except OsvClientError as exc:
                findings.append(self._query_failed(manifest, str(exc)))
                continue

            for query, ids in vulnerable.items():
                findings.extend(self._normalize(query, ids, details, manifest, workspace))
        return findings

    def _normalize(
        self,
        query: PackageQuery,
        ids: tuple[str, ...],
        details: dict[str, dict[str, Any]],
        manifest: str,
        workspace: Workspace,
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        for vuln_id in ids:
            record = details.get(vuln_id)
            advisories = verified_advisories([vuln_id, *(record or {}).get("aliases", [])])
            # The same rule pip-audit's engine follows: no verifiable
            # identifier, no finding. OSV's own id shape is verified rather
            # than assumed well-formed.
            if not advisories:
                continue
            primary = advisories[0]

            fixed_versions = _fixed_versions(record, query.name) if record else ()
            summary = (record or {}).get("summary") or f"{primary} affects {query.name}"
            severity = _severity_of(record, fixed_versions)
            impact = self._reachability_impact(workspace, query.name) or (
                "Reachability was not assessed. A vulnerable version being "
                "present does not establish that the affected code path is "
                "used by this application."
            )

            results.append(
                ScanResult(
                    id=f"KERVY-SCA-{primary}",
                    title=f"{query.name} {query.version} is affected by {primary}",
                    category=Category.INFRASTRUCTURE,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    endpoint=f"{manifest}:{query.name}",
                    description=(
                        f"{query.name} is resolved at {query.version}, which {primary} "
                        f"identifies as affected: {summary}\n\n"
                        + (
                            f"First fixed in {', '.join(fixed_versions)}."
                            if fixed_versions
                            else "No fixed version is published yet, so mitigation "
                            "rather than upgrade may be required."
                        )
                        + f"\n\nAdvisory data retrieved directly from {ADVISORY_SERVICE}."
                    ),
                    evidence=(
                        f"manifest: {manifest}\npackage: {query.name}\n"
                        f"resolved version: {query.version}\n"
                        f"advisories: {', '.join(advisories)}\n"
                        f"first patched: {', '.join(fixed_versions) or 'none published'}"
                    ),
                    impact=impact,
                    remediation=(
                        f"Upgrade {query.name} to {fixed_versions[0]} or later."
                        if fixed_versions
                        else f"Track {primary} for a fixed release and apply the "
                        "advisory's mitigation in the meantime."
                    ),
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                    frameworks=advisories,
                    reproduction=(
                        f"Query osv.dev directly for {query.name}@{query.version} "
                        f"(ecosystem: {query.ecosystem}).",
                        f"Observe {primary} returned as a match, and fetch "
                        f"GET /v1/vulns/{primary} for its detail.",
                    ),
                    fingerprint="sha256:"
                    + hashlib.sha256(f"{primary}|{manifest}|{query.name}".encode()).hexdigest(),
                    evidence_bundle=code_evidence(
                        self.meta,
                        rule_id=primary,
                        relative_path=manifest,
                        line=None,
                        snippet=f"{query.name}@{query.version}",
                        message=(
                            f"{primary} affects {query.name} {query.version}"
                            + (f"; fixed in {', '.join(fixed_versions)}" if fixed_versions else "")
                        ),
                    ),
                )
            )
        return results

    def _lookup_disabled(self, manifests: list[str]) -> ScanResult:
        return ScanResult(
            id="KERVY-APPSEC-000",
            title=f"Not tested: {self._display_name} dependency advisory matching (OSV.dev)",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=Pillar.SCA.value,
            description=(
                f"{self._display_name} manifests were found but not matched against "
                "osv.dev, so this assessment says nothing about whether those "
                "dependencies are vulnerable."
            ),
            evidence=(
                f"in-scope manifests: {', '.join(manifests)}\n\n"
                "Advisory matching sends the resolved dependency list to a third-party "
                f"service ({ADVISORY_SERVICE}). That is a disclosure the operator opts "
                "into per assessment, so it is off unless enabled."
            ),
            impact="Unknown — no advisory matching was performed.",
            remediation="Enable advisory lookup for this assessment.",
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )

    def _query_failed(self, manifest: str, reason: str) -> ScanResult:
        return ScanResult(
            id="KERVY-APPSEC-000",
            title=f"Not tested: {self._display_name} dependency advisory matching (OSV.dev)",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=Pillar.SCA.value,
            description=(
                f"osv.dev could not be queried for {manifest}, so this assessment "
                f"says nothing about whether its {self._display_name} dependencies "
                "are vulnerable."
            ),
            evidence=reason,
            impact="Unknown — the query did not complete.",
            remediation="Re-run once osv.dev is reachable, or check egress policy.",
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )


class OsvEngine(_OsvEngineBase):
    meta = EngineMeta(
        id="appsec.sca.osv_npm",
        version="1.0.0",
        name="OSV.dev direct query (npm)",
        pillar=Pillar.SCA,
        tool="osv.dev",
        description=(
            "Parses npm lockfiles and queries osv.dev directly for known "
            "vulnerabilities, through the platform's own scope-gated transport."
        ),
    )
    _manifest_names = _NPM_LOCKFILES
    _ecosystem = "npm"
    _display_name = "npm"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return npm_lockfile_packages(path)

    # No reachability wiring: `python_imports.py` only understands Python
    # import/call syntax, so it cannot assess an npm package. The base
    # class's `None` default — the original, always-generic `impact` text —
    # is correct here, not a gap introduced by this refactor.


class OsvPypiEngine(_OsvEngineBase):
    meta = EngineMeta(
        id="appsec.sca.osv_pypi",
        version="1.0.0",
        name="OSV.dev direct query (PyPI)",
        pillar=Pillar.SCA,
        tool="osv.dev",
        description=(
            "Parses pinned Python requirements files and queries osv.dev "
            "directly for known vulnerabilities, as a second, live source "
            "alongside pip-audit's own embedded advisory data."
        ),
    )
    _manifest_names = ("requirements.txt", "requirements.in")
    _ecosystem = "pypi"
    _display_name = "PyPI"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return pypi_requirements_packages(path)

    def _reachability_impact(self, workspace: Workspace, package_name: str) -> str | None:
        return reachability_impact_text(workspace, package_name)


class OsvGoEngine(_OsvEngineBase):
    meta = EngineMeta(
        id="appsec.sca.osv_go",
        version="1.0.0",
        name="OSV.dev direct query (Go)",
        pillar=Pillar.SCA,
        tool="osv.dev",
        description=(
            "Parses go.sum and queries osv.dev directly for known "
            "vulnerabilities, through the platform's own scope-gated transport."
        ),
    )
    _manifest_names = ("go.sum",)
    _ecosystem = "Go"
    _display_name = "Go"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return go_sum_packages(path)

    # No reachability wiring: `python_imports.py` only understands Python
    # import/call syntax — the same reason `OsvEngine` (npm) has none.


class OsvRustEngine(_OsvEngineBase):
    meta = EngineMeta(
        id="appsec.sca.osv_rust",
        version="1.0.0",
        name="OSV.dev direct query (Rust)",
        pillar=Pillar.SCA,
        tool="osv.dev",
        description=(
            "Parses Cargo.lock and queries osv.dev directly for known "
            "vulnerabilities, through the platform's own scope-gated transport."
        ),
    )
    _manifest_names = ("Cargo.lock",)
    _ecosystem = "crates.io"
    _display_name = "Rust"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return cargo_lock_packages(path)


class OsvJavaEngine(_OsvEngineBase):
    meta = EngineMeta(
        id="appsec.sca.osv_java",
        version="1.0.0",
        name="OSV.dev direct query (Java/Gradle)",
        pillar=Pillar.SCA,
        tool="osv.dev",
        description=(
            "Parses a Gradle single-file lockfile and queries osv.dev directly "
            "for known vulnerabilities, through the platform's own "
            "scope-gated transport."
        ),
    )
    _manifest_names = ("gradle.lockfile", "buildscript-gradle.lockfile")
    _ecosystem = "Maven"
    _display_name = "Java/Gradle"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return gradle_lockfile_packages(path)


def _fixed_versions(record: dict[str, Any] | None, package_name: str) -> tuple[str, ...]:
    if not record:
        return ()
    fixed: list[str] = []
    for affected in record.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        if package.get("name") != package_name:
            continue
        for range_ in affected.get("ranges", []) or []:
            if not isinstance(range_, dict):
                continue
            for event in range_.get("events", []) or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed.append(str(event["fixed"]))
    seen: list[str] = []
    for version in fixed:
        if version not in seen:
            seen.append(version)
    return tuple(seen)


def _severity_of(record: dict[str, Any] | None, fixed_versions: tuple[str, ...]) -> Severity:
    """The advisory's own stated severity where it gave one, never a CVSS
    vector computed here — §12's "do not manufacture a CVSS vector"
    applies just as much to a severity word derived from one. GHSA-sourced
    OSV records carry a plain label in `database_specific.severity`; where
    that is absent, fix-availability is the same conservative fallback
    `pip_audit_engine` already uses.
    """
    if record:
        label = (record.get("database_specific") or {}).get("severity")
        if isinstance(label, str) and label.strip():
            return severity_from(label)
    return Severity.HIGH if fixed_versions else Severity.MEDIUM
