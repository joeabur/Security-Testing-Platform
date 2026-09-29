"""Name-confusion and install-hook signals as findings.

Every finding this engine emits is a *signal for a human to check*, never an
accusation. The titles say "resembles" and "runs code at install time"; none of
them say "malicious", because nothing here establishes that and a scanner that
cries malware gets muted.

Severity is capped at LOW for the same reason, and confidence is
`DESIGN_REVIEW` throughout: nothing was executed and no registry was consulted,
so this is a reading of the manifests, not a demonstration.
"""

from __future__ import annotations

import json

from app.core.appsec.contract import EngineMeta, Pillar
from app.core.appsec.supplychain.manifests import declared_dependencies
from app.core.appsec.supplychain.typosquat import INSTALL_HOOKS, near_matches, unpinned
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity


class NameConfusionEngine:
    meta = EngineMeta(
        id="appsec.supplychain.name_confusion",
        version="1.0.0",
        name="Dependency name-confusion and install-hook signals",
        pillar=Pillar.SCA,
        tool="built-in",
        description=(
            "Flags dependency names resembling widely-used packages, unpinned "
            "versions, and npm install hooks. Reads files; consults no registry."
        ),
    )

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(declared_dependencies(workspace))

    def _install_hooks(self, workspace: Workspace) -> list[str]:
        found: list[str] = []
        for path in workspace.files:
            if path.name != "package.json":
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                continue
            relative = str(path.relative_to(workspace.root))
            for hook in INSTALL_HOOKS:
                if hook in scripts:
                    found.append(f"{relative}: {hook} = {str(scripts[hook])[:200]}")
        return found

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        dependencies = declared_dependencies(workspace)
        if not dependencies:
            return []

        results: list[ScanResult] = []

        confusable = [
            (dependency, matches)
            for dependency in dependencies
            if (matches := near_matches(dependency))
        ]
        if confusable:
            listed = "\n".join(
                f"{dependency.ecosystem}:{dependency.name} [{dependency.manifest}] — "
                + "; ".join(reason for _, reason in matches)
                for dependency, matches in confusable
            )
            results.append(
                ScanResult(
                    id="KERVY-SUPPLY-030",
                    title=(f"{len(confusable)} dependency name(s) resemble widely-used packages"),
                    category=Category.DESIGN,
                    severity=Severity.LOW,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="supplychain/name-confusion",
                    description=(
                        "These names are close to those of widely-used packages. That is "
                        "a reason to look, not a finding of wrongdoing: legitimate "
                        "packages routinely wrap or extend a popular name. Confirm each "
                        "is the package that was intended.\n\n"
                        "No registry was consulted, so this says nothing about whether a "
                        "package with the resembled name also exists upstream."
                    ),
                    evidence=listed,
                    impact=(
                        "If one of these is not the intended package, it runs with the "
                        "privileges of the build and of everything that imports it."
                    ),
                    remediation=(
                        "Check each against the package's project page and pin it to a "
                        "known-good version with a hash where the ecosystem supports one."
                    ),
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                )
            )

        loose = [dependency for dependency in dependencies if unpinned(dependency)]
        if loose:
            listed = "\n".join(
                f"{dependency.ecosystem}:{dependency.name} [{dependency.manifest}]"
                for dependency in sorted(loose, key=lambda item: (item.ecosystem, item.name))
            )
            results.append(
                ScanResult(
                    id="KERVY-SUPPLY-031",
                    title=f"{len(loose)} dependenc{'y' if len(loose) == 1 else 'ies'} unpinned",
                    category=Category.DESIGN,
                    severity=Severity.LOW,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="supplychain/unpinned",
                    description=(
                        "These dependencies carry no version constraint, so a build takes "
                        "whatever the registry serves at the time. A compromised release "
                        "then reaches the build with no change on this side, and two "
                        "builds of the same commit can differ."
                    ),
                    evidence=listed,
                    impact=(
                        "A malicious or broken release is picked up automatically, and "
                        "builds are not reproducible."
                    ),
                    remediation=(
                        "Pin to a version range you have reviewed, and use a lock file "
                        "with hashes so the resolved set is what was reviewed."
                    ),
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                )
            )

        hooks = self._install_hooks(workspace)
        if hooks:
            results.append(
                ScanResult(
                    id="KERVY-SUPPLY-032",
                    title=f"{len(hooks)} npm lifecycle script(s) run code at install time",
                    category=Category.DESIGN,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="supplychain/install-hooks",
                    description=(
                        "These scripts execute during `npm install`, before any code is "
                        "reviewed or any test runs. Plenty of legitimate packages build "
                        "native code this way, so this is not a vulnerability — it is "
                        "where an install-time supply-chain attack lands, and therefore "
                        "worth knowing about."
                    ),
                    evidence="\n".join(hooks),
                    impact=(
                        "Code here runs with the privileges of whoever runs the install, "
                        "which in CI is usually the build's full credential set."
                    ),
                    remediation=(
                        "Confirm each script is one you wrote and expect. In CI, consider "
                        "`--ignore-scripts` for installs that do not need them."
                    ),
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                )
            )

        return results
