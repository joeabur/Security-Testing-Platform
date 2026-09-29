"""Reporting the licence obligations a dependency set carries.

This engine reports obligations; it does not declare violations. Whether
AGPL-3.0 is a problem depends on whether the product is distributed, hosted, or
itself open source — facts the scanner does not have. Emitting "licence
violation" without them would be the kind of confident-and-wrong finding that
teaches a team to ignore the tool.

Licence data comes from installed package metadata where the environment has it
(`importlib.metadata`, for Python packages actually installed alongside the
workspace) and from `package.json` for npm. A dependency whose licence cannot
be determined is reported as unknown, in its own finding, rather than assumed
permissive.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from app.core.appsec.contract import EngineMeta, Pillar
from app.core.appsec.supplychain.licenses import (
    OBLIGATIONS,
    LicenseRisk,
    classify,
    from_classifier,
)
from app.core.appsec.supplychain.manifests import Dependency, declared_dependencies
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

#: Risk bands that get their own finding. Permissive and public-domain do not:
#: a finding per MIT dependency is noise that buries the two that matter.
_REPORTED = {
    LicenseRisk.NETWORK_COPYLEFT: Severity.MEDIUM,
    LicenseRisk.STRONG_COPYLEFT: Severity.LOW,
    LicenseRisk.WEAK_COPYLEFT: Severity.INFORMATIONAL,
    LicenseRisk.PROPRIETARY_OR_UNKNOWN: Severity.INFORMATIONAL,
}

_RULE_IDS = {
    LicenseRisk.NETWORK_COPYLEFT: "KERVY-SUPPLY-020",
    LicenseRisk.STRONG_COPYLEFT: "KERVY-SUPPLY-021",
    LicenseRisk.WEAK_COPYLEFT: "KERVY-SUPPLY-022",
    LicenseRisk.PROPRIETARY_OR_UNKNOWN: "KERVY-SUPPLY-023",
}


def _npm_license(workspace: Workspace, dependency: Dependency) -> str | None:
    """A dependency's licence from its installed `node_modules` metadata."""
    import json

    package = workspace.root / "node_modules" / dependency.name / "package.json"
    if not package.is_file() or not workspace.contains(package):
        return None
    try:
        data = json.loads(package.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("license") or data.get("licence")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        kind = value.get("type")
        return kind if isinstance(kind, str) else None
    return None


def _python_license(dependency: Dependency) -> str | None:
    """A dependency's licence from installed distribution metadata.

    Three sources, in this order, because each earlier one is more precise:

    1. `License-Expression` (PEP 639) — already an SPDX expression.
    2. The legacy `License` field, when short. Usually an SPDX identifier
       (`Apache-2.0`); bounded by length because it is just as often a whole
       licence text pasted in.
    3. A Trove `License ::` classifier, mapped through `CLASSIFIER_TO_SPDX`.
       Classifier text like "Apache Software License" is prose, not an
       identifier, so it has to be mapped rather than trimmed — reading it
       literally put every such package in the "unknown" bucket.
    """
    from importlib.metadata import PackageNotFoundError, metadata

    try:
        meta = metadata(dependency.name)
    except (PackageNotFoundError, ValueError):
        return None

    expression = meta.get("License-Expression")
    if expression:
        return str(expression)

    legacy = meta.get("License")
    if legacy and len(str(legacy)) <= 64 and "\n" not in str(legacy):
        return str(legacy)

    for value in meta.get_all("Classifier") or []:
        text = str(value)
        if not text.startswith("License ::"):
            continue
        mapped = from_classifier(text)
        if mapped:
            return mapped
        # An unmapped classifier is returned verbatim, so it classifies as
        # unknown and appears in the finding's evidence. That is the signal to
        # extend CLASSIFIER_TO_SPDX, rather than a silent miscategorisation.
        return text.split("::")[-1].strip()
    return None


#: How a dependency's licence is looked up. A seam, not a test hook: licence
#: data can come from installed metadata (the default), from a lock file that
#: records it, or from an SBOM an operator already produced — and which of those
#: is available differs per deployment. Returning `None` means "could not
#: determine", which classifies as unknown rather than permissive.
LicenseLookup = Callable[[Workspace, Dependency], str | None]


def default_license_lookup(workspace: Workspace, dependency: Dependency) -> str | None:
    if dependency.ecosystem == "pypi":
        return _python_license(dependency)
    return _npm_license(workspace, dependency)


class LicenseRiskEngine:
    meta = EngineMeta(
        id="appsec.supplychain.license",
        version="1.0.0",
        name="Dependency licence risk",
        pillar=Pillar.SCA,
        tool="built-in",
        description=(
            "Classifies declared dependencies by licence obligation. Reads files "
            "and installed metadata; makes no network calls."
        ),
    )

    def __init__(self, *, lookup: LicenseLookup | None = None) -> None:
        self._lookup = lookup or default_license_lookup

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(declared_dependencies(workspace))

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        dependencies = declared_dependencies(workspace)
        if not dependencies:
            return []

        by_risk: dict[LicenseRisk, list[tuple[Dependency, str]]] = defaultdict(list)
        for dependency in dependencies:
            expression = self._lookup(workspace, dependency)
            by_risk[classify(expression)].append((dependency, expression or "not stated"))

        results: list[ScanResult] = []
        for risk, severity in _REPORTED.items():
            entries = by_risk.get(risk)
            if not entries:
                continue
            listed = "\n".join(
                f"{dependency.ecosystem}:{dependency.name} "
                f"{dependency.version_spec or '(unpinned)'} — {expression} "
                f"[{dependency.manifest}]"
                for dependency, expression in sorted(
                    entries, key=lambda item: (item[0].ecosystem, item[0].name)
                )
            )
            unknown = risk is LicenseRisk.PROPRIETARY_OR_UNKNOWN
            results.append(
                ScanResult(
                    id=_RULE_IDS[risk],
                    title=(
                        f"{len(entries)} dependenc{'y' if len(entries) == 1 else 'ies'} "
                        f"under {risk.value.replace('_', ' ')} licences"
                    ),
                    category=Category.DESIGN,
                    severity=severity,
                    confidence=(Confidence.DESIGN_REVIEW if unknown else Confidence.HIGH),
                    endpoint=f"supplychain/license/{risk.value}",
                    description=(
                        f"{OBLIGATIONS[risk]}\n\nThis is the obligation the licence "
                        "carries, not a finding that it has been breached: whether it "
                        "matters depends on how this software is distributed, which the "
                        "scanner does not know."
                    ),
                    evidence=listed,
                    impact=(
                        "Unknown until someone reads the actual terms."
                        if unknown
                        else "Legal and distribution obligations, not a security exposure."
                    ),
                    remediation=(
                        "Record the licence for each of these, or replace the dependency."
                        if unknown
                        else "Confirm with whoever owns licensing that this is acceptable "
                        "for how the product ships, and record the decision."
                    ),
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                )
            )
        return results
