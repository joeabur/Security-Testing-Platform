"""Promoting a `ScanResult` into a `Finding` (docs/BUILD_SPEC.md §11, §12).

This is the only place a finding is created, which is what keeps the
guarantees in one reviewable file:

* Identity comes from `fingerprint.py`, never from response text.
* The risk score and its rationale are produced together by the risk model,
  so a finding can never carry a number nobody can account for.
* `likelihood` uses the measured interval's **lower bound**, not the point
  estimate — a 3/5 success rate is not 60% established.
* CVSS and AIVSS are left empty here. §12 forbids manufacturing a CVSS
  vector for something CVSS cannot express, and "the model followed an
  injected instruction" is exactly that. An empty field is honest; a
  fabricated vector is not.
"""

from dataclasses import dataclass
from typing import Any

from app.core.findings.fingerprint import fingerprint
from app.core.findings.frameworks import versions_for
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.risk.model import (
    Environment,
    Exposure,
    Impact,
    RiskInputs,
    RiskScore,
    score,
)

# How a probe's own severity maps onto the impact ordinal. A probe's
# severity is its author's judgement about consequence, which is exactly
# what `impact` means; likelihood and exposure are supplied separately.
_IMPACT_FROM_SEVERITY: dict[Severity, Impact] = {
    Severity.CRITICAL: Impact.SEVERE,
    Severity.HIGH: Impact.MAJOR,
    Severity.MEDIUM: Impact.MODERATE,
    Severity.LOW: Impact.MINOR,
    Severity.INFORMATIONAL: Impact.NEGLIGIBLE,
}

# Likelihood for results with no measurement. A deterministic engine —
# SAST, IaC, a static API check — either found the condition or did not, so
# the condition is present with certainty; what is uncertain is whether it
# is reachable, and that is what `confidence` and `exposure` carry.
_DETERMINISTIC_LIKELIHOOD = 1.0
# A design-review finding describes a property of the design. It is not
# "probably false", but it has not been exercised, so it does not score as
# though it had been.
_DESIGN_REVIEW_LIKELIHOOD = 0.6


@dataclass(frozen=True)
class FindingDraft:
    """A finding, computed but not yet persisted."""

    fingerprint: str
    title: str
    category: Category
    probe_id: str
    probe_version: str
    surface: str
    severity: Severity
    severity_rationale: str
    confidence: Confidence
    stability: str
    risk: RiskScore
    attack_success_rate: dict[str, Any] | None
    control_success_rate: dict[str, Any] | None
    description: str
    impact: str
    remediation: str
    reproduction: tuple[str, ...]
    mappings: dict[str, list[str]]
    mapping_versions: dict[str, str]
    evidence_ref: str | None


def likelihood_from(result: ScanResult) -> float:
    """The likelihood input, from the measurement where one exists.

    §12: "likelihood incorporates the measured ASR lower bound for
    probabilistic findings". The lower bound rather than the rate, because
    the rate is a point estimate from a handful of trials and the interval
    is what the trials actually established.
    """
    measurement = result.measurement or {}
    attack = measurement.get("attack_success_rate") if isinstance(measurement, dict) else None
    if isinstance(attack, dict):
        interval = attack.get("ci95")
        if isinstance(interval, list | tuple) and len(interval) == 2:
            return float(interval[0])
        rate = attack.get("rate")
        if isinstance(rate, int | float):
            return float(rate)

    if result.confidence is Confidence.DESIGN_REVIEW:
        return _DESIGN_REVIEW_LIKELIHOOD
    return _DETERMINISTIC_LIKELIHOOD


def group_mappings(frameworks: tuple[str, ...]) -> dict[str, list[str]]:
    """Split the flat framework list into the §11 `mappings` block.

    Only prefixes this platform emits are recognised; anything else is kept
    under `other` rather than guessed at, because a mapping filed under the
    wrong framework is worse than one filed under none.
    """
    grouped: dict[str, list[str]] = {}
    prefixes = {
        "OWASP-LLM-2026:": "owasp_llm_2026",
        "OWASP-ASI-2026:": "owasp_asi_2026",
        "OWASP-API-2023:": "owasp_api_2023",
        "OWASP-ASVS:": "owasp_asvs",
        "MITRE-ATLAS:": "mitre_atlas",
        "MITRE-ATTACK:": "mitre_attack",
        "NIST-AI-RMF:": "nist_ai_rmf",
        "NIST-SSDF:": "nist_ssdf",
        "CWE-": "cwe",
    }
    for reference in frameworks:
        for prefix, key in prefixes.items():
            if reference.startswith(prefix):
                # CWEs keep their prefix because "CWE-79" is how they are
                # written everywhere; the others are stored bare.
                value = reference if key == "cwe" else reference[len(prefix) :]
                grouped.setdefault(key, []).append(value)
                break
        else:
            grouped.setdefault("other", []).append(reference)
    return grouped


def build_finding(
    result: ScanResult,
    *,
    exposure: Exposure,
    environment: Environment,
    mapping_versions: dict[str, str] | None = None,
) -> FindingDraft:
    """Compute a finding from one scan result."""
    measurement = result.measurement if isinstance(result.measurement, dict) else {}

    risk = score(
        RiskInputs(
            impact=_IMPACT_FROM_SEVERITY[result.severity],
            likelihood=likelihood_from(result),
            confidence=result.confidence,
            exposure=exposure,
            environment=environment,
        )
    )

    return FindingDraft(
        # An engine that computed its own stable identity keeps it; a
        # dynamic probe's is derived here from the surface and the
        # structural facts, never from response text.
        fingerprint=result.fingerprint
        or fingerprint(
            probe_id=result.probe_id,
            surface=result.endpoint,
            signature=f"{result.id} {result.title}",
        ),
        title=result.title,
        category=result.category,
        probe_id=result.probe_id,
        probe_version=result.probe_version,
        surface=result.endpoint,
        # The severity a reader sees is the one the risk model derived, not
        # the probe's own label — otherwise the number and the word could
        # disagree on the same finding.
        severity=risk.severity,
        severity_rationale=risk.rationale,
        confidence=result.confidence,
        stability=result.stability or "deterministic",
        risk=risk,
        attack_success_rate=measurement.get("attack_success_rate"),
        control_success_rate=measurement.get("control_success_rate"),
        description=result.description,
        impact=result.impact,
        remediation=result.remediation,
        reproduction=result.reproduction,
        mappings=group_mappings(result.frameworks),
        # Empty until §3.4's ingestion runs. An unverified version string is
        # worse than none: it implies a check nobody performed.
        # Derived from the mappings actually present, so a finding cannot
        # claim a framework edition it carries no reference for. An explicit
        # argument still wins, for a caller importing findings that were
        # mapped against a different edition elsewhere.
        mapping_versions=mapping_versions
        if mapping_versions is not None
        else versions_for(group_mappings(result.frameworks)),
        # Whatever the run stored for this result, if anything. Never a
        # placeholder: a finding that points at a bundle which does not exist
        # is worse than one that admits it has none.
        evidence_ref=result.evidence_ref,
    )
