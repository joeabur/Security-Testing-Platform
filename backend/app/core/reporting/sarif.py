"""SARIF 2.1.0 output (docs/BUILD_SPEC.md §14).

SARIF is how these findings reach a code host's UI, so the mapping has to be
correct rather than merely accepted: `tests/test_reporting.py` validates the
output against the vendored OASIS schema, not against a hand-written
approximation that would pass things the spec rejects.

Two mapping decisions worth stating:

* **`level` is not severity.** SARIF has four levels — none, note, warning,
  error — and five severities exist here. Critical and high both map to
  `error` because SARIF has nothing stronger, and the Kervy score travels in
  `properties` where it keeps its full resolution instead of being flattened
  away.
* **A finding's stable identity becomes `partialFingerprints`.** That is the
  field SARIF consumers use to track an issue across runs, which is exactly
  what the Phase 7 fingerprint is for. Without it a code host would show
  every run's findings as new.
"""

import json
from typing import Any

from app.core.reporting.model import ReportData, ReportFinding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

# SARIF offers four levels; this platform distinguishes five severities. The
# collapse is lossless in practice because the real number stays in
# properties.security-severity, which is also what code hosts read.
_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFORMATIONAL": "note",
}


def _rule(finding: ReportFinding) -> dict[str, Any]:
    tags = ["security", finding.category.lower()]
    for framework, items in finding.mappings.items():
        if isinstance(items, list):
            tags.extend(f"{framework}:{item}" for item in items)

    return {
        "id": finding.probe_id,
        "name": finding.probe_id.replace(".", "-"),
        "shortDescription": {"text": finding.title[:200]},
        "fullDescription": {"text": finding.description[:2000] or finding.title},
        "help": {
            "text": finding.remediation[:2000] or "See the finding's remediation guidance.",
        },
        "defaultConfiguration": {"level": _LEVELS.get(finding.severity, "warning")},
        "properties": {
            "tags": tags,
            # The convention code hosts read for a numeric severity.
            "security-severity": str(finding.risk_score),
            "probe_version": finding.probe_version,
        },
    }


def _result(finding: ReportFinding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.probe_id,
        "ruleIndex": rule_index,
        "level": _LEVELS.get(finding.severity, "warning"),
        "message": {"text": f"{finding.title}\n\n{finding.severity_rationale}"},
        "locations": [
            {
                "physicalLocation": {
                    # A surface is a route or a file path, not always a file
                    # on disk. SARIF requires a URI, so the surface is the
                    # URI and the reader is told which it is.
                    "artifactLocation": {"uri": _location_uri(finding.surface)},
                }
            }
        ],
        # What SARIF consumers use to track an issue across runs — and what
        # the Phase 7 fingerprint exists to provide.
        "partialFingerprints": {"kervyFingerprint/v1": finding.fingerprint},
        "properties": {
            "kervy_risk_score": finding.risk_score,
            "kervy_risk_model": finding.risk_model,
            "kervy_severity": finding.severity,
            "confidence": finding.confidence,
            "stability": finding.stability,
            "status": finding.status,
            "times_seen": finding.times_seen,
        },
    }

    if finding.attack_success_rate:
        # Carried explicitly rather than folded into the level: a
        # probabilistic result and a deterministic one are different claims,
        # and SARIF's level cannot express the difference.
        result["properties"]["attack_success_rate"] = finding.attack_success_rate
    if finding.control_success_rate:
        result["properties"]["control_success_rate"] = finding.control_success_rate
    if finding.evidence_ref:
        result["properties"]["evidence_ref"] = finding.evidence_ref
    if finding.reproduction:
        result["properties"]["reproduction"] = finding.reproduction
    return result


def _location_uri(surface: str) -> str:
    """A SARIF-acceptable URI for a surface.

    A code path is used as-is so a code host can link to the file; an HTTP
    surface like `GET /api/orders/{id}` is not a path, so it is expressed as
    one rather than pretending to be a file that exists.
    """
    cleaned = surface.strip()
    if " " in cleaned:
        method, _, path = cleaned.partition(" ")
        return f"{path.lstrip('/')}#{method.lower()}"
    return cleaned.lstrip("/") or "unknown"


def to_sarif(report: ReportData) -> dict[str, Any]:
    """Render the report as a SARIF 2.1.0 log."""
    rules: list[dict[str, Any]] = []
    rule_indexes: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        if finding.probe_id not in rule_indexes:
            rule_indexes[finding.probe_id] = len(rules)
            rules.append(_rule(finding))
        results.append(_result(finding, rule_indexes[finding.probe_id]))

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Kervy Security",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/joeabur/Generative-AI-Risk-Identification-Security-Testing-Platform",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": report.halted_reason is None,
                        "startTimeUtc": report.generated_at.isoformat().replace("+00:00", "Z"),
                        **(
                            {"exitCodeDescription": report.halted_reason}
                            if report.halted_reason
                            else {}
                        ),
                    }
                ],
                "results": results,
                "properties": {
                    # Coverage honesty survives the format conversion: a
                    # SARIF consumer can see what was not tested, not just
                    # what was found (§14).
                    "not_tested": [
                        {"area": item.area, "reason": item.reason, "probe_id": item.probe_id}
                        for item in report.not_tested
                    ],
                    "checks_completed": report.checks_completed,
                    "checks_total": report.checks_total,
                    "requests_blocked": report.requests_blocked,
                    "authorization_digest": report.authorization_digest,
                    "roe_digest": report.roe_digest,
                },
            }
        ],
    }


def to_sarif_json(report: ReportData) -> str:
    """SARIF, serialized deterministically.

    Sorted keys and a fixed indent for the same reason the canonical JSON has
    them: two runs of the same report must differ only where the facts do,
    which is what lets a golden snapshot mean something.
    """
    return json.dumps(to_sarif(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
