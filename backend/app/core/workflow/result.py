"""The result stage: the gate decides, and nothing else gets a vote.

§26 Phase 17 requires that *an AI recommendation cannot alter a gate decision*.
This module is where that is true, and it is true structurally rather than by
policy:

* The decision comes from `gate.evaluate`, the same function the CI gate and the
  pull-request check run use. One implementation, so a workflow, a pipeline and
  a pull request cannot disagree about the same findings.
* `evaluate` takes `GateFinding`s, which are built here from a finding's **real
  columns**. AI output lives in `ai_drafts`, keyed separately, and this module
  does not import the assistant package or read that table. There is no
  parameter through which a draft could be passed in.
* A draft only ever becomes a finding's real field when a human accepts it,
  which is an ordinary write to the finding — at which point it is a human's
  decision, not the model's, and the gate reads it like any other.

`tests/test_workflow.py` asserts the property directly: a draft proposing
CRITICAL against a LOW finding changes neither the decision nor the counts.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date

from app.core.gate.evaluate import evaluate
from app.core.gate.model import GateConfig, GateDecision, GateFinding, license_bands_from_mappings
from app.core.probes.models import Confidence, Severity
from app.models.finding import Finding

#: The gate a workflow uses when its own configuration says nothing. Matches the
#: CLI default so the two cannot drift.
DEFAULT_GATE = GateConfig(
    fail_on=(Severity.CRITICAL,),
    min_confidence=Confidence.MEDIUM,
    max_high=None,
    max_medium=None,
)


def gate_finding(finding: Finding) -> GateFinding:
    """A finding's real fields, and only those.

    Deliberately reads columns rather than anything computed elsewhere: the
    point of this function is that there is no seam through which a draft, a
    recommendation or any other advisory artifact could enter the decision.
    """
    return GateFinding(
        fingerprint=finding.fingerprint,
        title=finding.title,
        severity=Severity(str(getattr(finding.severity, "value", finding.severity))),
        confidence=Confidence(str(getattr(finding.confidence, "value", finding.confidence))),
        stability=str(getattr(finding.stability, "value", finding.stability) or "single_shot"),
        status=str(getattr(finding.status, "value", finding.status) or "new"),
        license_bands=license_bands_from_mappings(finding.mappings),
    )


def decide(
    findings: Sequence[Finding],
    config: GateConfig | None = None,
    *,
    today: date | None = None,
) -> GateDecision:
    """The workflow's verdict.

    No `drafts` parameter, no `recommendations` parameter, no override. Adding
    one would be the change that breaks the phase's acceptance criterion, which
    is why the signature is worth reading as part of the control.
    """
    return evaluate([gate_finding(item) for item in findings], config or DEFAULT_GATE, today=today)
