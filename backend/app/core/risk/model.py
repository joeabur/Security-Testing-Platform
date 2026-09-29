"""The Kervy risk model (docs/BUILD_SPEC.md §12).

    risk = impact × likelihood × confidence_weight × exposure_modifier

Every input is an ordinal with a published numeric value, and the tables
below *are* the publication — `docs/risk-model.md` is generated from them,
so the documentation cannot drift from the code that scores.

Two properties this module exists to guarantee:

* **The rationale always matches the number.** `severity_rationale` is
  generated from the same inputs that produced the score, in the same call.
  A hand-written rationale beside a computed score drifts the first time
  either changes, and a reader who spots the mismatch stops trusting both.
* **Scoring systems are never blended.** This produces the Kervy score and
  nothing else. CVSS and AIVSS live in their own fields, carry their own
  vectors, and are never averaged into this number (§12).

`likelihood` incorporates the measured ASR **lower bound** for probabilistic
findings, not the point estimate. A 3/5 success rate has a lower bound near
0.19; scoring it as 0.6 would treat sampling noise as an established fact.
"""

from dataclasses import dataclass
from enum import StrEnum

from app.core.probes.models import Confidence, Severity

RISK_MODEL_VERSION = "kervy-v1"


class Impact(StrEnum):
    """What it costs if this is exercised."""

    NEGLIGIBLE = "negligible"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"
    SEVERE = "severe"


class Exposure(StrEnum):
    """Who can reach it."""

    INTERNAL_AUTHENTICATED = "internal_authenticated"
    INTERNAL_UNAUTHENTICATED = "internal_unauthenticated"
    INTERNET_AUTHENTICATED = "internet_authenticated"
    INTERNET_UNAUTHENTICATED = "internet_unauthenticated"


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


# --- published tables ----------------------------------------------------
# These are the numbers docs/risk-model.md publishes and the report appendix
# reproduces. Changing one is a change to every score the platform has
# produced, so RISK_MODEL_VERSION is bumped alongside it.

IMPACT_VALUES: dict[Impact, float] = {
    Impact.NEGLIGIBLE: 1.0,
    Impact.MINOR: 3.0,
    Impact.MODERATE: 5.0,
    Impact.MAJOR: 8.0,
    Impact.SEVERE: 10.0,
}

# `confidence_weight` down-weights a detection whose basis is weaker. A
# design-review finding is not less true, but it has not been exercised, and
# the score should not read as though it had been.
CONFIDENCE_WEIGHTS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.8,
    Confidence.LOW: 0.6,
    Confidence.DESIGN_REVIEW: 0.5,
}

EXPOSURE_MODIFIERS: dict[Exposure, float] = {
    Exposure.INTERNAL_AUTHENTICATED: 0.6,
    Exposure.INTERNAL_UNAUTHENTICATED: 0.8,
    Exposure.INTERNET_AUTHENTICATED: 0.9,
    Exposure.INTERNET_UNAUTHENTICATED: 1.0,
}

# A finding in production is the same defect as one in dev, but the standing
# risk is not. This multiplies the exposure modifier rather than the impact:
# what changes is who can reach it today, not what it would cost.
ENVIRONMENT_MODIFIERS: dict[Environment, float] = {
    Environment.DEV: 0.5,
    Environment.TEST: 0.6,
    Environment.STAGING: 0.8,
    Environment.PRODUCTION: 1.0,
}

# Severity bands over the 0-10 score. Published, so a reader can check the
# banding rather than trust the label.
SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (1.0, Severity.LOW),
    (0.0, Severity.INFORMATIONAL),
)


@dataclass(frozen=True)
class RiskInputs:
    """Everything that goes into a score, recorded with the score itself."""

    impact: Impact
    # 0.0-1.0. For a probabilistic finding this is the ASR interval's lower
    # bound; for a deterministic one it is 1.0; for a design-review finding
    # it is an estimate of how readily the condition would be reached.
    likelihood: float
    confidence: Confidence
    exposure: Exposure
    environment: Environment

    def as_dict(self) -> dict[str, object]:
        return {
            "impact": self.impact.value,
            "likelihood": round(self.likelihood, 4),
            "confidence": self.confidence.value,
            "exposure": self.exposure.value,
            "environment": self.environment.value,
        }


@dataclass(frozen=True)
class RiskScore:
    model: str
    value: float
    severity: Severity
    rationale: str
    inputs: RiskInputs

    def as_dict(self) -> dict[str, object]:
        return {
            "model": self.model,
            "value": self.value,
            "severity": self.severity.value,
            "inputs": self.inputs.as_dict(),
        }


def severity_for(value: float) -> Severity:
    for threshold, severity in SEVERITY_BANDS:
        if value >= threshold:
            return severity
    return Severity.INFORMATIONAL


def score(inputs: RiskInputs) -> RiskScore:
    """Compute the score and the rationale that explains it, together.

    Generating both here is the point: there is no path that produces one
    without the other, so a rationale cannot describe a score the finding
    does not carry.
    """
    likelihood = max(0.0, min(1.0, inputs.likelihood))
    impact = IMPACT_VALUES[inputs.impact]
    confidence_weight = CONFIDENCE_WEIGHTS[inputs.confidence]
    exposure = EXPOSURE_MODIFIERS[inputs.exposure] * ENVIRONMENT_MODIFIERS[inputs.environment]

    value = round(impact * likelihood * confidence_weight * exposure, 1)
    severity = severity_for(value)

    return RiskScore(
        model=RISK_MODEL_VERSION,
        value=value,
        severity=severity,
        rationale=_rationale(
            inputs, impact, likelihood, confidence_weight, exposure, value, severity
        ),
        inputs=RiskInputs(
            impact=inputs.impact,
            likelihood=likelihood,
            confidence=inputs.confidence,
            exposure=inputs.exposure,
            environment=inputs.environment,
        ),
    )


def _rationale(
    inputs: RiskInputs,
    impact: float,
    likelihood: float,
    confidence_weight: float,
    exposure: float,
    value: float,
    severity: Severity,
) -> str:
    """The arithmetic, in words, with every factor named.

    Written so a reader can disagree with a specific input rather than with
    the number as a whole — which is the only kind of disagreement that
    leads anywhere.
    """
    likelihood_note = (
        "measured attack success rate (lower bound of the 95% interval)"
        if 0.0 < likelihood < 1.0
        else "reproduced on every attempt"
        if likelihood >= 1.0
        else "not observed to succeed"
    )
    return (
        f"Scored {value}/10 ({severity.value}) by {RISK_MODEL_VERSION}: "
        f"impact {inputs.impact.value} ({impact}) × likelihood {likelihood:.2f} "
        f"[{likelihood_note}] × confidence {inputs.confidence.value} "
        f"({confidence_weight}) × exposure {inputs.exposure.value} in "
        f"{inputs.environment.value} ({exposure:.2f}). "
        f"Severity follows the published banding, where {value} falls in the "
        f"{severity.value} band."
    )
