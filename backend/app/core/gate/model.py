"""The CI/CD security gate (docs/BUILD_SPEC.md §23).

The gate decides whether a pipeline fails. §23 makes one point sharply and
this module is built around it: *gating on unstable, low-confidence AI
findings makes pipelines flaky and gets the tool disabled by the first
adopting team.* A tool that blocks a deploy on a 2-of-5 probabilistic result
will be switched off within a week, and then it protects nothing.

So the default configuration refuses to gate on anything it cannot stand
behind, and every exclusion is reported rather than silently applied. A gate
that fails without saying which finding failed it is a gate people learn to
bypass.

Exit codes are part of the contract (§20), because CI has to tell "found
issues" apart from "refused to run":

    0  pass
    1  security gate failed
    2  configuration error
    3  authentication error
    4  scope violation
"""

from dataclasses import dataclass, field
from datetime import date
from enum import IntEnum
from typing import Any

from app.core.appsec.supplychain.licenses import LICENSE_BAND_FRAMEWORK_PREFIX
from app.core.probes.models import Confidence, Severity


class ExitCode(IntEnum):
    PASS = 0
    GATE_FAILED = 1
    CONFIG_ERROR = 2
    AUTH_ERROR = 3
    SCOPE_VIOLATION = 4


class GateConfigError(ValueError):
    """The configuration could not be understood.

    Its own type because it maps to exit code 2, and a misconfigured gate must
    never be reported as a pass.
    """


# Ordered most severe first, so "fail on high" means high and everything
# above it without the caller having to list them.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)

_CONFIDENCE_ORDER: tuple[Confidence, ...] = (
    Confidence.HIGH,
    Confidence.MEDIUM,
    Confidence.LOW,
    Confidence.DESIGN_REVIEW,
)

# Stability values a gate may act on. `single_shot` is absent by design:
# §23's "never gate on single-shot results". One observation is not a
# measurement, and a pipeline that fails on one will fail arbitrarily.
DEFAULT_STABILITY: tuple[str, ...] = ("deterministic", "probabilistic")


@dataclass(frozen=True)
class Ignore:
    """One accepted finding, with a reason and an expiry.

    Both are required. A permanent unexplained exclusion is how a gate
    quietly stops covering the thing it was added for; an expiry forces the
    decision to be revisited, and the reason tells the next person why.
    """

    fingerprint: str
    reason: str
    expires: date

    def active_on(self, today: date) -> bool:
        return today <= self.expires


@dataclass(frozen=True)
class GateConfig:
    fail_on: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH)
    max_high: int | None = 0
    max_medium: int | None = 5
    min_confidence: Confidence = Confidence.MEDIUM
    require_stability: tuple[str, ...] = DEFAULT_STABILITY
    ignores: tuple[Ignore, ...] = ()
    # §23's severity-threshold model answers "how bad", not "which licence
    # obligations are acceptable here" — a different question an operator
    # has to answer themselves, which is why this is a separate list rather
    # than another severity. A band named here blocks the build whenever a
    # `LicenseRiskEngine` finding carries it, independently of `fail_on`:
    # `strong_copyleft` is `Severity.LOW` by design (docs/supply-chain.md),
    # so it would never reach even the most permissive `fail_on` floor on
    # severity alone.
    forbidden_license_bands: tuple[str, ...] = ()

    def ignore_for(self, fingerprint: str, today: date) -> Ignore | None:
        for item in self.ignores:
            if item.fingerprint == fingerprint and item.active_on(today):
                return item
        return None


@dataclass(frozen=True)
class GateFinding:
    """The subset of a finding the gate reads.

    Deliberately not the whole `Finding`: the gate runs against whatever the
    API returned to a CLI, and depending on the ORM model here would make the
    decision impossible to test without a database.
    """

    fingerprint: str
    title: str
    severity: Severity
    confidence: Confidence
    stability: str
    status: str
    # Which licence bands (if any) `LicenseRiskEngine` classified this
    # finding under. There is no dedicated column for this anywhere in the
    # findings pipeline — it rides on `mappings["other"]`, the same bucket
    # `group_mappings()` already files any framework reference under that it
    # does not recognise a namespace for (`app/core/findings/normalize.py`).
    license_bands: tuple[str, ...] = ()

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "GateFinding":
        try:
            return cls(
                fingerprint=str(payload["fingerprint"]),
                title=str(payload.get("title", "")),
                severity=Severity(str(payload["severity"])),
                confidence=Confidence(str(payload["confidence"])),
                stability=str(payload.get("stability") or "single_shot"),
                status=str(payload.get("status") or "new"),
                license_bands=license_bands_from_mappings(payload.get("mappings")),
            )
        except (KeyError, ValueError) as exc:
            raise GateConfigError(f"unreadable finding in gate input: {exc}") from exc


def license_bands_from_mappings(mappings: Any) -> tuple[str, ...]:
    """Which `LicenseRisk` bands (if any) a finding's `mappings` carries.

    Shared by every place a `GateFinding` gets built — the CLI's
    `from_api()` here, and the pull-request check run and workflow gate
    (`app/core/vcs/service.py`, `app/core/workflow/result.py`), which each
    read a `Finding`'s own `mappings` column directly rather than a JSON
    payload. One implementation, so all three cannot drift on what counts
    as a licence-band match.
    """
    if not isinstance(mappings, dict):
        return ()
    other = mappings.get("other")
    if not isinstance(other, list):
        return ()
    return tuple(
        reference[len(LICENSE_BAND_FRAMEWORK_PREFIX) :]
        for reference in other
        if isinstance(reference, str) and reference.startswith(LICENSE_BAND_FRAMEWORK_PREFIX)
    )


@dataclass(frozen=True)
class Exclusion:
    """Why a finding did not count, so the report can say so."""

    finding: GateFinding
    reason: str


@dataclass
class GateDecision:
    passed: bool
    exit_code: ExitCode
    blocking: list[GateFinding] = field(default_factory=list)
    excluded: list[Exclusion] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def severity_at_least(severity: Severity, minimum: Severity) -> bool:
    return _SEVERITY_ORDER.index(severity) <= _SEVERITY_ORDER.index(minimum)


def confidence_at_least(confidence: Confidence, minimum: Confidence) -> bool:
    return _CONFIDENCE_ORDER.index(confidence) <= _CONFIDENCE_ORDER.index(minimum)
