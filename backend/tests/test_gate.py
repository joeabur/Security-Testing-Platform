"""The CI/CD security gate (docs/BUILD_SPEC.md §23).

§23 states the failure mode this module is designed around: *gating on
unstable, low-confidence AI findings makes pipelines flaky and gets the tool
disabled by the first adopting team.* So the tests that matter most here are
the ones asserting what the gate refuses to fail on.
"""

from datetime import date

import pytest

from app.core.gate.evaluate import evaluate, load_config
from app.core.gate.model import (
    ExitCode,
    GateConfig,
    GateConfigError,
    GateFinding,
)
from app.core.probes.models import Confidence, Severity

TODAY = date(2026, 6, 1)


def _finding(
    *,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    stability: str = "deterministic",
    status: str = "new",
    fingerprint: str = "sha256:" + "1" * 64,
    title: str = "Direct prompt injection",
    license_bands: tuple[str, ...] = (),
) -> GateFinding:
    return GateFinding(
        fingerprint=fingerprint,
        title=title,
        severity=severity,
        confidence=confidence,
        stability=stability,
        status=status,
        license_bands=license_bands,
    )


# --- what the gate refuses to fail on ------------------------------------


def test_a_single_shot_finding_never_fails_a_build() -> None:
    """§23's rule, and the reason the gate has any credibility: one
    observation is not a measurement, and a pipeline that fails on one fails
    arbitrarily."""
    decision = evaluate([_finding(stability="single_shot")], GateConfig(), today=TODAY)

    assert decision.passed
    assert decision.exit_code is ExitCode.PASS
    assert "One observation is not a measurement" in decision.excluded[0].reason


def test_a_low_confidence_finding_does_not_fail_the_default_gate() -> None:
    decision = evaluate([_finding(confidence=Confidence.LOW)], GateConfig(), today=TODAY)
    assert decision.passed
    assert "below min_confidence" in decision.excluded[0].reason


def test_a_design_review_finding_does_not_fail_the_default_gate() -> None:
    """Architectural observations are for humans to weigh, not for a build to
    die on."""
    decision = evaluate([_finding(confidence=Confidence.DESIGN_REVIEW)], GateConfig(), today=TODAY)
    assert decision.passed


@pytest.mark.parametrize("status", ["false_positive", "accepted_risk", "closed"])
def test_a_finding_a_human_already_ruled_on_is_not_re_blocked(status: str) -> None:
    """Otherwise the triage workflow is decorative: someone accepts a risk and
    the pipeline keeps failing anyway."""
    decision = evaluate([_finding(status=status)], GateConfig(), today=TODAY)
    assert decision.passed
    assert status in decision.excluded[0].reason


# --- what it does fail on -------------------------------------------------


def test_a_critical_deterministic_finding_fails_the_default_gate() -> None:
    decision = evaluate([_finding(severity=Severity.CRITICAL)], GateConfig(), today=TODAY)

    assert not decision.passed
    assert decision.exit_code is ExitCode.GATE_FAILED
    assert decision.blocking[0].severity is Severity.CRITICAL
    assert decision.reasons


def test_listing_only_high_still_catches_a_critical() -> None:
    """A gate configured with `[high]` that let a critical through would be
    indefensible: someone writing that list means "this bad and worse"."""
    config = GateConfig(fail_on=(Severity.HIGH,))
    decision = evaluate([_finding(severity=Severity.CRITICAL)], config, today=TODAY)

    assert not decision.passed
    assert decision.blocking[0].severity is Severity.CRITICAL


def test_a_medium_count_over_its_limit_fails_even_when_fail_on_excludes_medium() -> None:
    config = GateConfig(fail_on=(Severity.CRITICAL,), max_medium=1)
    findings = [
        _finding(severity=Severity.MEDIUM, fingerprint=f"sha256:{index:064d}") for index in range(3)
    ]

    decision = evaluate(findings, config, today=TODAY)

    assert not decision.passed
    assert "exceeds max_medium=1" in " ".join(decision.reasons)
    assert decision.blocking == []  # the count failed it, not a single finding


def test_the_counts_exclude_what_the_gate_skipped() -> None:
    """A gate that counts findings it then ignores would report numbers that
    do not explain its own verdict."""
    decision = evaluate(
        [
            _finding(severity=Severity.HIGH, stability="single_shot"),
            _finding(severity=Severity.MEDIUM, fingerprint="sha256:" + "2" * 64),
        ],
        GateConfig(),
        today=TODAY,
    )
    assert decision.counts["HIGH"] == 0
    assert decision.counts["MEDIUM"] == 1


# --- ignores --------------------------------------------------------------


IGNORE_CONFIG = """
security_gate:
  fail_on: [critical, high]
  ignore:
    - fingerprint: sha256:1111111111111111111111111111111111111111111111111111111111111111
      reason: "accepted risk, TICKET-987"
      expires: 2026-12-31
"""


def test_an_active_ignore_suppresses_its_finding_and_says_why() -> None:
    decision = evaluate([_finding()], load_config(IGNORE_CONFIG), today=TODAY)

    assert decision.passed
    assert "TICKET-987" in decision.excluded[0].reason


def test_an_expired_ignore_stops_applying() -> None:
    """The point of requiring an expiry: an exclusion nobody revisits is how a
    gate quietly stops covering the thing it was added for."""
    decision = evaluate([_finding()], load_config(IGNORE_CONFIG), today=date(2027, 1, 1))

    assert not decision.passed
    assert decision.blocking[0].fingerprint.endswith("1" * 8)


def test_an_ignore_without_a_reason_or_expiry_is_refused() -> None:
    with pytest.raises(GateConfigError, match="expires"):
        load_config(
            "security_gate:\n  ignore:\n    - fingerprint: sha256:abc\n      reason: because\n"
        )


# --- configuration --------------------------------------------------------


def test_the_documented_example_configuration_parses() -> None:
    """The §23 example, verbatim. If the documentation and the parser drift,
    the first thing an adopting team copies will not work."""
    config = load_config(
        """
security_gate:
  fail_on: [critical, high]
  max_high: 0
  max_medium: 5
  min_confidence: medium
  require_stability: [deterministic, probabilistic]
  ignore:
    - fingerprint: sha256:aaaa
      reason: "accepted risk, TICKET-987"
      expires: 2026-12-31
"""
    )
    assert config.fail_on == (Severity.CRITICAL, Severity.HIGH)
    assert config.max_high == 0
    assert config.max_medium == 5
    assert config.min_confidence is Confidence.MEDIUM
    assert config.require_stability == ("deterministic", "probabilistic")
    assert config.ignores[0].reason.endswith("TICKET-987")


def test_a_misspelled_setting_is_an_error_not_a_shrug() -> None:
    """`max_hihg: 0` silently doing nothing would leave a team believing they
    had a gate they did not have."""
    with pytest.raises(GateConfigError, match="max_hihg"):
        load_config("security_gate:\n  max_hihg: 0\n")


def test_an_empty_configuration_is_the_documented_default() -> None:
    config = load_config("")
    assert config.fail_on == (Severity.CRITICAL, Severity.HIGH)
    assert "single_shot" not in config.require_stability


@pytest.mark.parametrize(
    "document",
    [
        "security_gate:\n  fail_on: [enormous]\n",
        "security_gate:\n  min_confidence: vibes\n",
        "security_gate:\n  require_stability: [maybe]\n",
        "security_gate:\n  max_high: -1\n",
        "security_gate:\n  max_high: not-a-number\n",
        "security_gate: [1, 2]\n",
        "- just\n- a\n- list\n",
    ],
)
def test_nonsense_configuration_is_refused(document: str) -> None:
    with pytest.raises(GateConfigError):
        load_config(document)


def test_gating_on_single_shot_is_possible_but_must_be_asked_for() -> None:
    """Not forbidden — an operator who understands the trade-off may want it —
    but never the default."""
    config = load_config("security_gate:\n  require_stability: [single_shot]\n")
    decision = evaluate([_finding(stability="single_shot")], config, today=TODAY)
    assert not decision.passed


# --- licence policy --------------------------------------------------------


def test_a_forbidden_license_band_fails_the_build_even_at_low_severity() -> None:
    """The whole point: `strong_copyleft` is `Severity.LOW` by design
    (docs/supply-chain.md), so it would never reach even the default
    `fail_on`'s floor on severity alone — an operator who names a band here
    is making a policy decision independent of that threshold."""
    config = GateConfig(forbidden_license_bands=("strong_copyleft",))
    finding = _finding(severity=Severity.LOW, license_bands=("strong_copyleft",))

    decision = evaluate([finding], config, today=TODAY)

    assert not decision.passed
    assert finding in decision.blocking
    assert "forbidden licence band" in " ".join(decision.reasons)
    assert "strong_copyleft" in " ".join(decision.reasons)


def test_a_license_band_not_on_the_forbidden_list_does_not_fail() -> None:
    config = GateConfig(forbidden_license_bands=("network_copyleft",))
    finding = _finding(severity=Severity.LOW, license_bands=("weak_copyleft",))

    decision = evaluate([finding], config, today=TODAY)

    assert decision.passed


def test_forbidden_license_bands_is_empty_by_default() -> None:
    """A finding carrying a band is not blocking until an operator actually
    names that band — existing configurations must not change behaviour."""
    finding = _finding(severity=Severity.LOW, license_bands=("network_copyleft",))

    decision = evaluate([finding], GateConfig(), today=TODAY)

    assert decision.passed


def test_a_settled_status_still_excludes_a_forbidden_band_finding() -> None:
    """A licence policy is not a bypass of triage: a human who already
    marked this accepted_risk or false_positive still gets the last word."""
    config = GateConfig(forbidden_license_bands=("network_copyleft",))
    finding = _finding(
        severity=Severity.LOW, license_bands=("network_copyleft",), status="accepted_risk"
    )

    decision = evaluate([finding], config, today=TODAY)

    assert decision.passed
    assert decision.excluded[0].reason.startswith("status is accepted_risk")


def test_a_critical_finding_with_a_forbidden_band_reports_one_reason_per_trigger() -> None:
    """A finding that trips both the severity threshold and the licence
    policy is not double-counted, but each trigger still gets its own
    stated reason."""
    config = GateConfig(forbidden_license_bands=("network_copyleft",))
    finding = _finding(severity=Severity.CRITICAL, license_bands=("network_copyleft",))

    decision = evaluate([finding], config, today=TODAY)

    assert not decision.passed
    assert decision.blocking == [finding]
    assert len(decision.reasons) == 2


def test_an_unknown_license_band_in_config_is_refused() -> None:
    with pytest.raises(GateConfigError, match="unknown licence band"):
        load_config("security_gate:\n  forbidden_license_bands: [agpl]\n")


def test_forbidden_license_bands_parses_from_yaml() -> None:
    config = load_config("security_gate:\n  forbidden_license_bands: [network_copyleft]\n")
    assert config.forbidden_license_bands == ("network_copyleft",)


# --- the wire shape -------------------------------------------------------


def test_a_finding_from_the_api_is_read_without_a_database() -> None:
    finding = GateFinding.from_api(
        {
            "fingerprint": "sha256:" + "3" * 64,
            "title": "Command injection",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "stability": "deterministic",
            "status": "confirmed",
        }
    )
    assert finding.severity is Severity.CRITICAL


def test_a_finding_with_no_stability_is_treated_as_single_shot() -> None:
    """Fail closed: an unknown stability must not be gated on."""
    finding = GateFinding.from_api(
        {"fingerprint": "sha256:x", "severity": "HIGH", "confidence": "HIGH"}
    )
    assert finding.stability == "single_shot"
    assert evaluate([finding], GateConfig(), today=TODAY).passed


def test_a_license_band_is_read_from_the_mappings_other_bucket() -> None:
    """There is no dedicated API field for this: `LicenseRiskEngine`'s
    `LICENSE-BAND:...` framework reference rides on `mappings["other"]`,
    the same bucket `group_mappings()` files any reference under that it
    does not recognise a namespace for."""
    finding = GateFinding.from_api(
        {
            "fingerprint": "sha256:" + "4" * 64,
            "severity": "LOW",
            "confidence": "HIGH",
            "mappings": {"other": ["LICENSE-BAND:network_copyleft"], "cwe": ["CWE-1"]},
        }
    )
    assert finding.license_bands == ("network_copyleft",)


def test_a_finding_with_no_mappings_has_no_license_bands() -> None:
    finding = GateFinding.from_api(
        {"fingerprint": "sha256:x", "severity": "LOW", "confidence": "HIGH"}
    )
    assert finding.license_bands == ()


def test_an_unreadable_finding_is_a_configuration_error_not_a_pass() -> None:
    with pytest.raises(GateConfigError):
        GateFinding.from_api({"severity": "HIGH"})


def test_the_exit_codes_are_the_documented_numbers() -> None:
    """§20 publishes these, and CI scripts branch on them."""
    assert int(ExitCode.PASS) == 0
    assert int(ExitCode.GATE_FAILED) == 1
    assert int(ExitCode.CONFIG_ERROR) == 2
    assert int(ExitCode.AUTH_ERROR) == 3
    assert int(ExitCode.SCOPE_VIOLATION) == 4
