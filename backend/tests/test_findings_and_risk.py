"""Phase 7 acceptance: "Fingerprint-stability test passes; every finding has
a generated `severity_rationale` matching its score" (docs/BUILD_SPEC.md
§26, §11, §12).
"""

import pytest

from app.core.findings.fingerprint import (
    evidence_signature,
    fingerprint,
    normalize_surface,
)
from app.core.findings.normalize import build_finding, group_mappings, likelihood_from
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.risk.model import (
    CONFIDENCE_WEIGHTS,
    ENVIRONMENT_MODIFIERS,
    EXPOSURE_MODIFIERS,
    IMPACT_VALUES,
    RISK_MODEL_VERSION,
    Environment,
    Exposure,
    Impact,
    RiskInputs,
    score,
    severity_for,
)
from app.core.risk.publish import render_markdown


def _result(**overrides: object) -> ScanResult:
    base: dict = {
        "id": "KERVY-API-050",
        "title": "Object readable by an account that does not own it",
        "category": Category.API_SECURITY,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "endpoint": "GET /api/orders/{order_id}",
        "description": "d",
        "evidence": "e",
        "impact": "i",
        "remediation": "r",
        "probe_id": "api.authz.bola",
        "probe_version": "1.0.0",
        "frameworks": ("OWASP-API-2023:API1", "CWE-639"),
        "reproduction": ("step one",),
    }
    base.update(overrides)
    return ScanResult(**base)  # type: ignore[arg-type]


# --- fingerprint stability ----------------------------------------------


def test_the_same_weakness_keeps_one_fingerprint_across_runs() -> None:
    """The acceptance criterion. A per-run canary, a timestamp and a request
    id all differ every run; if any of them reached the fingerprint, the
    same unfixed weakness would become a new finding each time and the
    history would be destroyed."""
    first = fingerprint(
        probe_id="ai.injection.direct.instruction_override",
        surface="POST /api/chat",
        signature="canary KERVY-CANARY-AAAA1111BBBB2222 at 2026-09-18T10:00:00Z req 9f3a1b2c",
    )
    second = fingerprint(
        probe_id="ai.injection.direct.instruction_override",
        surface="POST /api/chat",
        signature="canary KERVY-CANARY-FFFF9999EEEE8888 at 2026-11-02T23:45:01Z req 1122aabb",
    )

    assert first == second


def test_an_object_id_in_the_path_does_not_split_one_surface_into_many() -> None:
    """Otherwise a BOLA finding would be filed once per object id the scan
    happened to touch."""
    assert normalize_surface("GET /api/orders/41d6f0e2-1111-2222-3333-444455556666") == (
        normalize_surface("GET /api/orders/9021")
    )


def test_different_weaknesses_keep_different_fingerprints() -> None:
    """The counterpart: normalization must not be so aggressive that two
    genuinely different findings collapse into one."""
    bola = fingerprint(probe_id="api.authz.bola", surface="GET /api/orders/{id}", signature="x")
    authn = fingerprint(
        probe_id="api.auth.unauthenticated_access", surface="GET /api/orders/{id}", signature="x"
    )
    other_surface = fingerprint(
        probe_id="api.authz.bola", surface="GET /api/invoices/{id}", signature="x"
    )

    assert len({bola, authn, other_surface}) == 3


def test_evidence_signature_ignores_volatile_detail_but_not_content() -> None:
    assert evidence_signature("rule B602 at 2026-09-18T10:00:00Z") == evidence_signature(
        "rule B602 at 2026-09-19T11:00:00Z"
    )
    assert evidence_signature("rule B602") != evidence_signature("rule B324")


def test_a_finding_reuses_an_engine_computed_fingerprint() -> None:
    """A static engine already computes a stable identity from rule, path
    and code span; recomputing it here from the title would be worse."""
    draft = build_finding(
        _result(fingerprint="sha256:enginecomputed"),
        exposure=Exposure.INTERNET_UNAUTHENTICATED,
        environment=Environment.PRODUCTION,
    )

    assert draft.fingerprint == "sha256:enginecomputed"


# --- severity rationale matches the score -------------------------------


@pytest.mark.parametrize("impact", list(Impact))
@pytest.mark.parametrize("confidence", list(Confidence))
@pytest.mark.parametrize("exposure", list(Exposure))
def test_every_rationale_states_the_score_it_belongs_to(
    impact: Impact, confidence: Confidence, exposure: Exposure
) -> None:
    """The acceptance criterion. Generated together, in the same call, so a
    rationale cannot describe a number the finding does not carry."""
    result = score(
        RiskInputs(
            impact=impact,
            likelihood=0.8,
            confidence=confidence,
            exposure=exposure,
            environment=Environment.PRODUCTION,
        )
    )

    assert f"{result.value}/10" in result.rationale
    assert result.severity.value in result.rationale
    assert impact.value in result.rationale
    assert confidence.value in result.rationale
    assert exposure.value in result.rationale
    assert RISK_MODEL_VERSION in result.rationale


def test_the_score_is_the_published_arithmetic() -> None:
    """A reader must be able to reproduce the number from the published
    tables. If this fails, either the tables or the scorer moved."""
    inputs = RiskInputs(
        impact=Impact.MAJOR,
        likelihood=0.5,
        confidence=Confidence.MEDIUM,
        exposure=Exposure.INTERNET_UNAUTHENTICATED,
        environment=Environment.STAGING,
    )
    expected = round(
        IMPACT_VALUES[Impact.MAJOR]
        * 0.5
        * CONFIDENCE_WEIGHTS[Confidence.MEDIUM]
        * EXPOSURE_MODIFIERS[Exposure.INTERNET_UNAUTHENTICATED]
        * ENVIRONMENT_MODIFIERS[Environment.STAGING],
        1,
    )

    assert score(inputs).value == expected


def test_severity_follows_the_published_banding() -> None:
    assert severity_for(9.5) is Severity.CRITICAL
    assert severity_for(9.0) is Severity.CRITICAL
    assert severity_for(8.9) is Severity.HIGH
    assert severity_for(4.0) is Severity.MEDIUM
    assert severity_for(0.9) is Severity.INFORMATIONAL


def test_the_published_document_is_generated_from_the_scorer() -> None:
    """docs/risk-model.md is rendered from the same constants the scorer
    uses, so the published numbers cannot drift from the applied ones."""
    document = render_markdown()

    for value in IMPACT_VALUES.values():
        assert str(value) in document
    for weight in CONFIDENCE_WEIGHTS.values():
        assert str(weight) in document
    assert RISK_MODEL_VERSION in document
    assert "never blended" in document.lower()


# --- likelihood from measurement ----------------------------------------


def test_likelihood_uses_the_interval_lower_bound_not_the_rate() -> None:
    """A 3/5 success rate is not 60% established. §12 says the lower bound,
    and scoring the point estimate would treat sampling noise as fact."""
    measured = _result(
        measurement={
            "attack_success_rate": {"successes": 3, "trials": 5, "rate": 0.6, "ci95": [0.23, 0.88]}
        },
        stability="probabilistic",
    )

    assert likelihood_from(measured) == 0.23


def test_a_deterministic_result_scores_at_full_likelihood() -> None:
    assert likelihood_from(_result()) == 1.0


def test_a_design_review_finding_does_not_score_as_though_exercised() -> None:
    assert likelihood_from(_result(confidence=Confidence.DESIGN_REVIEW)) < 1.0


def test_a_probabilistic_finding_scores_below_the_same_deterministic_one() -> None:
    """The whole point of the measurement machinery: an attack that worked
    three times in five is a smaller problem than one that works every time,
    and the number has to say so."""
    deterministic = build_finding(
        _result(), exposure=Exposure.INTERNET_UNAUTHENTICATED, environment=Environment.PRODUCTION
    )
    probabilistic = build_finding(
        _result(
            measurement={
                "attack_success_rate": {
                    "successes": 3,
                    "trials": 5,
                    "rate": 0.6,
                    "ci95": [0.23, 0.88],
                }
            },
            stability="probabilistic",
        ),
        exposure=Exposure.INTERNET_UNAUTHENTICATED,
        environment=Environment.PRODUCTION,
    )

    assert probabilistic.risk.value < deterministic.risk.value


# --- three scoring systems, never blended -------------------------------


def test_cvss_and_aivss_are_left_empty_rather_than_manufactured() -> None:
    """§12: never manufacture a CVSS vector for "the model followed an
    injected instruction". An empty field is honest; a fabricated vector
    that a reader will paste into a calculator is not."""
    draft = build_finding(
        _result(probe_id="ai.injection.direct.instruction_override"),
        exposure=Exposure.INTERNET_UNAUTHENTICATED,
        environment=Environment.PRODUCTION,
    )

    assert draft.risk.model == RISK_MODEL_VERSION
    assert not hasattr(draft, "cvss_v4") or getattr(draft, "cvss_v4", None) is None


def test_the_severity_a_reader_sees_is_the_one_the_model_derived() -> None:
    """Otherwise the word and the number could disagree on the same finding."""
    draft = build_finding(
        _result(severity=Severity.CRITICAL, confidence=Confidence.DESIGN_REVIEW),
        exposure=Exposure.INTERNAL_AUTHENTICATED,
        environment=Environment.DEV,
    )

    assert draft.severity is severity_for(draft.risk.value)
    assert f"{draft.risk.value}/10" in draft.severity_rationale


# --- mappings -------------------------------------------------------------


def test_mappings_are_grouped_by_framework_and_never_guessed() -> None:
    grouped = group_mappings(
        (
            "OWASP-API-2023:API1",
            "CWE-639",
            "OWASP-LLM-2026:LLM01",
            "MITRE-ATTACK:T1046",
            "SOMETHING-ELSE",
        )
    )

    assert grouped["owasp_api_2023"] == ["API1"]
    assert grouped["cwe"] == ["CWE-639"]
    assert grouped["owasp_llm_2026"] == ["LLM01"]
    # Enterprise ATT&CK, distinct from `mitre_atlas` (AI-system-specific) —
    # see `app/core/findings/frameworks.py`'s own note on why the pentest
    # module's findings map here rather than to ATLAS.
    assert grouped["mitre_attack"] == ["T1046"]
    # An unrecognised reference is kept rather than filed under a framework
    # it might not belong to.
    assert grouped["other"] == ["SOMETHING-ELSE"]


def test_every_mapping_cites_a_pinned_version_and_date() -> None:
    """§3.4 and §27: a mapping must cite the edition it was made against.

    This test previously asserted `mapping_versions == {}` — an honest
    placeholder, because an unverified version string implies a check nobody
    performed. `app/core/findings/frameworks.py` now supplies the pinned
    editions, so the stronger property holds: every framework the finding maps
    to carries a version and a retrieval date.
    """
    draft = build_finding(
        _result(), exposure=Exposure.INTERNET_UNAUTHENTICATED, environment=Environment.PRODUCTION
    )

    assert draft.mappings, "the fixture should carry framework references"
    for key, references in draft.mappings.items():
        if key == "cwe":
            # Deliberately unversioned: CWE identifiers are stable across
            # MITRE's releases, and pinning a "version" would imply a
            # precision that does not exist.
            assert key not in draft.mapping_versions
            continue
        assert references
        assert key in draft.mapping_versions, key
        assert "retrieved" in draft.mapping_versions[key]


def test_a_framework_with_no_references_is_not_claimed() -> None:
    """A finding must not state it was assessed against a framework it carries
    no reference for."""
    from app.core.findings.frameworks import versions_for

    assert versions_for({"owasp_api_2023": []}) == {}
    assert versions_for({"not_a_framework": ["X1"]}) == {}


def test_no_framework_version_is_invented() -> None:
    """Every pinned entry names a real source and a real date, and the table is
    the only place a version may come from."""
    from datetime import date

    from app.core.findings.frameworks import FRAMEWORKS

    for key, entry in FRAMEWORKS.items():
        assert entry.version, key
        assert entry.source, key
        # Parses, so a typo in a date is a failure rather than a string nobody
        # checked.
        date.fromisoformat(entry.retrieved)
