"""Reporting: SARIF conformance, golden snapshots, and template behaviour
(docs/BUILD_SPEC.md §14).

The golden snapshots are the point of this module. A report is the artefact
that leaves the platform, so an unnoticed change to its wording, ordering or
structure is a change to what the organization believes it was told. The
snapshots make any such change show up in a diff and require someone to say
"yes, that is what I meant".

Run with `UPDATE_GOLDEN=1` to re-record them, and read the diff before
committing it.
"""

import json
import os
import pathlib

import pytest
from jsonschema import Draft7Validator

from app.core.reporting.build import to_canonical_json
from app.core.reporting.model import PILLARS
from app.core.reporting.render import (
    CSV_COLUMNS,
    PdfUnavailableError,
    render_csv,
    render_html,
    render_markdown,
    render_pdf,
)
from app.core.reporting.sarif import SARIF_VERSION, to_sarif, to_sarif_json
from app.core.reporting.templates import Section, Template, sections_for, shows_probe_ids
from tests.reporting_fixtures import retest_report, sample_report

GOLDEN_DIR = pathlib.Path(__file__).parent / "golden"
SCHEMA_PATH = pathlib.Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"


def assert_golden(name: str, text: str) -> None:
    path = GOLDEN_DIR / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return
    assert path.exists(), f"missing golden {path}; re-record with UPDATE_GOLDEN=1"
    expected = path.read_text(encoding="utf-8")
    assert text == expected, (
        f"{name} differs from its recorded golden. If the change is intended, "
        "re-record with UPDATE_GOLDEN=1 and review the diff."
    )


@pytest.fixture(scope="module")
def sarif_validator() -> Draft7Validator:
    """The real OASIS schema, vendored. See tests/schemas/README.md."""
    return Draft7Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


# --- SARIF ---------------------------------------------------------------


def test_sarif_validates_against_the_oasis_2_1_0_schema(
    sarif_validator: Draft7Validator,
) -> None:
    document = to_sarif(sample_report())
    errors = [
        f"{list(error.path)}: {error.message}" for error in sarif_validator.iter_errors(document)
    ]
    assert errors == []
    assert document["version"] == SARIF_VERSION


def test_the_schema_check_has_teeth(sarif_validator: Draft7Validator) -> None:
    """A validator that accepts anything proves nothing.

    Breaking the document in a way the spec forbids must fail, otherwise the
    test above is decoration.
    """
    document = to_sarif(sample_report())
    document["runs"][0]["results"][0].pop("message")
    assert list(sarif_validator.iter_errors(document))


def test_every_result_carries_a_fingerprint_a_consumer_can_track() -> None:
    """Without this a code host shows every run's findings as brand new."""
    document = to_sarif(sample_report())
    for result in document["runs"][0]["results"]:
        assert result["partialFingerprints"]["kervyFingerprint/v1"].startswith("sha256:")


def test_sarif_records_what_was_not_tested() -> None:
    """Coverage honesty survives the export. A SARIF file that lists three
    findings and nothing else reads as "these are the problems"."""
    run = to_sarif(sample_report())["runs"][0]
    assert run["properties"]["not_tested"]
    assert run["properties"]["not_tested"][0]["area"] == "dependency advisories"


# --- golden snapshots ----------------------------------------------------


@pytest.mark.parametrize("template", list(Template))
def test_markdown_snapshot(template: Template) -> None:
    assert_golden(f"report-{template.value}.md", render_markdown(sample_report(), template))


def test_canonical_json_snapshot() -> None:
    assert_golden("report.json", to_canonical_json(sample_report()))


def test_sarif_snapshot() -> None:
    assert_golden("report.sarif.json", to_sarif_json(sample_report()))


def test_csv_snapshot() -> None:
    assert_golden("report.csv", render_csv(sample_report()))


def test_html_snapshot() -> None:
    assert_golden("report.technical.html", render_html(sample_report()))


def test_two_renderings_of_the_same_report_are_byte_identical() -> None:
    """The property the snapshots depend on: nothing in a rendering varies
    run to run. A dict iterating differently, or an unsorted set in a
    mapping list, would make every golden flaky."""
    report = sample_report()
    assert to_canonical_json(report) == to_canonical_json(report)
    assert render_markdown(report) == render_markdown(report)
    assert to_sarif_json(report) == to_sarif_json(report)


# --- templates -----------------------------------------------------------


def test_the_executive_template_omits_probe_ids() -> None:
    report = sample_report()
    executive = render_markdown(report, Template.EXECUTIVE)
    technical = render_markdown(report, Template.TECHNICAL)

    assert not shows_probe_ids(Template.EXECUTIVE)
    assert "KERVY-AI-001" in technical
    assert "KERVY-AI-001" not in executive


def test_every_template_states_its_authorization_and_its_gaps() -> None:
    """§14: no template may drop the authorization reference or the
    "not tested" list. Those are the two things that stop a report being
    read as broader than it is."""
    report = sample_report()
    for template in Template:
        rendered = render_markdown(report, template)
        assert Section.AUTHORIZATION_AND_SCOPE in sections_for(template)
        assert "AUTH-2026-014" in rendered
        assert "dependency advisories" in rendered, template
        assert "Advisory lookup is disabled by default" in rendered, template


def test_the_developer_template_leads_with_remediation() -> None:
    sections = sections_for(Template.DEVELOPER)
    assert Section.REMEDIATION_PLAN in sections
    assert sections.index(Section.REMEDIATION_PLAN) < sections.index(Section.APPENDIX)


def test_a_report_says_when_measurement_did_not_apply() -> None:
    """Design-review findings have no attack success rate. Printing "0%"
    for them, or omitting the line, would both mislead."""
    rendered = render_markdown(sample_report(), Template.TECHNICAL)
    assert "Tool invocation is not scoped to the requesting user" in rendered
    assert "5/5" in rendered  # the measured finding
    assert "not measured" in rendered.lower()


# --- hostile content -----------------------------------------------------


def test_html_cannot_be_injected_through_a_finding() -> None:
    """A finding's text can come from a target's response. A report that
    renders that as markup would be an unusually ironic vulnerability."""
    rendered = render_html(sample_report())
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    # And the target name's quotes and ampersand survive as text.
    assert "&amp; API" in rendered


def test_csv_has_a_header_and_one_row_per_finding() -> None:
    lines = render_csv(sample_report()).strip().splitlines()
    assert lines[0] == ",".join(CSV_COLUMNS)
    assert len(lines) == 1 + len(sample_report().findings)
    # Highest risk first, so a spreadsheet opened without sorting is useful.
    assert lines[1].startswith("CRITICAL,9.1")


# --- PDF -----------------------------------------------------------------


def test_pdf_is_produced_from_the_html() -> None:
    try:
        document = render_pdf(sample_report(), Template.EXECUTIVE)
    except PdfUnavailableError as exc:
        pytest.skip(f"WeasyPrint not installed: {exc}")
    assert document.startswith(b"%PDF-")
    assert len(document) > 1000


# --- retest rendering (Phase 9) -------------------------------------------


def test_retest_snapshot() -> None:
    assert_golden("report-retest.md", render_markdown(retest_report(), Template.TECHNICAL))


def test_a_retest_report_never_presents_not_tested_as_good_news() -> None:
    """The verdict that keeps the other two honest has to survive rendering."""
    rendered = render_markdown(retest_report(), Template.TECHNICAL)
    assert "**Not** evidence of a fix" in rendered
    assert "Not looking is not a fix" in rendered
    assert "Evidence of a fix" in rendered  # not_reproduced, stated separately


def test_a_reproduced_finding_shows_its_attack_success_rate_either_side() -> None:
    """§7.1's rate, interval and control follow the finding across the
    retest boundary — not just a verdict, but the numbers behind it."""
    rendered = render_markdown(retest_report(), Template.TECHNICAL)
    assert "Attack success rate before: 3/5 = 60%" in rendered
    assert "Attack success rate after: 5/5 = 100%" in rendered


def test_a_not_reproduced_finding_has_no_fabricated_rate_comparison() -> None:
    """The not_reproduced and not_tested rows in the fixture carry no
    attack_success_rate_delta, so no rate line is printed for them — never
    a guessed "0%" standing in for a measurement that was never taken."""
    rendered = render_markdown(retest_report(), Template.TECHNICAL)
    section = rendered.split("## Retest results")[1].split("## Appendix")[0]
    assert section.count("Attack success rate before:") == 1


def test_an_assessment_does_not_claim_to_be_a_retest() -> None:
    """Recurrence is a weaker claim than a verdict, and is labelled as one."""
    rendered = render_markdown(sample_report(), Template.TECHNICAL)
    assert "was an assessment, not a retest" in rendered
    assert "reproduced" not in rendered.split("## Retest results")[1].split("## Appendix")[0]


# --- pillar coverage (docs/BUILD_SPEC.md §27 addendum) --------------------
#
# "Report's framework-coverage section names SAST/DAST/SCA/Secrets/IaC/RASP
# explicitly whenever any of them were not run."
#
# The old coverage section was derived entirely from the engines' own "not
# tested" markers, which cannot satisfy that: a pillar that never ran emits no
# marker, so its absence from the report is exactly what reads as a clean
# result. DAST went unmentioned for three phases and RASP for one, and no test
# noticed, because nothing enumerated.


@pytest.mark.parametrize("pillar", list(PILLARS))
@pytest.mark.parametrize("template", list(Template))
def test_every_pillar_is_named_in_every_markdown_template(pillar: str, template: Template) -> None:
    """Named, not merely accounted for internally.

    Parametrised over the pillars rather than asserting against a written list,
    so adding a pillar to `PILLARS` and forgetting the renderer is a failure
    rather than a silent omission — which is the failure this replaces.

    Verified by removing the pillar-coverage block from `_framework_coverage`.
    """
    body = render_markdown(sample_report(), template)
    assert pillar in body, (
        f"{template.value} never names the {pillar} pillar. A reader cannot tell "
        "'found nothing' from 'never ran' about a pillar the report does not mention."
    )


@pytest.mark.parametrize("pillar", list(PILLARS))
def test_every_pillar_is_named_in_the_canonical_json(pillar: str) -> None:
    payload = json.loads(to_canonical_json(sample_report()))
    entries = payload["coverage"]["pillar_coverage"]
    assert [item["pillar"] for item in entries] == list(PILLARS)
    named = next(item for item in entries if item["pillar"] == pillar)
    # Every entry carries a verdict and a reason — a `tested: false` with no
    # detail would tell a consumer nothing they could act on.
    assert isinstance(named["tested"], bool)
    assert named["detail"].strip()


@pytest.mark.parametrize("pillar", list(PILLARS))
def test_every_pillar_is_named_in_the_html(pillar: str) -> None:
    assert pillar in render_html(sample_report())


def test_an_untested_pillar_is_named_in_the_executive_summary() -> None:
    """The summary is what a reader who reads one page reads.

    "Some areas were not tested" is how a gap goes unnoticed, so the untested
    pillars are listed by name there too.

    Verified by replacing the names with a count: this fails.
    """
    body = render_markdown(sample_report(), Template.EXECUTIVE)
    summary = body.split("## Authorization")[0]
    for pillar in ("DAST", "RASP"):
        assert pillar in summary, f"the executive summary does not name {pillar}"


def test_a_pillar_that_only_produced_a_not_tested_marker_is_not_counted_as_tested() -> None:
    """A degraded engine tested nothing, and must not read as though it did.

    An engine whose tool was missing emits a "Not tested:" marker under its own
    probe id. Counting that as coverage would move the lie from one part of the
    report to another.

    Verified by dropping the marker check from `_pillar_coverage`: SAST is then
    reported as tested on the strength of a marker saying it did not run.
    """
    from app.core.reporting.build import _pillar_coverage

    class _Row:
        def __init__(self, probe_id: str, title: str) -> None:
            self.probe_id = probe_id
            self.title = title

    class _Target:
        kind = "llm_app"
        code_repo_ref = "git+https://example.test/repo.git#main"
        adapter_kind = "chat_http"
        runtime_protection: list[object] = []

    marker_only = _pillar_coverage(
        [_Row("appsec.sast.semgrep", "Not tested: Semgrep (static analysis)")],  # type: ignore[list-item]
        _Target(),  # type: ignore[arg-type]
    )
    sast = next(item for item in marker_only if item.pillar == "SAST")
    assert sast.tested is False
    assert sast.detail.strip()

    real = _pillar_coverage(
        [_Row("appsec.sast.semgrep", "Use of eval on untrusted input")],  # type: ignore[list-item]
        _Target(),  # type: ignore[arg-type]
    )
    assert next(item for item in real if item.pillar == "SAST").tested is True


def test_coverage_is_enumerated_not_derived_from_what_produced_output() -> None:
    """A run that produced nothing at all still names all eight pillars.

    This is the property the requirement is really about. Every other
    formulation — "list the markers", "list what ran" — degrades to silence
    exactly when coverage is worst.
    """
    from app.core.reporting.build import _pillar_coverage

    class _Target:
        kind = "api"
        code_repo_ref = None
        adapter_kind = None
        runtime_protection: list[object] = []

    coverage = _pillar_coverage([], _Target())  # type: ignore[arg-type]
    assert [item.pillar for item in coverage] == list(PILLARS)
    assert all(item.tested is False for item in coverage)
    assert all(item.detail.strip() for item in coverage)


def test_a_target_declaring_runtime_protection_says_none_of_it_was_measured() -> None:
    """The RASP line changes when a target actually claims something.

    "This target declares no runtime protection" and "declares runtime
    protection, and none of it was measured" are different facts, and only the
    second is a gap somebody should act on.
    """
    from app.core.reporting.build import _pillar_coverage

    class _Target:
        kind = "api"
        code_repo_ref = None
        adapter_kind = None
        runtime_protection = [{"kind": "waf", "evidenced": "claimed"}]

    rasp = next(
        item
        for item in _pillar_coverage([], _Target())  # type: ignore[arg-type]
        if item.pillar == "RASP"
    )
    assert rasp.tested is False
    assert "none of it was measured" in rasp.detail
