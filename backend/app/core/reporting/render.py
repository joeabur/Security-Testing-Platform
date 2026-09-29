"""Rendering a report (docs/BUILD_SPEC.md §14).

Markdown is the source rendering; HTML wraps it in a minimal document, and
PDF is produced from that HTML via WeasyPrint — §14 chose that deliberately
so there is no headless-browser dependency. CSV is a flat finding list for a
spreadsheet.

Every renderer reads the same `ReportData` and the same template section
list, so two formats cannot disagree about a number. The one thing a
renderer may vary is *presentation*: the executive template's omission of
probe ids happens here, because it is a rendering choice rather than a
different fact.
"""

import csv
import html
import io
from collections.abc import Iterable

from app.core.reporting.model import ReportData, ReportFinding
from app.core.reporting.templates import Section, Template, sections_for, shows_probe_ids

CSV_COLUMNS = (
    "severity",
    "risk_score",
    "title",
    "surface",
    "status",
    "confidence",
    "stability",
    "probe_id",
    "fingerprint",
    "first_seen",
    "last_seen",
    "times_seen",
)


def _lines(parts: Iterable[str]) -> str:
    return "\n".join(parts).rstrip() + "\n"


def render_markdown(report: ReportData, template: Template = Template.TECHNICAL) -> str:
    show_probes = shows_probe_ids(template)
    out: list[str] = [
        f"# Security assessment — {report.target_name}",
        "",
        f"**Template:** {template.value}  ",
        f"**Generated:** {report.generated_at.isoformat()}  ",
        f"**Tool:** Kervy Security {report.tool_version}  ",
        f"**Run:** `{report.run_id}`",
        "",
    ]

    for section in sections_for(template):
        out.extend(_render_section(report, section, show_probes))
    return _lines(out)


def _render_section(report: ReportData, section: Section, show_probes: bool) -> list[str]:
    match section:
        case Section.EXECUTIVE_SUMMARY:
            return _executive_summary(report)
        case Section.AUTHORIZATION_AND_SCOPE:
            return _authorization(report)
        case Section.METHODOLOGY:
            return _methodology(report)
        case Section.ATTACK_SURFACE:
            return _attack_surface(report)
        case Section.RISK_SUMMARY:
            return _risk_summary(report)
        case Section.FINDINGS_BY_SEVERITY:
            return _findings_by_severity(report, show_probes)
        case Section.AI_FINDINGS:
            return _grouped(report, "AI findings", "ai.", show_probes)
        case Section.API_FINDINGS:
            return _grouped(report, "API findings", "api.", show_probes)
        case Section.APPSEC_FINDINGS:
            return _grouped(report, "AppSec findings", "appsec.", show_probes)
        case Section.FRAMEWORK_COVERAGE:
            return _framework_coverage(report)
        case Section.REMEDIATION_PLAN:
            return _remediation_plan(report, show_probes)
        case Section.RETEST_RESULTS:
            return _retest_results(report)
        case Section.APPENDIX:
            return _appendix(report)
    return []


def _executive_summary(report: ReportData) -> list[str]:
    counts = report.severity_counts()
    reportable = sum(v for k, v in counts.items() if k != "INFORMATIONAL")
    headline = (
        f"{reportable} finding(s) were identified" if reportable else "No findings were identified"
    )
    out = [
        "## Executive summary",
        "",
        f"{headline} against {report.target_name} "
        f"({report.target_kind}, {report.target_environment}).",
        "",
        f"- Critical: {counts.get('CRITICAL', 0)}",
        f"- High: {counts.get('HIGH', 0)}",
        f"- Medium: {counts.get('MEDIUM', 0)}",
        f"- Low: {counts.get('LOW', 0)}",
        "",
    ]
    untested = [item.pillar for item in report.pillar_coverage if not item.tested]
    if untested:
        # §14: silence about a pillar is not an acceptable summary. A reader
        # who sees "no findings" has to be told what was not looked at — and
        # told by name, because "some areas" is how a gap goes unnoticed.
        out += [
            f"**Not tested:** {', '.join(untested)}. "
            "See Framework coverage for why each did not run.",
            "",
        ]
    if report.not_tested:
        out += [
            f"{len(report.not_tested)} area(s) were **not tested** in this assessment; "
            "see Framework coverage for the list and the reasons.",
            "",
        ]
    if report.halted_reason:
        out += [
            f"This assessment stopped early: {report.halted_reason}. Coverage is "
            "partial and the findings below are what was reached before it stopped.",
            "",
        ]
    return out


def _authorization(report: ReportData) -> list[str]:
    return [
        "## Authorization & scope",
        "",
        f"- Authorized by: {report.authorization_by or 'not recorded'}",
        f"- Reference: {report.authorization_reference or 'not recorded'}",
        f"- Valid: {report.authorization_valid_from or '?'} to "
        f"{report.authorization_valid_until or '?'}",
        f"- Authorization digest: `{report.authorization_digest or 'not recorded'}`",
        f"- Rules of Engagement digest: `{report.roe_digest or 'not recorded'}`",
        f"- Safe mode: {'on' if report.safe_mode else 'off'}",
        f"- Excluded domains: {', '.join(report.excluded_domains) or 'none'}",
        f"- Excluded paths: {', '.join(report.excluded_paths) or 'none'}",
        "",
        "The digests above were pinned when the run started, so a later change to "
        "the authorization or the Rules of Engagement cannot alter what this report "
        "says was permitted.",
        "",
    ]


def _methodology(report: ReportData) -> list[str]:
    out = [
        "## Methodology",
        "",
        f"- Trials per probabilistic probe: {report.trials_per_probe}",
        f"- Finding rule: {report.decision_rule or 'not recorded'}",
        f"- {report.judge_status or 'Judge: not recorded'}",
        f"- Checks completed: {report.checks_completed}/{report.checks_total}",
        f"- Requests refused by the scope engine: {report.requests_blocked}",
        "",
    ]
    if report.limitations:
        out += ["### Limitations", ""]
        out += [f"- {item}" for item in report.limitations]
        out += [""]
    if report.ai_drafted_sections:
        # §14 and Addendum §6.3: disclose where AI-drafted text was accepted.
        out += [
            "### AI-assisted text",
            "",
            "A human operator reviewed and accepted AI-drafted text in: "
            + ", ".join(report.ai_drafted_sections)
            + ". All measurements, counts, scope digests and framework mappings in "
            "this report are generated from data, never drafted.",
            "",
        ]
    return out


def _attack_surface(report: ReportData) -> list[str]:
    out = [
        "## Attack surface",
        "",
        f"- Base URL: `{report.target_base_url}`",
        f"- Adapters: {', '.join(report.adapters) or 'none configured'}",
        f"- Endpoints in scope: {len(report.endpoints)}",
        "",
    ]
    if report.endpoints:
        out += [f"  - `{endpoint}`" for endpoint in report.endpoints[:50]]
        if len(report.endpoints) > 50:
            out += [f"  - … and {len(report.endpoints) - 50} more"]
        out += [""]
    if report.declared_tools:
        out += ["### Declared agent tools", ""]
        out += [f"- {tool}" for tool in report.declared_tools]
        out += [""]
    if report.permission_graph:
        out += ["### Permission graph", "", "```mermaid", report.permission_graph, "```", ""]
    return out


def _risk_summary(report: ReportData) -> list[str]:
    counts = report.severity_counts()
    out = [
        "## Risk summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    out += [f"| {name} | {count} |" for name, count in counts.items()]
    out += [
        "",
        "Scores come from the Kervy risk model "
        "(`impact × likelihood × confidence_weight × exposure_modifier`). Every "
        "finding carries the inputs that produced its score, and the severity "
        "follows a published banding — see the appendix. CVSS and AIVSS, where "
        "present, are separate figures and are never averaged into this score.",
        "",
    ]
    return out


def _finding_block(finding: ReportFinding, show_probes: bool) -> list[str]:
    out = [
        f"#### {finding.title}",
        "",
        f"- Severity: **{finding.severity}** (risk {finding.risk_score}/10)",
        f"- Surface: `{finding.surface}`",
        f"- Confidence: {finding.confidence}; stability: {finding.stability}",
        f"- Status: {finding.status}; seen {finding.times_seen}x "
        f"(first {finding.first_seen}, last {finding.last_seen})",
    ]
    if show_probes:
        out.append(f"- Probe: `{finding.probe_id}` {finding.probe_version}")
        out.append(f"- Fingerprint: `{finding.fingerprint}`")
    if finding.evidence_ref:
        out.append(f"- Evidence: `{finding.evidence_ref}`")
    if finding.attack_success_rate:
        asr = finding.attack_success_rate
        interval = asr.get("ci95", ["?", "?"])
        out.append(
            f"- Attack success rate: {asr.get('successes')}/{asr.get('trials')} "
            f"(95% CI {interval[0]}–{interval[1]})"
        )
    if finding.control_success_rate:
        control = finding.control_success_rate
        out.append(f"- Control success rate: {control.get('successes')}/{control.get('trials')}")
    if not finding.attack_success_rate:
        # Said out loud rather than left blank. A reader who sees rates on
        # one finding and nothing on the next would otherwise be entitled to
        # read the silence as a measured zero.
        out.append(
            "- Attack success rate: not measured — this finding comes from analysis "
            "of declared configuration or code, not from repeated trials"
        )

    mappings = [
        f"{framework}: {', '.join(str(i) for i in items)}"
        for framework, items in sorted(finding.mappings.items())
        if isinstance(items, list) and items
    ]
    if mappings:
        out.append(f"- Mappings: {'; '.join(mappings)}")
        if not finding.mapping_versions:
            # Honest about what the mapping does not yet carry.
            out.append(
                "- Mapping versions: not recorded — these mappings have not been "
                "pinned to a verified framework release"
            )

    out += [
        "",
        f"**Why this severity.** {finding.severity_rationale}",
        "",
        finding.description,
        "",
        f"**Impact.** {finding.impact}",
        "",
        f"**Remediation.** {finding.remediation}",
        "",
    ]
    if finding.reproduction:
        out += ["**Reproduction.**", ""]
        out += [f"{index}. {step}" for index, step in enumerate(finding.reproduction, 1)]
        out += [""]
    return out


def _findings_by_severity(report: ReportData, show_probes: bool) -> list[str]:
    out = ["## Findings by severity", ""]
    if not report.findings:
        out += ["No findings were recorded for this run.", ""]
        return out
    for severity, findings in report.findings_by_severity():
        out += [f"### {severity} ({len(findings)})", ""]
        for finding in findings:
            out += _finding_block(finding, show_probes)
    return out


def _grouped(report: ReportData, title: str, prefix: str, show_probes: bool) -> list[str]:
    findings = report.findings_for_category(prefix)
    out = [f"## {title}", ""]
    if not findings:
        out += [
            f"No findings in this category. See Framework coverage for whether "
            f"{title.lower()} were tested at all.",
            "",
        ]
        return out
    out += [f"- **{f.severity}** {f.title} (`{f.surface}`)" for f in findings]
    out += [""]
    return out


def _framework_coverage(report: ReportData) -> list[str]:
    out = ["## Framework coverage", ""]
    covered = report.frameworks_covered()
    if covered:
        out += ["### Reported against", ""]
        out += [f"- **{framework}**: {', '.join(items)}" for framework, items in covered.items()]
        out += [""]
    else:
        out += ["No framework category had a finding reported against it.", ""]

    # Every pillar, named, whether or not it ran. §27's addendum asks for
    # exactly this: a reader must not have to infer that DAST was absent from
    # the fact that nothing mentions it.
    out += ["### Pillar coverage", "", "| Pillar | Status | Detail |", "|---|---|---|"]
    for pillar in report.pillar_coverage:
        out += [f"| {pillar.pillar} | {pillar.label} | {pillar.detail} |"]
    out += [""]

    out += ["### Not tested", ""]
    if report.not_tested:
        for item in report.not_tested:
            out += [f"- **{item.area}** — {item.reason}"]
        out += [""]
    else:
        out += [
            "Nothing was explicitly recorded as untested. Note that this states "
            "what the engines reported, not that every framework category was "
            "covered: a pillar with no engine configured produces no marker.",
            "",
        ]
    out += [
        "A category listed as reported against means at least one finding cited it. "
        "It does not mean the category was exhaustively tested.",
        "",
    ]
    return out


def _remediation_plan(report: ReportData, show_probes: bool) -> list[str]:
    out = ["## Remediation plan", ""]
    ordered = sorted(report.findings, key=lambda f: f.risk_score, reverse=True)
    if not ordered:
        out += ["Nothing to remediate from this run.", ""]
        return out

    out += ["Ordered by risk score. Effort bands are not estimated by this tool.", ""]
    for index, finding in enumerate(ordered, 1):
        label = f"`{finding.probe_id}`" if show_probes else finding.surface
        out += [
            f"{index}. **{finding.severity}** ({finding.risk_score}/10) — {finding.title} "
            f"[{label}]",
            f"   {finding.remediation}",
        ]
    out += [""]
    return out


def _retest_results(report: ReportData) -> list[str]:
    """Deltas by fingerprint.

    A retest run states a verdict per finding, with the evidence digest from
    before and after. An ordinary assessment has no verdicts, and reports
    recurrence instead — which is a weaker claim, so it is labelled as one.
    """
    out = ["## Retest results", ""]
    if report.is_retest:
        return out + _retest_verdicts(report)

    recurring = [f for f in report.findings if f.times_seen > 1]
    if not report.findings:
        out += ["No findings to compare.", ""]
        return out
    out += [
        "This run was an assessment, not a retest, so nothing here is a "
        "verdict on whether a specific weakness was fixed. What it can say is "
        "which findings have survived more than one run.",
        "",
        f"- New in this run: {len(report.findings) - len(recurring)}",
        f"- Seen in a previous run and still present: {len(recurring)}",
        "",
    ]
    if recurring:
        out += [f"- `{f.fingerprint[:19]}…` {f.title} (seen {f.times_seen}x)" for f in recurring]
        out += [""]
    return out


def _retest_verdicts(report: ReportData) -> list[str]:
    """The three verdicts, counted and then listed.

    `not tested` is reported as loudly as the other two. A retest whose probe
    did not run tells you nothing about a fix, and a report that folded those
    rows into "not reproduced" would be claiming the opposite.
    """
    if not report.retests:
        return [
            "This run was a retest, but no findings were compared — the baseline was empty.",
            "",
        ]

    counts: dict[str, int] = {}
    for record in report.retests:
        counts[record.verdict] = counts.get(record.verdict, 0) + 1

    out = [
        "| Verdict | Count | Means |",
        "|---|---|---|",
        f"| reproduced | {counts.get('reproduced', 0)} | Found again. Still present. |",
        f"| not_reproduced | {counts.get('not_reproduced', 0)} | "
        "The probe ran and found nothing. Evidence of a fix. |",
        f"| not_tested | {counts.get('not_tested', 0)} | "
        "The probe did not run. **Not** evidence of a fix. |",
        "",
    ]
    for record in report.retests:
        out += [
            f"#### {record.title}",
            "",
            f"- Verdict: **{record.verdict}**",
            f"- Severity at baseline: {record.severity}",
            f"- Fingerprint: `{record.fingerprint}`",
            f"- Evidence before: `{record.before_evidence_ref or 'none recorded'}`",
            f"- Evidence after: `{record.after_evidence_ref or 'none — nothing was observed'}`",
            "",
            record.detail,
            "",
        ]
    return out


def _appendix(report: ReportData) -> list[str]:
    out = ["## Appendix", "", "### Risk model", ""]
    out += [report.risk_model_tables or "Risk model tables were not supplied.", ""]
    out += ["### Tool versions", ""]
    if report.tool_versions:
        out += [f"- {name}: {version}" for name, version in sorted(report.tool_versions.items())]
    else:
        out += ["- Not recorded"]
    out += [""]
    return out


def render_html(report: ReportData, template: Template = Template.TECHNICAL) -> str:
    """A minimal, self-contained HTML document.

    Deliberately plain: this is the input WeasyPrint would render to PDF, and
    the markdown body is escaped rather than converted, so nothing in a
    finding's text — which includes attacker-supplied evidence — can inject
    markup into the report. A report that renders hostile HTML from its own
    evidence would be an ironic way to fail.
    """
    body = html.escape(render_markdown(report, template))
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        f"<title>Security assessment — {html.escape(report.target_name)}</title>\n"
        "<style>\n"
        "  body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem auto;\n"
        "         max-width: 50rem; line-height: 1.55; color: #1a1a1a; }\n"
        "  pre { white-space: pre-wrap; word-wrap: break-word; font-family:\n"
        "        ui-monospace, monospace; font-size: 0.9rem; }\n"
        "  @media print { body { margin: 0; max-width: none; } }\n"
        "</style>\n</head>\n<body>\n"
        f"<pre>{body}</pre>\n"
        "</body>\n</html>\n"
    )


class PdfUnavailableError(RuntimeError):
    """WeasyPrint is not installed, so PDF cannot be produced.

    Its own reason, not a generic import error, so the API can say what is
    missing instead of returning a 500 that looks like a bug.
    """


def render_pdf(report: ReportData, template: Template = Template.TECHNICAL) -> bytes:
    """The HTML rendering, printed.

    WeasyPrint is an optional dependency (the `pdf` extra) because it needs
    system Pango and Cairo libraries that not every deployment has. It is
    imported here rather than at module scope so that a deployment without it
    still serves every other format — a missing PDF renderer must not take
    the reporting package down with it.
    """
    try:
        from weasyprint import HTML
    except ImportError as exc:  # pragma: no cover - exercised by the skip path
        raise PdfUnavailableError(
            "PDF rendering requires WeasyPrint; install the 'pdf' extra "
            "(pip install -e '.[pdf]') and its system Pango/Cairo libraries."
        ) from exc

    # No base_url: the document is self-contained by construction (the styles
    # are inline and the body is escaped text), so there is nothing to fetch.
    # Passing one would let a report reach the filesystem or the network while
    # rendering, which is not something a report should ever do.
    document: bytes | None = HTML(string=render_html(report, template)).write_pdf()
    if document is None:  # pragma: no cover - WeasyPrint returns bytes here
        raise PdfUnavailableError("WeasyPrint produced no document")
    return document


def render_csv(report: ReportData) -> str:
    """A flat finding list. No template: a spreadsheet wants every row."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for finding in sorted(report.findings, key=lambda f: f.risk_score, reverse=True):
        writer.writerow([getattr(finding, column) for column in CSV_COLUMNS])
    return buffer.getvalue()
