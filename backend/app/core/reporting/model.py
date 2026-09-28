"""The report's data model (docs/BUILD_SPEC.md §14).

One section set. Every template is a *projection* of it — "templates differ
in which sections are emphasized/omitted, not in the facts reported". That
is why the sections are computed once, here, and the renderers only choose
what to show: two renderings that disagreed about a count would be worse
than either one alone.

Two requirements shape the structure:

* **Coverage honesty is mandatory.** `framework_coverage` names what was
  *not* tested and why, drawn from the informational "not tested" results
  the engines emit rather than from a guess. A report that ran AI and API
  testing but no SAST has to say so.
* **The authorization and scope section is exact.** It carries the
  authorization digest and the RoE digest the run pinned at start, so a
  later change to either cannot rewrite what the report says was permitted.
  These are never drafted by the AI layer (§4.5 row 7).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.probes.models import Severity

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
)


@dataclass(frozen=True)
class ReportFinding:
    """A finding as the report presents it."""

    id: str
    fingerprint: str
    title: str
    category: str
    severity: str
    severity_rationale: str
    confidence: str
    stability: str
    risk_model: str
    risk_score: float
    risk_inputs: dict[str, Any]
    surface: str
    probe_id: str
    probe_version: str
    description: str
    impact: str
    remediation: str
    reproduction: list[str]
    mappings: dict[str, Any]
    mapping_versions: dict[str, Any]
    attack_success_rate: dict[str, Any] | None
    control_success_rate: dict[str, Any] | None
    evidence_ref: str | None
    status: str
    first_seen: str
    last_seen: str
    times_seen: int


@dataclass(frozen=True)
class NotTested:
    """Something the run explicitly did not cover, and why.

    Taken from the engines' own informational markers. §14's coverage
    honesty is unenforceable if this is assembled by hand — a section
    someone remembers to fill in is a section that goes stale.
    """

    area: str
    reason: str
    probe_id: str


#: Every assessment pillar this platform can run, in the order a report lists
#: them. The §27 addendum requires the coverage section to name
#: SAST/DAST/SCA/Secrets/IaC/RASP **explicitly whenever any of them were not
#: run**, so the list is fixed and enumerated rather than assembled from
#: whatever happened to produce output. A pillar that produced nothing is the
#: case this exists for: silence is what reads as a clean result.
PILLARS: tuple[str, ...] = (
    "AI security",
    "API security",
    "SAST",
    "DAST",
    "SCA",
    "Secrets",
    "IaC",
    "RASP",
    "Container",
    "Cloud",
    "VM",
    "Domain",
    "Pentest",
)


@dataclass(frozen=True)
class PillarCoverage:
    """Whether one pillar ran, and what that means for this report.

    `tested` is derived from whether results actually carry that pillar's
    probe ids — not from what was configured, because configuring an engine
    and that engine running are different things and only one of them puts
    findings in a report.
    """

    pillar: str
    tested: bool
    detail: str

    @property
    def label(self) -> str:
        return "tested" if self.tested else "not tested"


@dataclass(frozen=True)
class RetestRecord:
    """One finding's retest verdict, with the digests either side of it."""

    fingerprint: str
    title: str
    severity: str
    verdict: str
    before_evidence_ref: str | None
    after_evidence_ref: str | None
    detail: str


@dataclass(frozen=True)
class ReportData:
    """Everything every template draws from."""

    # --- identity -------------------------------------------------------
    organization: str
    target_name: str
    target_kind: str
    target_environment: str
    target_base_url: str
    run_id: str
    generated_at: datetime
    tool_version: str

    # --- authorization & scope (exact, never drafted) -------------------
    authorization_reference: str | None
    authorization_by: str | None
    authorization_valid_from: str | None
    authorization_valid_until: str | None
    authorization_digest: str | None
    roe_digest: str | None
    excluded_domains: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    safe_mode: bool = True

    # --- methodology ----------------------------------------------------
    trials_per_probe: int = 5
    decision_rule: str = ""
    judge_status: str = ""
    limitations: list[str] = field(default_factory=list)

    # --- surface --------------------------------------------------------
    adapters: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    declared_tools: list[str] = field(default_factory=list)
    permission_graph: str | None = None

    # --- results --------------------------------------------------------
    findings: list[ReportFinding] = field(default_factory=list)
    not_tested: list[NotTested] = field(default_factory=list)
    #: One entry per pillar in `PILLARS`, always. A report that omitted a
    #: pillar would be a report whose silence reads as coverage.
    pillar_coverage: list[PillarCoverage] = field(default_factory=list)
    # Present when this run was a retest. Empty on an ordinary assessment,
    # which is not the same as "everything was fixed" — the renderer says so.
    is_retest: bool = False
    retests: list[RetestRecord] = field(default_factory=list)
    checks_completed: int = 0
    checks_total: int = 0
    requests_blocked: int = 0
    halted_reason: str | None = None

    # --- appendix -------------------------------------------------------
    risk_model_tables: str = ""
    tool_versions: dict[str, str] = field(default_factory=dict)
    ai_drafted_sections: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def findings_by_severity(self) -> list[tuple[str, list[ReportFinding]]]:
        grouped: list[tuple[str, list[ReportFinding]]] = []
        for severity in SEVERITY_ORDER:
            matching = [f for f in self.findings if f.severity == severity.value]
            if matching:
                grouped.append((severity.value, matching))
        return grouped

    def findings_for_category(self, prefix: str) -> list[ReportFinding]:
        return [f for f in self.findings if f.probe_id.startswith(prefix)]

    def frameworks_covered(self) -> dict[str, list[str]]:
        """Which framework categories the findings actually touch.

        Built from the mappings on real findings, so "covered" means
        something was reported against it — not that a probe for it exists.
        """
        covered: dict[str, set[str]] = {}
        for finding in self.findings:
            for framework, items in finding.mappings.items():
                if isinstance(items, list):
                    covered.setdefault(framework, set()).update(str(item) for item in items)
        return {name: sorted(values) for name, values in sorted(covered.items())}
