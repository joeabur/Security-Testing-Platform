"""A fixed `ReportData` for the reporting tests.

Hand-built rather than produced by a run, for one reason: a golden snapshot
has to be deterministic. Nothing here is random, no timestamp is "now", and
the findings cover the awkward cases on purpose — a measured probe with
rates, a design-review finding with none, a code finding whose surface is a
file and line, and a finding whose text contains characters that HTML, CSV
and SARIF each handle differently.
"""

from dataclasses import replace
from datetime import UTC, datetime

from app.core.measure.asr import DEFAULT_RULE, asr_delta, rate_of
from app.core.reporting.model import (
    NotTested,
    PillarCoverage,
    ReportData,
    ReportFinding,
    RetestRecord,
)
from app.core.risk.publish import render_markdown as render_risk_tables

FIXED_TIME = datetime(2026, 3, 4, 9, 30, 0, tzinfo=UTC)


def _finding(**overrides: object) -> ReportFinding:
    base: dict[str, object] = {
        "id": "00000000-0000-0000-0000-000000000001",
        "fingerprint": "sha256:" + "1" * 64,
        "title": "Direct prompt injection overrides the system instruction",
        "category": "PROMPT_INJECTION",
        "severity": "HIGH",
        "severity_rationale": "Risk 7.4/10 (high): impact major, likelihood 0.62, confidence high.",
        "confidence": "HIGH",
        "stability": "deterministic",
        "risk_model": "kervy-v1",
        "risk_score": 7.4,
        "risk_inputs": {
            "impact": "major",
            "likelihood": 0.62,
            "confidence_weight": 1.0,
            "exposure_modifier": 1.0,
        },
        "surface": "POST /api/chat",
        "probe_id": "KERVY-AI-001",
        "probe_version": "1.0.0",
        "description": "The assistant followed an instruction embedded in user input.",
        "impact": "An untrusted instruction can redirect the assistant's behaviour.",
        "remediation": "Separate instructions from data; re-assert the system policy per turn.",
        "reproduction": [
            "Send a turn containing an overriding instruction.",
            "Observe the canary in the reply.",
        ],
        "mappings": {"owasp_llm": ["LLM01"], "mitre_atlas": ["AML.T0051"]},
        "mapping_versions": {"owasp_llm": "2025", "mitre_atlas": "4.5.2"},
        "attack_success_rate": {"successes": 5, "trials": 5, "rate": 1.0, "ci95": [0.566, 1.0]},
        "control_success_rate": {"successes": 0, "trials": 5, "rate": 0.0, "ci95": [0.0, 0.434]},
        "evidence_ref": "sha256:" + "a" * 64,
        "status": "new",
        "first_seen": "2026-03-04T09:00:00+00:00",
        "last_seen": "2026-03-04T09:25:00+00:00",
        "times_seen": 2,
    }
    base.update(overrides)
    return ReportFinding(**base)  # type: ignore[arg-type]


def sample_report() -> ReportData:
    return ReportData(
        organization="11111111-1111-1111-1111-111111111111",
        target_name='Support assistant "beta" & API',
        target_kind="llm_app",
        target_environment="staging",
        target_base_url="https://assistant.example.test",
        run_id="22222222-2222-2222-2222-222222222222",
        generated_at=FIXED_TIME,
        tool_version="0.1.0",
        authorization_reference="AUTH-2026-014",
        authorization_by="A. Okafor (CISO)",
        authorization_valid_from="2026-03-01T00:00:00+00:00",
        authorization_valid_until="2026-03-31T00:00:00+00:00",
        authorization_digest="sha256:" + "b" * 64,
        roe_digest="sha256:" + "c" * 64,
        excluded_domains=["payments.example.test"],
        excluded_paths=["/admin"],
        safe_mode=True,
        trials_per_probe=5,
        decision_rule=DEFAULT_RULE,
        judge_status="Judge: not used in this run; all detections are deterministic.",
        limitations=["No source repository was configured, so SAST did not run."],
        adapters=["chat_http"],
        endpoints=["POST /api/chat", "GET /api/history"],
        declared_tools=["search_docs", "create_ticket"],
        permission_graph="graph TD\n  assistant --> search_docs",
        findings=[
            _finding(),
            _finding(
                id="00000000-0000-0000-0000-000000000002",
                fingerprint="sha256:" + "2" * 64,
                title="Tool invocation is not scoped to the requesting user",
                category="EXCESSIVE_AGENCY",
                severity="MEDIUM",
                severity_rationale=(
                    "Risk 5.0/10 (medium): impact moderate, likelihood 0.5, confidence medium."
                ),
                confidence="MEDIUM",
                stability="single_shot",
                risk_score=5.0,
                risk_inputs={
                    "impact": "moderate",
                    "likelihood": 0.5,
                    "confidence_weight": 0.8,
                    "exposure_modifier": 1.0,
                },
                surface="declared tool: create_ticket",
                probe_id="KERVY-AI-030",
                probe_version="1.0.0",
                description="The declared tool accepts an arbitrary account identifier.",
                impact="A user could act on another account through the assistant.",
                remediation="Bind tool calls to the authenticated principal.",
                reproduction=["Review the declared tool schema."],
                mappings={"owasp_llm": ["LLM06"]},
                mapping_versions={"owasp_llm": "2025"},
                attack_success_rate=None,
                control_success_rate=None,
                evidence_ref=None,
                status="triaged",
                times_seen=1,
            ),
            _finding(
                id="00000000-0000-0000-0000-000000000003",
                fingerprint="sha256:" + "3" * 64,
                title="Command built from unvalidated input, with a <script> in the snippet",
                category="INJECTION",
                severity="CRITICAL",
                severity_rationale=(
                    'Risk 9.1/10 (critical): impact severe, "likelihood" 0.9, confidence high.'
                ),
                confidence="HIGH",
                stability="deterministic",
                risk_score=9.1,
                surface="app/handlers.py:42",
                probe_id="KERVY-SAST-B602",
                probe_version="bandit-1.7",
                description="subprocess called with shell=True on a request-derived value.",
                impact="Remote command execution.",
                remediation="Pass an argument list; never shell=True.",
                reproduction=["Read app/handlers.py:42."],
                mappings={"cwe": ["CWE-78"], "owasp_asvs": ["V5.3.8"]},
                mapping_versions={"cwe": "4.15", "owasp_asvs": "4.0.3"},
                attack_success_rate=None,
                control_success_rate=None,
                evidence_ref="sha256:" + "d" * 64,
                status="confirmed",
                times_seen=1,
            ),
        ],
        not_tested=[
            NotTested(
                area="dependency advisories",
                reason="Advisory lookup is disabled by default (no outbound disclosure).",
                probe_id="KERVY-APPSEC-000",
            ),
        ],
        # Every pillar, always. The fixture mixes tested and untested ones so a
        # renderer that only emitted the untested (or only the tested) half
        # would show up in the snapshots.
        pillar_coverage=[
            PillarCoverage(
                pillar="AI security", tested=True, detail="Ran and reported against this target."
            ),
            PillarCoverage(
                pillar="API security", tested=True, detail="Ran and reported against this target."
            ),
            PillarCoverage(
                pillar="SAST", tested=True, detail="Ran and reported against this target."
            ),
            PillarCoverage(
                pillar="DAST",
                tested=False,
                detail=(
                    "This target is registered as 'llm_app'; the crawler and the DAST "
                    "scanners run only against a target registered as 'web_app'."
                ),
            ),
            PillarCoverage(
                pillar="SCA",
                tested=False,
                detail="No source repository is configured, so no dependency manifest was read.",
            ),
            PillarCoverage(
                pillar="Secrets", tested=False, detail="No source repository is configured."
            ),
            PillarCoverage(
                pillar="IaC", tested=False, detail="No source repository is configured."
            ),
            PillarCoverage(
                pillar="RASP",
                tested=False,
                detail=(
                    "No runtime-protection engine exists on this platform. This target "
                    "declares no runtime protection."
                ),
            ),
            PillarCoverage(
                pillar="Container",
                tested=False,
                detail=(
                    "This target is registered as 'llm_app'; the container engine runs "
                    "only against a target registered as 'container'."
                ),
            ),
            PillarCoverage(
                pillar="Cloud",
                tested=False,
                detail=(
                    "This target is registered as 'llm_app'; the cloud engine runs only "
                    "against a target registered as 'cloud_account'."
                ),
            ),
            PillarCoverage(
                pillar="VM",
                tested=False,
                detail=(
                    "This target is registered as 'llm_app'; the VM engine runs only "
                    "against a target registered as 'virtual_machine'."
                ),
            ),
            PillarCoverage(
                pillar="Domain",
                tested=False,
                detail=(
                    "This target is registered as 'llm_app'; the domain engine runs only "
                    "against a target registered as 'domain'."
                ),
            ),
            PillarCoverage(
                pillar="Pentest",
                tested=False,
                detail=(
                    "No pentest tools were configured or authorized for this run's "
                    "Rules of Engagement (`asset_scope.pentest`)."
                ),
            ),
        ],
        checks_completed=4,
        checks_total=5,
        requests_blocked=2,
        halted_reason=None,
        risk_model_tables=render_risk_tables(),
        tool_versions={"kervy": "0.1.0", "bandit": "1.7.9"},
        ai_drafted_sections=["remediation"],
    )


def retest_report() -> ReportData:
    """The same assessment, re-run as a retest, with one of each verdict.

    All three on purpose. A renderer that only ever saw reproduced and not
    reproduced could quietly present `not_tested` as good news, which is the
    one outcome that must never read as a fix.
    """
    base = sample_report()
    return replace(
        base,
        is_retest=True,
        retests=[
            RetestRecord(
                fingerprint="sha256:" + "3" * 64,
                title="Command built from unvalidated input, with a <script> in the snippet",
                severity="CRITICAL",
                verdict="reproduced",
                before_evidence_ref="sha256:" + "d" * 64,
                after_evidence_ref="sha256:" + "e" * 64,
                detail="This run reported the same fingerprint again.",
                attack_success_rate_delta=asr_delta(
                    rate_of(3, 5).as_dict(), rate_of(5, 5).as_dict()
                ),
            ),
            RetestRecord(
                fingerprint="sha256:" + "1" * 64,
                title="Direct prompt injection overrides the system instruction",
                severity="HIGH",
                verdict="not_reproduced",
                before_evidence_ref="sha256:" + "a" * 64,
                after_evidence_ref=None,
                detail="KERVY-AI-001 ran and did not report this fingerprint.",
            ),
            RetestRecord(
                fingerprint="sha256:" + "2" * 64,
                title="Tool invocation is not scoped to the requesting user",
                severity="MEDIUM",
                verdict="not_tested",
                before_evidence_ref=None,
                after_evidence_ref=None,
                detail=("KERVY-AI-030 produced no result in this run. Not looking is not a fix."),
            ),
        ],
    )
