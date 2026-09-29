"""Phase 14 acceptance: the AppSec engines find every seeded flaw in the
vulnerable repo fixture and report nothing against the hardened control
(docs/BUILD_SPEC.md §26 Phase 14).

These run the real scanners against real files. No tool output is mocked,
because the thing under test is precisely whether this platform reads a
scanner's output correctly.
"""

from pathlib import Path

import pytest

from app.core.appsec.contract import code_span_signature, finding_fingerprint, relative_to_workspace
from app.core.appsec.identifiers import (
    is_advisory,
    is_cve,
    is_cwe,
    is_ghsa,
    verified_advisories,
    verified_cwes,
)
from app.core.appsec.registry import appsec_engines
from app.core.appsec.sast.semgrep_engine import SemgrepEngine
from app.core.appsec.secrets.gitleaks_engine import GitleaksEngine, report_path
from app.core.appsec.tooling import tool_available
from app.core.appsec.workspace import CodeScope, CodeScopeError, resolve_workspace
from app.core.probes.models import Confidence, ScanResult, Severity

REPOS = Path(__file__).parent / "lab" / "repos"
SCOPE = CodeScope(allowed_paths=("src/**", "infra/**", "requirements.txt"))


def _workspace(repo: str):
    return resolve_workspace(REPOS / repo, SCOPE, build_manifest_paths=("requirements.txt",))


async def _scan(repo: str) -> list[ScanResult]:
    workspace = _workspace(repo)
    results: list[ScanResult] = []
    for engine in appsec_engines():
        if engine.applies_to(workspace):
            results.extend(await engine.run(workspace))
    return results


@pytest.fixture(scope="module")
async def vulnerable_results() -> list[ScanResult]:
    return await _scan("vulnerable")


@pytest.fixture(scope="module")
async def hardened_results() -> list[ScanResult]:
    return await _scan("hardened")


def _reportable(results: list[ScanResult]) -> list[ScanResult]:
    return [r for r in results if r.severity is not Severity.INFORMATIONAL]


# Every defect deliberately seeded into tests/lab/repos/vulnerable, with the
# result code the engines must report for it.
SEEDED_FLAWS = {
    "KERVY-SAST-B602": "subprocess with shell=True on caller input",
    "KERVY-SAST-B324": "MD5 used to hash a password",
    "KERVY-SAST-B307": "eval on input",
    "KERVY-SAST-tls-verification-disabled": "requests called with verify=False",
    "KERVY-SAST-unsafe-yaml-load": "yaml.load without a safe loader",
    "KERVY-SECRET-AWS_ACCESS_KEY_ID": "committed AWS access key id",
    "KERVY-SECRET-CONNECTION_STRING": "committed database connection string",
    "KERVY-IAC-CKV_AWS_24": "security group open to the world on SSH",
    "KERVY-IAC-CKV_AWS_20": "S3 bucket with a public-read ACL",
}


@pytest.mark.parametrize("code", sorted(SEEDED_FLAWS))
async def test_every_seeded_appsec_flaw_is_found(
    code: str, vulnerable_results: list[ScanResult]
) -> None:
    found = {result.id for result in vulnerable_results}
    assert code in found, f"missed seeded flaw {code}: {SEEDED_FLAWS[code]}"


async def test_hardened_control_repo_produces_no_findings(
    hardened_results: list[ScanResult],
) -> None:
    """A correctly-written repository yields nothing.

    Informational results are excluded: that is where the honest "not
    tested" markers and the downgraded advisory rules live. A scanner whose
    clean state is unreachable teaches its users to ignore it, so this
    assertion is what keeps the engine useful.
    """
    reportable = _reportable(hardened_results)
    assert reportable == [], [f"{r.id} {r.endpoint}" for r in reportable]


async def test_no_finding_carries_an_invented_identifier(
    vulnerable_results: list[ScanResult],
) -> None:
    """§28: normalization is not a licence to launder an invented identifier.

    Every framework mapping on a finding must be a well-formed CWE, CVE,
    GHSA, OSV id or a recognised framework reference — never something this
    platform constructed from a rule's wording.
    """
    for result in vulnerable_results:
        for reference in result.frameworks:
            assert (
                is_cwe(reference)
                or is_advisory(reference)
                or reference.startswith(("OWASP-", "MITRE-", "NIST-"))
            ), f"{result.id} carries an unverifiable identifier {reference!r}"


async def test_static_findings_are_fingerprinted_and_stable(
    vulnerable_results: list[ScanResult],
) -> None:
    for result in _reportable(vulnerable_results):
        assert result.fingerprint, f"{result.id} has no fingerprint"
        assert result.fingerprint.startswith("sha256:")


def test_a_fingerprint_survives_an_edit_above_the_finding() -> None:
    """The reason fingerprints use a code-span signature rather than a line
    number: inserting a line above an issue must not turn one long-lived
    finding into a new one on every commit."""
    before = finding_fingerprint(
        rule_id="B602", relative_path="src/app.py", snippet="subprocess.call(x, shell=True)"
    )
    after_whitespace_change = finding_fingerprint(
        rule_id="B602", relative_path="src/app.py", snippet="subprocess.call(x,  shell=True)  "
    )
    different_code = finding_fingerprint(
        rule_id="B602", relative_path="src/app.py", snippet="subprocess.call(y, shell=True)"
    )

    assert before == after_whitespace_change
    assert before != different_code


def test_code_span_signature_ignores_formatting_but_not_content() -> None:
    assert code_span_signature("a  =  1") == code_span_signature("a = 1")
    assert code_span_signature("a = 1") != code_span_signature("a = 2")


async def test_every_finding_has_reproduction_steps_and_remediation(
    vulnerable_results: list[ScanResult],
) -> None:
    for result in _reportable(vulnerable_results):
        assert result.reproduction, f"{result.id} has no reproduction steps"
        assert result.remediation.strip(), f"{result.id} has no remediation"
        assert result.probe_id and result.probe_version


async def test_a_committed_secret_is_reported_without_its_value(
    vulnerable_results: list[ScanResult],
) -> None:
    """§13: the digest and a masked preview prove the finding; the value
    itself is never stored."""
    secret = next(r for r in vulnerable_results if r.id == "KERVY-SECRET-AWS_ACCESS_KEY_ID")
    blob = " ".join([secret.description, secret.evidence, secret.remediation])

    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "sha256:" in secret.evidence
    assert secret.severity is Severity.CRITICAL


async def test_advisory_rules_are_downgraded_not_suppressed(
    hardened_results: list[ScanResult],
) -> None:
    """Bandit's B404/B603/B607 fire on correctly-written code. They are
    recorded as informational so the coverage stays visible, rather than
    dropped — §28 forbids silent suppression."""
    advisory = [r for r in hardened_results if r.id in ("KERVY-SAST-B404", "KERVY-SAST-B603")]

    assert advisory, "the advisory rules should still be recorded on the control repo"
    for result in advisory:
        assert result.severity is Severity.INFORMATIONAL
        assert "informational rather than as a finding" in result.description


async def test_dependency_advisory_lookup_is_off_unless_enabled() -> None:
    """Matching dependencies against an advisory database sends the client's
    dependency list to a third party. That is a disclosure the operator opts
    into, so the default says what it did not do rather than returning
    nothing."""
    workspace = _workspace("vulnerable")
    engine = next(e for e in appsec_engines() if e.meta.pillar.value == "sca")

    results = await engine.run(workspace)

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "disclosure" in results[0].evidence.lower()


# --- scope enforcement ---------------------------------------------------


def test_an_empty_allowlist_is_refused_rather_than_read_as_everything() -> None:
    with pytest.raises(CodeScopeError, match="not a permissive one"):
        CodeScope(allowed_paths=())


def test_excluded_paths_beat_allowed_paths() -> None:
    workspace = resolve_workspace(
        REPOS / "vulnerable",
        CodeScope(allowed_paths=("src/**", "infra/**"), excluded_paths=("infra/**",)),
    )

    assert "src/app.py" in workspace.relative_files
    assert not [name for name in workspace.relative_files if name.startswith("infra/")]


def test_a_file_outside_the_allowlist_is_never_enumerated() -> None:
    workspace = resolve_workspace(REPOS / "vulnerable", CodeScope(allowed_paths=("src/**",)))

    assert workspace.relative_files == ("src/app.py",)
    assert "README.md" not in workspace.relative_files


def test_a_repository_over_the_size_cap_is_refused_not_truncated(tmp_path: Path) -> None:
    """A partial scan reported as a complete one is the dishonest outcome."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "big.py").write_bytes(b"# padding\n" * 200_000)  # ~2 MB

    with pytest.raises(CodeScopeError, match="exceeds code_scope.max_repo_size_mb"):
        resolve_workspace(tmp_path, CodeScope(allowed_paths=("src/**",), max_repo_size_mb=1))


def test_engines_that_need_a_missing_tool_report_a_gap_not_a_clean_result() -> None:
    """Graceful degradation (§15) must never look like a passing scan."""
    from app.core.appsec.contract import EngineMeta, Pillar, tool_unavailable

    meta = EngineMeta(
        id="appsec.test",
        version="1.0.0",
        name="Test engine",
        pillar=Pillar.SAST,
        tool="nonexistent-scanner",
        description="",
    )
    result = tool_unavailable(meta, "nonexistent-scanner is not installed on this worker")

    assert result.severity is Severity.INFORMATIONAL
    assert "did not run" in result.description
    assert "not the same as it passing" in result.impact


def test_tool_availability_is_detected_rather_than_assumed() -> None:
    assert tool_available("python3") is True
    assert tool_available("kervy-definitely-not-a-real-binary") is False


# --- identifier verification --------------------------------------------


def test_only_well_formed_identifiers_survive_verification() -> None:
    assert is_cve("CVE-2021-44228")
    assert not is_cve("CVE-21-4")
    assert is_ghsa("GHSA-jfh8-c2jp-5v3q")
    assert not is_ghsa("GHSA-not-a-real-id")
    assert is_cwe("CWE-79")
    assert not is_cwe("CWE-")

    assert verified_advisories(["CVE-2021-44228", "made-up", "PYSEC-2021-76"]) == (
        "CVE-2021-44228",
        "PYSEC-2021-76",
    )
    # A bare number is formatting, not invention, so it is normalised.
    assert verified_cwes([79, "CWE-89", "nonsense"]) == ("CWE-79", "CWE-89")


# --- orchestrator integration -------------------------------------------


async def test_the_code_check_runs_every_applicable_engine() -> None:
    from app.core.orchestrator.code_check import CodeScanCheck
    from app.core.scope.transport import GatedTransport
    from tests.security.conftest import make_context

    check = CodeScanCheck(engines=appsec_engines(), workspace=_workspace("vulnerable"))

    results = await check.run(make_context(), GatedTransport())

    assert {result.surface for result in results} >= {
        "appsec.sast.bandit",
        "appsec.secrets.repository",
        "appsec.iac.checkov",
    }
    assert all(result.ok for result in results)
    assert _reportable(check.scan_results)


async def test_a_crashing_engine_is_a_visible_gap_not_a_silent_pass() -> None:
    from app.core.appsec.contract import EngineMeta, Pillar
    from app.core.orchestrator.code_check import CodeScanCheck
    from app.core.scope.transport import GatedTransport
    from tests.security.conftest import make_context

    class _Exploding:
        meta = EngineMeta(
            id="appsec.test.explode",
            version="1.0.0",
            name="Exploding engine",
            pillar=Pillar.SAST,
            tool="none",
            description="",
        )

        def applies_to(self, workspace: object) -> bool:
            return True

        async def run(self, workspace: object) -> list[ScanResult]:
            raise RuntimeError("engine boom")

    check = CodeScanCheck(engines=[_Exploding()], workspace=_workspace("hardened"))

    results = await check.run(make_context(), GatedTransport())

    assert results[0].ok is False
    assert "engine boom" in results[0].detail
    assert [r.id for r in check.scan_results] == ["KERVY-APPSEC-099"]


async def test_the_code_check_stops_when_the_run_halts() -> None:
    from app.core.orchestrator.code_check import CodeScanCheck
    from app.core.scope.transport import GatedTransport
    from tests.security.conftest import make_context

    ctx = make_context()
    ctx.kill_switch.trip()
    check = CodeScanCheck(engines=appsec_engines(), workspace=_workspace("vulnerable"))

    assert await check.run(ctx, GatedTransport()) == []
    assert check.scan_results == []


# --- SCA normalization ---------------------------------------------------

_PIP_AUDIT_PAYLOAD = {
    "dependencies": [
        {
            "name": "jinja2",
            "version": "2.10",
            "vulns": [
                {
                    "id": "GHSA-462w-v97r-4m45",
                    "aliases": ["CVE-2019-10906"],
                    "fix_versions": ["2.10.1"],
                }
            ],
        },
        {
            "name": "requests",
            "version": "2.19.1",
            "vulns": [{"id": "PYSEC-2018-28", "aliases": [], "fix_versions": []}],
        },
        {
            # A vulnerability with no verifiable identifier must not become a
            # finding: a reader cannot look it up, and naming it something
            # plausible would be worse than silence.
            "name": "mystery",
            "version": "1.0",
            "vulns": [{"id": "definitely-not-an-advisory-id", "aliases": ["also-not-one"]}],
        },
    ]
}


def test_sca_normalization_keeps_only_verifiable_advisories() -> None:
    from app.core.appsec.sca.pip_audit_engine import PipAuditEngine

    findings = PipAuditEngine()._normalize(_PIP_AUDIT_PAYLOAD, "requirements.txt")

    codes = {result.id for result in findings}
    assert codes == {"KERVY-SCA-GHSA-462w-v97r-4m45", "KERVY-SCA-PYSEC-2018-28"}
    assert not [r for r in findings if "mystery" in r.endpoint]


def test_sca_finding_states_the_resolved_and_first_patched_versions() -> None:
    from app.core.appsec.sca.pip_audit_engine import PipAuditEngine

    findings = PipAuditEngine()._normalize(_PIP_AUDIT_PAYLOAD, "requirements.txt")
    jinja = next(r for r in findings if "jinja2" in r.endpoint)

    assert "2.10" in jinja.description
    assert "2.10.1" in jinja.description
    assert "CVE-2019-10906" in jinja.frameworks
    # Reachability is not assessed by an SCA tool, and the finding says so
    # rather than implying the vulnerable path is used.
    assert "Reachability was not assessed" in jinja.impact


def test_an_unfixed_dependency_says_so_rather_than_inventing_a_version() -> None:
    from app.core.appsec.sca.pip_audit_engine import PipAuditEngine

    findings = PipAuditEngine()._normalize(_PIP_AUDIT_PAYLOAD, "requirements.txt")
    requests = next(r for r in findings if "requests" in r.endpoint)

    assert "No fixed version is published" in requests.description
    assert requests.severity is Severity.MEDIUM


def test_sca_fingerprint_ignores_the_resolved_version() -> None:
    """The same unfixed dependency is one finding across runs; a patch bump
    that does not fix it should not present as a brand new issue."""
    from app.core.appsec.sca.pip_audit_engine import PipAuditEngine

    engine = PipAuditEngine()
    first = engine._normalize(_PIP_AUDIT_PAYLOAD, "requirements.txt")[0]
    bumped = {
        "dependencies": [{**_PIP_AUDIT_PAYLOAD["dependencies"][0], "version": "2.10.0.post1"}]
    }
    second = engine._normalize(bumped, "requirements.txt")[0]

    assert first.fingerprint == second.fingerprint


# --- paths (a lab audit found these the hard way) -------------------------


def test_a_path_outside_the_workspace_is_dropped_not_trimmed() -> None:
    """A result about a file the operator did not put in scope is not a
    result this platform reports, however the tool phrased the path."""
    workspace = _workspace("vulnerable")
    assert relative_to_workspace("/etc/passwd", workspace) is None
    assert relative_to_workspace("", workspace) is None
    assert relative_to_workspace("../../etc/passwd", workspace) is None


def test_the_shapes_a_tool_actually_emits_all_normalize() -> None:
    workspace = _workspace("vulnerable")
    absolute = str(workspace.root / "src/app.py")
    for raw in ("src/app.py", "./src/app.py", absolute, f"file://{absolute}"):
        assert relative_to_workspace(raw, workspace) == "src/app.py", raw


def test_a_sarif_absolute_uri_does_not_leak_the_checkout_directory(tmp_path: Path) -> None:
    """The bug this test exists for: `uri.lstrip("./")` strips characters,
    not a prefix, so an absolute URI became `home/runner/checkout-a1b2/...`.
    A checkout directory is unique per run, and the path is part of the
    fingerprint — so every finding got a new identity on every scan, and the
    worker's filesystem layout went into the report.
    """
    engine = SemgrepEngine()

    def _sarif(root: Path) -> dict:
        return {
            "runs": [
                {
                    "tool": {"driver": {"rules": [{"id": "kervy.unsafe-yaml-load"}]}},
                    "results": [
                        {
                            "ruleId": "kervy.unsafe-yaml-load",
                            "message": {"text": "yaml.load without SafeLoader"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": str(root / "src/app.py")},
                                        "region": {
                                            "startLine": 36,
                                            "snippet": {"text": "yaml.load(raw)"},
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    # The same file, scanned from two different checkout directories.
    fingerprints = set()
    for name in ("checkout-a1b2", "checkout-c3d4"):
        root = tmp_path / name
        (root / "src").mkdir(parents=True)
        (root / "src/app.py").write_text("yaml.load(raw)\n", encoding="utf-8")
        workspace = resolve_workspace(root, CodeScope(allowed_paths=("src/**",)))

        findings = engine.parse_sarif(_sarif(root), workspace)
        assert len(findings) == 1
        assert findings[0].endpoint == "src/app.py:36"
        assert str(root) not in findings[0].endpoint
        assert str(root) not in findings[0].evidence
        fingerprints.add(findings[0].fingerprint)

    assert len(fingerprints) == 1, "the same defect must keep one identity across checkouts"


async def test_every_reportable_static_finding_carries_downloadable_evidence(
    vulnerable_results: list[ScanResult],
) -> None:
    """Evidence is what makes a retest a comparison rather than an opinion.

    Only reportable findings: a "not tested" marker has no code span behind
    it, and giving it one would make the evidence manifest claim a scan that
    did not happen.
    """
    for result in _reportable(vulnerable_results):
        assert result.evidence_bundle is not None, result.id
        assert result.evidence_bundle.request["method"] == "SCAN"
        assert result.evidence_bundle.adapter["rule_id"]


async def test_a_secret_findings_bundle_does_not_republish_the_secret(
    vulnerable_results: list[ScanResult],
) -> None:
    """The one place where storing evidence verbatim would spread the very
    thing being reported."""
    secrets = [r for r in vulnerable_results if r.id.startswith("KERVY-SECRET-")]
    assert secrets
    for result in secrets:
        assert result.evidence_bundle is not None
        payload = result.evidence_bundle.canonical_bytes().decode()
        assert "AKIA" not in payload or "AKIA****" in payload
        assert "kervy-dev-only" not in payload


# --- gitleaks (Phase 11's third tool adapter) -----------------------------

GITLEAKS_REPORT = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "File": "src/app.py",
        "StartLine": 10,
        "Commit": "9f1c2d3e4a5b6c7d8e9f0a1b2c3d4e5f60718293",
        "Author": "A Developer",
        "Date": "2026-02-11T09:14:00Z",
        # A real-looking value on purpose. Gitleaks `--redact` would have
        # replaced it, but the adapter must not depend on a flag staying set in
        # a future release, so the unredacted path is what gets tested.
        "Secret": "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
        "Match": "aws_key = AKIAIOSFODNN7EXAMPLE",
    },
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "src/app.py",
        "StartLine": 42,
        "Commit": "",
        "Secret": "s3cret-in-the-working-tree",
    },
    {
        # Outside the workspace: dropped, like every other engine's output.
        "RuleID": "aws-access-token",
        "File": "/etc/shadow",
        "StartLine": 1,
        "Commit": "abc",
    },
    {
        # No rule id: cannot be fingerprinted or traced upstream.
        "RuleID": "",
        "File": "src/app.py",
        "StartLine": 3,
    },
]


def test_gitleaks_output_normalizes_without_keeping_the_value() -> None:
    """The adapter's whole job. Gitleaks prints the match; a findings table
    that stores credentials is a credential store nobody secured."""
    engine = GitleaksEngine()
    workspace = _workspace("vulnerable")

    findings = engine.parse(GITLEAKS_REPORT, workspace)

    assert [f.endpoint for f in findings] == ["src/app.py:10", "src/app.py:42"]
    leaked = ("AKIAIOSFODNN7EXAMPLE", "s3cret-in-the-working-tree")
    for finding in findings:
        assert "sha256=" in finding.evidence
        assert finding.fingerprint is not None
        assert finding.evidence_bundle is not None
        serialized = finding.evidence_bundle.canonical_bytes().decode()
        for value in leaked:
            assert value not in finding.evidence
            assert value not in finding.description
            assert value not in serialized


def test_a_history_only_secret_says_that_removing_the_line_is_not_enough() -> None:
    findings = GitleaksEngine().parse(GITLEAKS_REPORT, _workspace("vulnerable"))
    historical = findings[0]

    assert historical.severity is Severity.CRITICAL
    assert "9f1c2d3e4a5b" in historical.description
    assert "does not remove it" in historical.description
    assert "Rotate the credential first" in historical.remediation


def test_a_shape_matched_secret_is_reported_lower_not_suppressed() -> None:
    """It fires on test fixtures and checksums as well as real credentials.
    Suppressing the rule would hide the one that is real."""
    generic = GitleaksEngine().parse(GITLEAKS_REPORT, _workspace("vulnerable"))[1]

    assert generic.severity is Severity.MEDIUM
    assert generic.confidence is Confidence.MEDIUM
    assert "fires on test fixtures" in generic.description


def test_gitleaks_only_applies_where_there_is_history_to_read() -> None:
    """Against a plain directory it would add nothing the working-tree engine
    does not already cover."""
    assert not GitleaksEngine().applies_to(_workspace("vulnerable"))


async def test_gitleaks_reports_a_gap_when_the_tool_is_absent(tmp_path: Path) -> None:
    """§15's graceful degradation: a missing scanner produces a visible gap,
    never an empty result set that reads as "nothing found"."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("src/**",)))

    engine = GitleaksEngine()
    assert engine.applies_to(workspace)

    results = await engine.run(workspace)

    assert len(results) == 1
    assert results[0].id == "KERVY-APPSEC-000"
    assert results[0].severity is Severity.INFORMATIONAL
    # And the report file it would have written is not left behind.
    assert not report_path(workspace).exists()
