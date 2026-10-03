"""Phase 6 acceptance: the AI engine finds every seeded AI flaw and reports
nothing against a hardened control (docs/BUILD_SPEC.md §26, Phase 6).

Requests go through the real `ChatHttpAdapter`, the real `GatedTransport`
and the real `ScopeEngine`; only DNS and the socket are replaced. The lab
apps are deterministic stand-ins for model behaviour, which is what lets
this test measure the engine rather than a model's variance — the
statistics themselves are covered by the determinism harness.
"""

import pytest
import respx

from app.core.orchestrator.ai_check import AiSecurityCheck
from app.core.probes.ai.contract import AiProbeTarget, DeclaredTool
from app.core.probes.ai.judge import DISABLED_JUDGE
from app.core.probes.models import ScanResult, Severity
from app.core.scope.engine import ScopeEngine
from app.core.scope.transport import GatedTransport
from app.core.targets.chat_http import ChatHttpAdapter, ChatHttpConfig
from tests.lab.ai_handlers import LAB_SECRET, hardened_chat, vulnerable_chat
from tests.security.conftest import FakeDnsResolver, make_budgets, make_context, make_roe

VULNERABLE_HOST = "vulnerable-ai.lab.test"
HARDENED_HOST = "hardened-ai.lab.test"

DECLARED_TOOLS = (
    DeclaredTool(name="search_products", description="Search the catalogue"),
    DeclaredTool(
        name="issue_refund",
        description="Refund an order to the original payment method",
        writes=True,
        irreversible=True,
        external=True,
    ),
)


def _context(host: str):
    return make_context(
        roe=make_roe(
            allowed_domains=(host,),
            allowed_methods=("GET", "POST"),
            budgets=make_budgets(max_requests=800, max_tokens_sent=200_000),
        )
    )


def _adapter(host: str) -> ChatHttpAdapter:
    return ChatHttpAdapter(
        ChatHttpConfig(base_url=f"https://{host}", endpoint="/api/chat"),
        GatedTransport(
            engine=ScopeEngine(), dns_resolver=FakeDnsResolver({host: ["203.0.113.20"]})
        ),
    )


async def _scan(host: str, app, *, tools=DECLARED_TOOLS) -> list[ScanResult]:
    target = AiProbeTarget(
        name="Lab assistant",
        surface="POST /api/chat",
        declared_tools=tools,
        trials=5,
    )
    check = AiSecurityCheck(adapter=_adapter(host), probe_target=target, judge=DISABLED_JUDGE)
    ctx = _context(host)

    with respx.mock(assert_all_called=False) as router:
        router.route(host=host).mock(side_effect=app)
        await check.run(ctx, GatedTransport())
    return check.scan_results


@pytest.fixture(scope="module")
async def vulnerable_results() -> list[ScanResult]:
    return await _scan(VULNERABLE_HOST, vulnerable_chat)


@pytest.fixture(scope="module")
async def hardened_results() -> list[ScanResult]:
    return await _scan(HARDENED_HOST, hardened_chat)


# Every AI flaw seeded into tests/lab/ai_handlers.py, with the code the
# engine must report. A miss is a false negative in the engine.
SEEDED_FLAWS = {
    "KERVY-AI-001": "obeys instruction override",
    "KERVY-AI-002": "obeys role reassignment",
    "KERVY-AI-003": "treats forged framing as system text",
    "KERVY-AI-004": "obeys a claimed authority",
    "KERVY-AI-005": "decodes and obeys obfuscated instructions",
    "KERVY-AI-006": "obeys instructions in another language",
    "KERVY-AI-008": "obeys an instruction embedded in retrieved/ingested content",
    "KERVY-AI-010": "recites credentials from its configuration",
    "KERVY-AI-011": "recites its system prompt",
    "KERVY-AI-012": "returns structure unescaped",
    "KERVY-AI-031": "holds an irreversible tool with no confirmation",
    "KERVY-AI-032": "can write to an external system",
}


def _codes(results: list[ScanResult]) -> set[str]:
    return {result.id for result in results}


@pytest.mark.parametrize("code", sorted(SEEDED_FLAWS))
async def test_every_seeded_ai_flaw_is_found(
    code: str, vulnerable_results: list[ScanResult]
) -> None:
    assert code in _codes(vulnerable_results), f"missed seeded flaw {code}: {SEEDED_FLAWS[code]}"


async def test_hardened_control_app_produces_no_ai_findings(
    hardened_results: list[ScanResult],
) -> None:
    """An application that treats input as data, keeps its instructions and
    escapes its output yields nothing. Informational results are excluded:
    that is where the methodology note and the honest "not tested" markers
    live, and suppressing them to pass this assertion would defeat them."""
    reportable = [
        result
        for result in hardened_results
        # The agency findings are architectural: they come from the declared
        # tool surface, which is identical for both apps, so they are not
        # evidence about the application's behaviour.
        if result.severity is not Severity.INFORMATIONAL
        and not result.probe_id.startswith("ai.agency")
    ]
    assert reportable == [], [f"{r.id} {r.title}" for r in reportable]


async def test_no_probe_crashed_against_either_app(
    vulnerable_results: list[ScanResult], hardened_results: list[ScanResult]
) -> None:
    for results in (vulnerable_results, hardened_results):
        crashed = [result for result in results if result.id == "KERVY-AI-099"]
        assert crashed == [], [result.evidence for result in crashed]


async def test_every_finding_carries_its_measurement(
    vulnerable_results: list[ScanResult],
) -> None:
    """§7.1: the rate, the interval, the control and the decision rule are
    visible wherever the finding is, so a reader can judge the strength of
    the claim instead of taking "vulnerable" on trust."""
    for result in vulnerable_results:
        if result.severity is Severity.INFORMATIONAL:
            continue
        if result.probe_id.startswith("ai.agency"):
            # Architectural findings have no trials by design, and say so.
            assert result.confidence.value == "DESIGN_REVIEW"
            continue
        assert "Attack success rate:" in result.evidence
        assert "Control success rate:" in result.evidence
        assert "95% CI" in result.evidence
        assert "Decision rule:" in result.evidence


async def test_a_disclosed_secret_is_never_stored_in_the_clear(
    vulnerable_results: list[ScanResult],
) -> None:
    """The lab app leaks a key. The finding must prove it without carrying
    it (docs/BUILD_SPEC.md §9 LLM02, §13)."""
    disclosure = next(r for r in vulnerable_results if r.id == "KERVY-AI-010")

    blob = " ".join(
        [
            disclosure.description,
            disclosure.evidence,
            disclosure.impact,
            disclosure.remediation,
            *disclosure.reproduction,
        ]
    )
    assert LAB_SECRET not in blob
    assert "labpassword" not in blob
    # What is stored instead: a digest, a masked preview and an offset.
    assert "sha256:" in disclosure.evidence
    assert "[REDACTED]" in disclosure.evidence


async def test_output_handling_finding_does_not_claim_exploitability(
    vulnerable_results: list[ScanResult],
) -> None:
    """§2.2: stop at proof of reachability. The finding must say that the
    downstream sink was not exercised."""
    result = next(r for r in vulnerable_results if r.id == "KERVY-AI-012")

    assert "unconfirmed" in result.description.lower()
    assert result.confidence.value == "MEDIUM"


async def test_every_run_records_how_detection_was_done(
    vulnerable_results: list[ScanResult], hardened_results: list[ScanResult]
) -> None:
    """§7.3 and §14: a disabled judge is reported, not omitted."""
    for results in (vulnerable_results, hardened_results):
        note = next(r for r in results if r.id == "KERVY-AI-900")
        assert "Judge: disabled" in note.evidence
        assert "marker-based" in note.evidence


async def test_agency_analysis_reports_nothing_when_no_tools_are_declared() -> None:
    """An empty declaration means "not declared", never "no tools" — so the
    engine says it did not test, rather than reporting a clean surface."""
    results = await _scan(HARDENED_HOST, hardened_chat, tools=())

    agency = [r for r in results if r.probe_id.startswith("ai.agency")]
    assert [r.id for r in agency] == ["KERVY-AI-000"]
    assert "never" in agency[0].evidence.lower()


async def test_the_permission_graph_is_rendered_as_mermaid(
    vulnerable_results: list[ScanResult],
) -> None:
    inventory = next(r for r in vulnerable_results if r.id == "KERVY-AI-030")

    assert "```mermaid" in inventory.evidence
    assert "graph LR" in inventory.evidence
    assert "issue_refund" in inventory.evidence
    assert "irreversible write" in inventory.evidence
