"""The DAST engine: crawl, report what the crawl learned, then run the tools.

The crawl is not just reconnaissance for the scanners — it produces findings of
its own, and two of them matter more than any template match:

* **`KERVY-DAST-001`, out-of-scope links.** The application links somewhere the
  engagement does not cover. That is how you discover a third-party tracker, or
  that the authorization covers less than the application spans.
* **`KERVY-DAST-009`, incomplete coverage.** The crawl stopped at a bound.
  Without this a report listing three findings from five pages reads as though
  the whole application was assessed.

`KERVY-DAST-002` records the state-changing forms found and *not* submitted,
because a reviewer wants to know they exist even when nothing touched them.
"""

from __future__ import annotations

from app.core.appsec.contract import Pillar, tool_unavailable
from app.core.dast.contract import CrawlOutcome, CrawlResult, DastTarget
from app.core.dast.crawl import ScopedCrawler, refused_hosts, state_changing_forms
from app.core.dast.egress_proxy import EgressGateway
from app.core.dast.nuclei import META as NUCLEI_META
from app.core.dast.nuclei import run_nuclei
from app.core.dast.policy import ToolPolicy, tool_policy
from app.core.dast.zap import META as ZAP_META
from app.core.dast.zap import run_zap
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport

ENGINE_ID = "dast.engine"
ENGINE_VERSION = "1.0.0"


def crawl_findings(result: CrawlResult, policy: ToolPolicy) -> list[ScanResult]:
    findings: list[ScanResult] = []

    if result.refused:
        hosts = refused_hosts(result)
        listed = "\n".join(
            f"{item.url}  ({item.rule}) — linked from {item.discovered_on or 'the seed'}"
            for item in result.refused[:50]
        )
        findings.append(
            ScanResult(
                id="KERVY-DAST-001",
                title=(
                    f"Application links to {len(result.refused)} location(s) outside "
                    "the rules of engagement"
                ),
                category=Category.DESIGN,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                endpoint="dast/crawl",
                description=(
                    "These URLs were discovered during the crawl and refused before "
                    "being queued, so none was requested. They are reported because an "
                    "application linking outside the engagement is worth knowing about: "
                    "it may be a third-party dependency nobody authorized testing of, or "
                    "a sign the authorization covers less than the application spans.\n\n"
                    f"Hosts: {', '.join(hosts) or 'none'}"
                ),
                evidence=listed,
                impact=(
                    "None from this scan — nothing was sent to these URLs. The question "
                    "is whether the engagement's boundary matches the application's."
                ),
                remediation=(
                    "Confirm each destination is expected. Widen the rules of engagement "
                    "only where an authorization covers it."
                ),
                probe_id=ENGINE_ID,
                probe_version=ENGINE_VERSION,
            )
        )

    forms = state_changing_forms(result)
    if forms:
        findings.append(
            ScanResult(
                id="KERVY-DAST-002",
                title=f"{len(forms)} state-changing form(s) found and not submitted",
                category=Category.DESIGN,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.DESIGN_REVIEW,
                endpoint="dast/forms",
                description=(
                    "The crawler records form actions but never submits one. "
                    + (
                        "This run allows state mutation, but the crawler still does not "
                        "submit forms — only the active scanners may, and only within "
                        "their template policy."
                        if policy.allow_state_mutation
                        else "This run does not allow state mutation, so no active "
                        "scanner ran against them either."
                    )
                ),
                evidence="\n".join(forms[:50]),
                impact="None from this scan. Listed so a reviewer knows what was not tested.",
                remediation=(
                    "If these should be tested, record an authorization that allows state "
                    "mutation and re-run against a non-production environment."
                ),
                probe_id=ENGINE_ID,
                probe_version=ENGINE_VERSION,
            )
        )

    if not result.complete():
        findings.append(
            ScanResult(
                id="KERVY-DAST-009",
                title=f"Not tested: crawl stopped ({result.outcome.value})",
                category=Category.INFRASTRUCTURE,
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.DESIGN_REVIEW,
                endpoint="dast/coverage",
                description=(
                    f"The crawl visited {len(result.pages)} page(s) and stopped because "
                    f"{_why(result.outcome)}. {len(result.unvisited)} in-scope URL(s) were "
                    "queued but never fetched, so this assessment says nothing about them."
                ),
                evidence="\n".join(result.unvisited[:50]) or "(no URLs left queued)",
                impact=(
                    "Unknown for the pages not reached. A finding count from a partial "
                    "crawl is not a statement about the whole application."
                ),
                remediation=(
                    "Raise the crawl limits or the request budget and re-run, or record "
                    "the uncrawled area as out of scope for this engagement."
                ),
                probe_id=ENGINE_ID,
                probe_version=ENGINE_VERSION,
            )
        )
    return findings


def _why(outcome: CrawlOutcome) -> str:
    return {
        CrawlOutcome.EXHAUSTED: "it ran out of in-scope links",
        CrawlOutcome.PAGE_LIMIT: "it reached the page limit",
        CrawlOutcome.DEPTH_LIMIT: "it reached the depth limit",
        CrawlOutcome.BUDGET_EXHAUSTED: "the run's request budget ran out",
        CrawlOutcome.HALTED: "the run was halted",
    }[outcome]


class DastEngine:
    """Crawl, then hand the cleared URLs to the tool adapters."""

    pillar = Pillar.DAST

    def __init__(
        self,
        *,
        crawler: ScopedCrawler | None = None,
        transport: GatedTransport | None = None,
        run_tools: bool = True,
    ) -> None:
        self._crawler = crawler or ScopedCrawler(transport=transport)
        # Off in tests that only exercise the crawl, so a worker without nuclei
        # or zap installed does not produce two "not tested" markers in every
        # unrelated assertion.
        self._run_tools = run_tools

    async def run(self, ctx: RunContext, target: DastTarget) -> list[ScanResult]:
        policy = tool_policy(
            allow_state_mutation=target.allow_state_mutation,
            allowed_methods=ctx.roe.allowed_methods,
        )
        result = await self._crawler.crawl(ctx, target)
        findings = crawl_findings(result, policy)

        if not self._run_tools:
            return findings

        if not result.pages:
            # Nothing was reachable, so the tools have nothing to test. Said
            # explicitly: two silent adapters would read as two clean scans.
            findings.append(
                tool_unavailable(
                    NUCLEI_META, "the crawl reached no pages, so nuclei had no targets"
                )
            )
            findings.append(
                tool_unavailable(ZAP_META, "the crawl reached no pages, so zap was not run")
            )
            return findings

        rate = max(1, int(ctx.roe.budgets.requests_per_second))
        # Nuclei and ZAP are subprocesses that open their own sockets, outside
        # GatedTransport's view. Every connection either one makes is pointed
        # at this run's own scope-checking proxy instead, so a destination
        # that rebinds to a private IP or the metadata endpoint between crawl
        # time and tool invocation is still refused. docs/egress-security.md
        # has the full model, including what this gateway cannot see inside
        # an HTTPS tunnel.
        async with EgressGateway(ctx) as gateway:
            findings.extend(
                await run_nuclei(list(result.urls), policy, rate=rate, proxy_url=gateway.proxy_url)
            )
            findings.extend(
                await run_zap(
                    target.seed_url,
                    policy,
                    allowed_domains=ctx.roe.allowed_domains,
                    proxy_url=gateway.proxy_url,
                )
            )
        return findings
