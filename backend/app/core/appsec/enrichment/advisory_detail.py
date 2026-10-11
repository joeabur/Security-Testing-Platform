"""Turns a finding that already names a verified CVE or GHSA id into one
that also carries NVD's or GHSA's own CVSS score/vector and description —
additive detail, never a replacement for the finding's existing evidence.

**Why this, and not a new discovery engine.** Every SCA engine on this
platform already verifies its own advisory ids before building a finding
(`app/core/appsec/identifiers.py`'s `verified_advisories()`); this module
never originates a new finding, only decorates one that already exists,
using the id `frameworks[0]` already carries — the same "primary"
advisory id every `KERVY-SCA-{primary}` finding id is already built from.

**Severity and confidence never change here.** Reporting NVD's or
GHSA's own real CVSS score as text is not the same as deriving a
severity *enum* from it — this stays a narrative-only annotation on
`description`, the same architectural boundary every reachability pass
this platform has already preserved for its own enrichment.

**Bounded and gracefully degrading, not a second place a run can fail.**
At most `MAX_ENRICHMENT_LOOKUPS` distinct ids are fetched per call — a
large result set past that cap keeps its original text, not an error. A
single id shared by several findings is looked up once, not once per
finding. Any one lookup failing (a 404, a timeout, a scope refusal, an
unparseable body) leaves that one finding exactly as it already was: a
complete, correct finding without this extra detail, never a crash and
never a reason to lose the finding entirely.
"""

from __future__ import annotations

import dataclasses

from app.core.probes.models import ScanResult
from app.core.scope.context import RunContext

from .egress import ghsa_egress_context, nvd_egress_context
from .ghsa_client import GhsaClient, GhsaClientError
from .ghsa_client import cvss_detail as ghsa_cvss_detail
from .nvd_client import NvdClient, NvdClientError
from .nvd_client import cvss_v3_detail as nvd_cvss_v3_detail
from .nvd_client import english_description as nvd_description

#: However many findings share advisory ids, at most this many *distinct*
#: ids are looked up per call — bounding the worst case to a fixed number
#: of outbound requests rather than one per finding.
MAX_ENRICHMENT_LOOKUPS = 25


async def enrich_findings(results: list[ScanResult]) -> list[ScanResult]:
    """Replaces each result's `description` with one that also carries
    direct NVD/GHSA detail, where a lookup for its primary advisory id
    succeeded. Results with no verified `frameworks`, or whose primary id
    is neither CVE- nor GHSA-shaped, pass through unchanged.
    """
    nvd_context = nvd_egress_context()
    ghsa_context = ghsa_egress_context()
    nvd_client = NvdClient()
    ghsa_client = GhsaClient()

    cache: dict[str, str | None] = {}
    enriched: list[ScanResult] = []

    for result in results:
        primary = result.frameworks[0] if result.frameworks else None
        if not primary:
            enriched.append(result)
            continue

        if primary not in cache:
            if len(cache) >= MAX_ENRICHMENT_LOOKUPS:
                cache[primary] = None
            elif primary.startswith("CVE-"):
                cache[primary] = await _nvd_detail_text(nvd_client, nvd_context, primary)
            elif primary.startswith("GHSA-"):
                cache[primary] = await _ghsa_detail_text(ghsa_client, ghsa_context, primary)
            else:
                cache[primary] = None

        detail_text = cache[primary]
        if detail_text is None:
            enriched.append(result)
        else:
            enriched.append(
                dataclasses.replace(result, description=f"{result.description}\n\n{detail_text}")
            )

    return enriched


async def _nvd_detail_text(client: NvdClient, ctx: RunContext, cve_id: str) -> str | None:
    try:
        cve = await client.get_cve(ctx, cve_id)
    except NvdClientError:
        return None
    if cve is None:
        return None

    pieces = [f"Direct NVD lookup for {cve_id}:"]
    cvss = nvd_cvss_v3_detail(cve)
    if cvss is not None:
        score, severity, vector = cvss
        pieces.append(f"CVSS {score} ({severity}, {vector}).")
    description = nvd_description(cve)
    if description:
        pieces.append(description)
    if len(pieces) == 1:
        return None  # nothing beyond the id itself was found
    return " ".join(pieces)


async def _ghsa_detail_text(client: GhsaClient, ctx: RunContext, ghsa_id: str) -> str | None:
    try:
        advisory = await client.get_advisory(ctx, ghsa_id)
    except GhsaClientError:
        return None
    if advisory is None:
        return None

    pieces = [f"Direct GHSA lookup for {ghsa_id}:"]
    cvss = ghsa_cvss_detail(advisory)
    if cvss is not None:
        score, vector = cvss
        pieces.append(f"CVSS {score} ({vector}).")
    summary = advisory.get("summary")
    if isinstance(summary, str) and summary:
        pieces.append(summary)
    if len(pieces) == 1:
        return None
    return " ".join(pieces)
