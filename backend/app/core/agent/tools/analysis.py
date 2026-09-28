"""`analyze_finding` — an AI-drafted explanation of one finding.

Reuses `app.core.assistant.service.AIService.explain_finding` in-process
rather than a second code path for "ask a model about a finding": the same
prompt template, the same evidence-fencing, the same observed/inferred/
recommended/unknown labelling discipline the assistant's own
`POST .../drafts` endpoint already provides. READ_ONLY — it drafts an
explanation and returns it; nothing is written, and (unlike a draft
requested through the assistant API) there is no `AiDraft` row to accept,
because the agent framework's zero-persistence rule means nothing here is
kept past the request either way.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from pydantic import BaseModel
from sqlalchemy import select

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolExecutionError, ToolNotFoundError
from app.core.assistant.autonomy import AutonomyMode
from app.core.assistant.provider import ProviderError, ProviderNotConfiguredError
from app.core.assistant.service import AIService, FindingView
from app.core.config import get_settings
from app.core.evidence.store import EvidenceError, EvidenceStore
from app.models.finding import Finding
from app.models.organization import Role

# Matches app/core/assistant/service.py's own cap: evidence this large adds
# cost without adding signal, and the model is instructed to draw only from
# what it is shown either way.
MAX_EVIDENCE_CHARS = 4000


def _evidence_store() -> EvidenceStore:
    settings = get_settings()
    return EvidenceStore(Path(settings.evidence_root), key=settings.evidence_encryption_key_bytes)


def _evidence_text(finding: Finding) -> str:
    """Best-effort: a finding with no sealed evidence bundle (or one that
    cannot be read) still gets explained — `explain_finding`'s own labelling
    discipline already says "unknown" for whatever it was not shown."""
    if not finding.evidence_ref or not finding.last_run_id:
        return ""
    try:
        raw = _evidence_store().read(str(finding.last_run_id), finding.evidence_ref)
        payload = json.loads(raw)
    except (EvidenceError, ValueError):
        return ""
    return json.dumps(
        {
            "request": payload.get("request"),
            "response": payload.get("response"),
            "detector_verdict": payload.get("detector_verdict"),
        },
        default=str,
    )[:MAX_EVIDENCE_CHARS]


class AnalyzeFindingParams(BaseModel):
    finding_id: uuid.UUID


class AnalyzeFindingResult(BaseModel):
    explanation: str
    model: str
    provider: str


async def _analyze_finding(ctx: AgentContext, params: AnalyzeFindingParams) -> AnalyzeFindingResult:
    finding = (
        await ctx.db.execute(
            select(Finding).where(
                Finding.id == params.finding_id, Finding.organization_id == ctx.organization_id
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise ToolNotFoundError(f"finding {params.finding_id} not found")

    if ctx.provider is None:
        raise ToolExecutionError("no AI provider is configured for this organization")

    view = FindingView(
        probe_id=finding.probe_id,
        title=finding.title,
        endpoint=finding.surface,
        severity=finding.severity.value,
        description=finding.description,
        evidence=_evidence_text(finding),
        remediation=finding.remediation,
    )
    # ASSIST is EXPLAIN_FINDING's own minimum (see autonomy.py); the agent's
    # tool-level role check above is the real gate for this call, not a
    # second autonomy configuration to keep in sync with it.
    service = AIService(ctx.provider, mode=AutonomyMode.ASSIST)
    try:
        draft = await service.explain_finding(view)
    except (ProviderNotConfiguredError, ProviderError) as exc:
        raise ToolExecutionError(f"AI provider call failed: {exc}") from exc

    return AnalyzeFindingResult(
        explanation=draft.content, model=draft.model, provider=draft.provider
    )


ANALYZE_FINDING = Tool(
    name="analyze_finding",
    description=(
        "Get an AI-drafted explanation of one finding: what was observed, what can be "
        "inferred, and what remains unknown."
    ),
    input_model=AnalyzeFindingParams,
    output_model=AnalyzeFindingResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_analyze_finding,
    timeout_seconds=30.0,
    rate_limit_rule="agent_tool_call",
)
