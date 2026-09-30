"""Executes a `Plan`'s tool calls in order, against one `Investigation`.

Per step: authorize the caller's role, then — independently — require
approval if the tool is SENSITIVE and has not already been approved
(`permissions.py`). The first unapproved SENSITIVE step **pauses** the
investigation (saved to `session_store.py`, resumed later once approved);
any other failure **stops** it. Neither case runs the steps after it — a
plan is not a best-effort batch, it is an ordered sequence, and skipping a
step silently would let a later step run against state an earlier one was
supposed to establish.

The optional final summary is a plain `provider.generate()` call over the
step outcomes, quoted as evidence exactly like every other model-facing
text in this codebase: a tool's result can contain content read from a
target (a finding's description, a report's body), and that is exactly the
kind of text `quote_evidence()` exists to fence. There is no exposed
chain-of-thought here — only the outcomes a human could also read from the
audit trail, and the model's own final answer.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel

from app.core.agent.context import AgentContext
from app.core.agent.investigation import Investigation, PendingApproval
from app.core.agent.permissions import ApprovalRequiredError, ToolPermissionError, authorize_tool
from app.core.agent.planner import Plan
from app.core.agent.tool_config import ToolConfig, effective_minimum_role, is_tool_enabled
from app.core.agent.tools.contract import Tool, ToolExecutionError, ToolNotFoundError
from app.core.assistant.prompts import PromptTemplate, quote_evidence
from app.core.assistant.provider import AIProvider

MAX_OUTCOME_CHARS = 2000

SUMMARY_PROMPT = PromptTemplate(
    id="agent.summarize_investigation",
    version="1.0.0",
    system=(
        "You are summarising what an authorized security-assessment agent just did, "
        "for the person who asked it to. Be concise and factual. State only what the "
        "outcomes below show; do not invent a result a step does not report."
    ),
    template=(
        "The investigation ran these steps, in order:\n\n{outcomes}\n\n"
        "Write a short summary of what was found and done."
    ),
)


class StepStatus(StrEnum):
    OK = "ok"
    TOOL_NOT_FOUND = "tool_not_found"
    PERMISSION_DENIED = "permission_denied"
    APPROVAL_REQUIRED = "approval_required"
    EXECUTION_ERROR = "execution_error"


@dataclass(frozen=True)
class StepOutcome:
    tool_name: str
    status: StepStatus
    result: BaseModel | None = None
    error: str | None = None
    duration_ms: int = 0


@dataclass
class ExecutionResult:
    investigation: Investigation
    outcomes: list[StepOutcome]
    summary: str | None = None


def _outcome_text(outcome: StepOutcome) -> str:
    if outcome.result is not None:
        body = json.dumps(outcome.result.model_dump(mode="json"), default=str)[:MAX_OUTCOME_CHARS]
        return f"- {outcome.tool_name} ({outcome.status.value}): {body}"
    if outcome.error:
        return f"- {outcome.tool_name} ({outcome.status.value}): {outcome.error}"
    return f"- {outcome.tool_name} ({outcome.status.value})"


async def _summarize(provider: AIProvider, outcomes: list[StepOutcome]) -> str:
    outcomes_text = quote_evidence("\n".join(_outcome_text(outcome) for outcome in outcomes))
    prompt = SUMMARY_PROMPT.render(outcomes=outcomes_text)
    completion = await provider.generate(prompt, system=SUMMARY_PROMPT.system)
    return completion.text


async def run_plan(
    ctx: AgentContext,
    plan: Plan,
    tools: Mapping[str, Tool],
    investigation: Investigation,
    *,
    approved_tool_names: frozenset[str] = frozenset(),
    tool_config: ToolConfig | None = None,
    summarize: bool = False,
) -> ExecutionResult:
    """Run `plan.steps[investigation.plan_step_index:]` against `tools`.

    Resuming an approved investigation is the same call with a later
    `plan_step_index` already set on `investigation` (by whoever loaded it
    from `session_store.py`) and that tool's name in `approved_tool_names`
    — there is no separate "resume" function, only the same loop starting
    partway through.

    `tool_config` is re-read by the caller for every call into this
    function, including a resumed one — never cached across the pause, the
    same "never trust an earlier check" reasoning
    `exploitation_service.py`'s fire task re-validates its own allowlists
    for rather than trusting the enqueue-time check alone. A tool disabled,
    or given a raised minimum role, after a plan was built but before a
    step runs is refused here, not silently allowed through on a stale
    decision.
    """
    config: ToolConfig = tool_config or {}
    outcomes: list[StepOutcome] = []

    for index in range(investigation.plan_step_index, len(plan.steps)):
        step = plan.steps[index]
        tool = tools.get(step.tool_name)
        if tool is None:
            outcomes.append(StepOutcome(step.tool_name, StepStatus.TOOL_NOT_FOUND))
            investigation.fail()
            return ExecutionResult(investigation, outcomes)

        try:
            authorize_tool(
                ctx.effective_role,
                tool,
                approved=tool.name in approved_tool_names,
                minimum_role=effective_minimum_role(tool, config),
                enabled=is_tool_enabled(tool, config),
            )
        except ToolPermissionError as exc:
            outcomes.append(StepOutcome(tool.name, StepStatus.PERMISSION_DENIED, error=str(exc)))
            investigation.fail()
            return ExecutionResult(investigation, outcomes)
        except ApprovalRequiredError:
            investigation.plan_step_index = index
            investigation.await_approval(
                PendingApproval(
                    tool_name=tool.name, risk_level=tool.risk_level, description=tool.description
                )
            )
            outcomes.append(StepOutcome(tool.name, StepStatus.APPROVAL_REQUIRED))
            return ExecutionResult(investigation, outcomes)

        started = time.monotonic()
        try:
            result = await tool.invoke(ctx, step.params)
        except (ToolNotFoundError, ToolExecutionError) as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            outcomes.append(
                StepOutcome(
                    tool.name, StepStatus.EXECUTION_ERROR, error=str(exc), duration_ms=duration_ms
                )
            )
            investigation.fail()
            return ExecutionResult(investigation, outcomes)
        duration_ms = int((time.monotonic() - started) * 1000)

        outcomes.append(
            StepOutcome(tool.name, StepStatus.OK, result=result, duration_ms=duration_ms)
        )
        investigation.plan_step_index = index + 1

    investigation.complete()
    summary = (
        await _summarize(ctx.provider, outcomes)
        if summarize and ctx.provider is not None and outcomes
        else None
    )
    return ExecutionResult(investigation, outcomes, summary=summary)
