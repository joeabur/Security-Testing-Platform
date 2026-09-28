"""Redis-backed storage for a paused investigation's approval state.

The sixth Redis-backed store in this codebase (after the Celery broker, the
run kill switch, the rate limiter, JWT revocation, and the AI spend cap),
following the same "state a fresh read, an explicit TTL, a stated fail
direction" discipline as the other five.

**Fails CLOSED**, unlike the rate limiter (`app/core/ratelimit/`) and unlike
`KillSwitch` (which has no remote state to lose in the first place). An
investigation with a pending SENSITIVE tool call is, by construction,
waiting to do something the platform does not do without a human saying so.
If Redis cannot be reached, the honest answer is "this cannot currently be
approved," never "proceed as if it already was" — see
`app/core/revocation/` for the same reasoning applied to token revocation.

**What is stored, and why it is safe to lose.** `Investigation.id`,
`organization_id`, `user_id`, `status`, `plan_step_index`, the pending
tool's name/risk level/fixed description when paused (see
`investigation.py`), and the plan's own steps — each step's tool name and
the structured arguments the planner chose for it. That last part is the
one exception to "nothing but scalar status fields": resuming a paused
plan has to know what the remaining steps *are*, and a tool call's
arguments (a target id, a run id, a workflow id) are platform-chosen
structured parameters, not a prompt, a model's response, or a tool's
output — the things the zero-persistence requirement actually protects.
Never the natural-language request that produced the plan and never any
step's *result*: those still live only in the process that ran them, and
this cache is the only place a paused plan's steps exist between the
approval request and the human's answer to it. Losing this key loses the
whole paused plan, which is why the approval flow treats a lost key as "no
longer resumable," not as data recoverable some other way.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime

import redis.asyncio as redis_async

from app.core.agent.investigation import Investigation, InvestigationStatus, PendingApproval
from app.core.agent.planner import Plan, PlanStep
from app.core.agent.tools.contract import RiskLevel
from app.core.config import get_settings

_KEY_PREFIX = "aegis:agent:investigation:"
# 30 minutes: long enough for a human to see an approval request and act on
# it, short enough that a forgotten one does not sit in Redis indefinitely.
TTL_SECONDS = 30 * 60


class SessionStoreUnavailable(Exception):
    """Redis could not be reached. Callers must treat this as "not
    approved," never as a pass-through — see the module docstring."""


@dataclass(frozen=True)
class PausedInvestigation:
    """What `load` returns: the investigation's state and the plan it
    paused partway through — both needed to resume it, neither meaningful
    without the other."""

    investigation: Investigation
    plan: Plan


def _key(investigation_id: uuid.UUID) -> str:
    return f"{_KEY_PREFIX}{investigation_id}"


def _to_json(investigation: Investigation, plan: Plan) -> str:
    pending = investigation.pending_approval
    return json.dumps(
        {
            "id": str(investigation.id),
            "organization_id": str(investigation.organization_id),
            "user_id": str(investigation.user_id),
            "status": investigation.status.value,
            "plan_step_index": investigation.plan_step_index,
            "pending_approval": (
                None
                if pending is None
                else {
                    "tool_name": pending.tool_name,
                    "risk_level": pending.risk_level.value,
                    "description": pending.description,
                }
            ),
            "created_at": investigation.created_at.isoformat(),
            "plan_steps": [
                {"tool_name": step.tool_name, "params": step.params} for step in plan.steps
            ],
        }
    )


def _from_json(raw: str) -> PausedInvestigation:
    data = json.loads(raw)
    pending_data = data["pending_approval"]
    pending = (
        None
        if pending_data is None
        else PendingApproval(
            tool_name=pending_data["tool_name"],
            risk_level=RiskLevel(pending_data["risk_level"]),
            description=pending_data["description"],
        )
    )
    investigation = Investigation(
        id=uuid.UUID(data["id"]),
        organization_id=uuid.UUID(data["organization_id"]),
        user_id=uuid.UUID(data["user_id"]),
        status=InvestigationStatus(data["status"]),
        plan_step_index=data["plan_step_index"],
        pending_approval=pending,
        created_at=datetime.fromisoformat(data["created_at"]),
    )
    plan = Plan(
        steps=tuple(
            PlanStep(tool_name=step["tool_name"], params=step["params"])
            for step in data["plan_steps"]
        )
    )
    return PausedInvestigation(investigation=investigation, plan=plan)


class InvestigationSessionStore:
    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
        return self._client

    async def save(self, investigation: Investigation, plan: Plan) -> None:
        try:
            # `ex=` on every write, never a bare `SET` — a session that
            # outlives its TTL by a code change here would silently turn
            # this store persistent, exactly what the zero-persistence
            # requirement forbids.
            await self._connect().set(
                _key(investigation.id), _to_json(investigation, plan), ex=TTL_SECONDS
            )
        except (redis_async.RedisError, OSError) as exc:
            raise SessionStoreUnavailable(str(exc)) from exc

    async def load(
        self, investigation_id: uuid.UUID, *, organization_id: uuid.UUID
    ) -> PausedInvestigation | None:
        """`None` means "no such investigation, or it is not this
        organization's" — the tenant-isolation check happens here, not left
        to the caller, so a wrong-organization id can never resume someone
        else's paused action."""
        try:
            raw = await self._connect().get(_key(investigation_id))
        except (redis_async.RedisError, OSError) as exc:
            raise SessionStoreUnavailable(str(exc)) from exc
        if raw is None:
            return None
        # `decode_responses=True` makes this a `str` at runtime; the client
        # is typed generically over `str | bytes` regardless.
        paused = _from_json(raw if isinstance(raw, str) else raw.decode("utf-8"))
        if paused.investigation.organization_id != organization_id:
            return None
        return paused

    async def delete(self, investigation_id: uuid.UUID) -> None:
        try:
            await self._connect().delete(_key(investigation_id))
        except (redis_async.RedisError, OSError) as exc:
            raise SessionStoreUnavailable(str(exc)) from exc
