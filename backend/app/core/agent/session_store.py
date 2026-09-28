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

**What is stored, and why it is safe to lose.** Only `Investigation.id`,
`organization_id`, `user_id`, `status`, `plan_step_index`, and — when
paused — the pending tool's name, risk level, and fixed description (see
`investigation.py`). Never the natural-language request, a tool's raw
arguments, or any tool's output: those live only in the process actually
running the investigation and are re-derived (from the plan and the
platform's own tables) when an approval resumes it, rather than duplicated
into this cache. Losing this key loses only "which step was next," never
anything the zero-persistence requirement protects.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime

import redis.asyncio as redis_async

from app.core.agent.investigation import Investigation, InvestigationStatus, PendingApproval
from app.core.agent.tools.contract import RiskLevel
from app.core.config import get_settings

_KEY_PREFIX = "aegis:agent:investigation:"
# 30 minutes: long enough for a human to see an approval request and act on
# it, short enough that a forgotten one does not sit in Redis indefinitely.
TTL_SECONDS = 30 * 60


class SessionStoreUnavailable(Exception):
    """Redis could not be reached. Callers must treat this as "not
    approved," never as a pass-through — see the module docstring."""


def _key(investigation_id: uuid.UUID) -> str:
    return f"{_KEY_PREFIX}{investigation_id}"


def _to_json(investigation: Investigation) -> str:
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
        }
    )


def _from_json(raw: str) -> Investigation:
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
    return Investigation(
        id=uuid.UUID(data["id"]),
        organization_id=uuid.UUID(data["organization_id"]),
        user_id=uuid.UUID(data["user_id"]),
        status=InvestigationStatus(data["status"]),
        plan_step_index=data["plan_step_index"],
        pending_approval=pending,
        created_at=datetime.fromisoformat(data["created_at"]),
    )


class InvestigationSessionStore:
    def __init__(self, url: str | None = None) -> None:
        self._url = url or get_settings().redis_url
        self._client: redis_async.Redis | None = None

    def _connect(self) -> redis_async.Redis:
        if self._client is None:
            self._client = redis_async.Redis.from_url(self._url, decode_responses=True)
        return self._client

    async def save(self, investigation: Investigation) -> None:
        try:
            # `ex=` on every write, never a bare `SET` — a session that
            # outlives its TTL by a code change here would silently turn
            # this store persistent, exactly what the zero-persistence
            # requirement forbids.
            await self._connect().set(
                _key(investigation.id), _to_json(investigation), ex=TTL_SECONDS
            )
        except (redis_async.RedisError, OSError) as exc:
            raise SessionStoreUnavailable(str(exc)) from exc

    async def load(
        self, investigation_id: uuid.UUID, *, organization_id: uuid.UUID
    ) -> Investigation | None:
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
        investigation = _from_json(raw if isinstance(raw, str) else raw.decode("utf-8"))
        if investigation.organization_id != organization_id:
            return None
        return investigation

    async def delete(self, investigation_id: uuid.UUID) -> None:
        try:
            await self._connect().delete(_key(investigation_id))
        except (redis_async.RedisError, OSError) as exc:
            raise SessionStoreUnavailable(str(exc)) from exc
