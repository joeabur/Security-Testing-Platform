"""An investigation's in-memory shape — a temporary execution, not a record.

Per the agent's zero-persistence requirement, an `Investigation` exists only
for the duration of a request (or, when a SENSITIVE tool call needs a human
approval round trip, for as long as `session_store.py`'s short-lived cache
holds it — never longer, and never in a database table). Its natural-
language request text and any tool output it has gathered so far live only
as attributes of this dataclass in one process's memory; only the minimal
fields below are ever serialized, by `session_store.py`, and only while an
approval is pending.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from app.core.agent.tools.contract import RiskLevel


class InvestigationStatus(StrEnum):
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(frozen=True)
class PendingApproval:
    """What a human approving a paused investigation needs to see.

    Deliberately just a name, a risk tier, and the tool's own fixed
    description — never the specific arguments the plan would call it with,
    which could contain content read from a target. An approver is
    confirming "yes, run this *kind* of action," not reviewing a payload.
    """

    tool_name: str
    risk_level: RiskLevel
    description: str


@dataclass
class Investigation:
    """One investigation's state. Only `id`, `organization_id`, `user_id`,
    `status`, `plan_step_index`, and `pending_approval` ever leave this
    process (see `session_store.py`); nothing else on this dataclass is ever
    serialized.
    """

    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID
    status: InvestigationStatus = InvestigationStatus.RUNNING
    plan_step_index: int = 0
    pending_approval: PendingApproval | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def start(cls, *, organization_id: uuid.UUID, user_id: uuid.UUID) -> Investigation:
        return cls(id=uuid.uuid4(), organization_id=organization_id, user_id=user_id)

    def await_approval(self, pending: PendingApproval) -> None:
        self.status = InvestigationStatus.AWAITING_APPROVAL
        self.pending_approval = pending

    def resume(self) -> None:
        self.status = InvestigationStatus.RUNNING
        self.pending_approval = None
        self.plan_step_index += 1

    def complete(self) -> None:
        self.status = InvestigationStatus.COMPLETED
        self.pending_approval = None

    def cancel(self) -> None:
        self.status = InvestigationStatus.CANCELLED
        self.pending_approval = None

    def fail(self) -> None:
        self.status = InvestigationStatus.FAILED
        self.pending_approval = None
