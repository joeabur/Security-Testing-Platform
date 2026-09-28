"""The agent's per-request context.

Built once, from the same role-ceiling logic `require_membership` already
enforces at the HTTP boundary (`app.auth.dependencies.effective_role`), and
discarded when the request returns. It is never persisted, cached, or reused
across requests — this is the concrete object that keeps "the AI processes
data, it does not store it" true for every tool call made through it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organization import Role


@dataclass
class AgentContext:
    organization_id: uuid.UUID
    user_id: uuid.UUID
    effective_role: Role
    db: AsyncSession
    request_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
