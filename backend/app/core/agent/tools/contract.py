"""The contract every native-agent tool implements.

A `Tool` wraps one existing platform read (or, in a later phase, action)
behind a typed input/output shape, a risk tier, a minimum role, and a
timeout — the AI never gets unrestricted database, shell, or HTTP access,
only what a registered tool exposes. Mirrors the platform's other closed-
registry idioms (`appsec_engines()`, `ActionKind`): a tool exists because
it is listed in `registry.py`, never because something was importable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from app.models.organization import Role

if TYPE_CHECKING:
    from app.core.agent.context import AgentContext


class RiskLevel(StrEnum):
    """Collapses the platform's own three-tier action classification —
    read-only/search/view/analyze; reports/passive-discovery/approved-
    automation; active-scanning/validation/pentest/infra-changing — into
    one closed set, matching this codebase's preference for small enums
    over open-ended classification.
    """

    READ_ONLY = "read_only"
    STANDARD = "standard"
    SENSITIVE = "sensitive"


class ToolNotFoundError(Exception):
    """The tool's target resource does not exist (or is not in this
    organization) — the tool-call analogue of a 404."""


# Deliberately loose (`Callable[..., Awaitable[BaseModel]]` rather than a
# signature parameterised on each tool's own Params/Result types): every
# concrete handler's real signature is `(AgentContext, SpecificParams) ->
# Awaitable[SpecificResult]`, and `Tool.invoke` below is the one place that
# validates a raw argument dict into that specific type before calling it,
# so the loose type here costs nothing at the only call site that matters.
ToolHandler = Callable[..., Awaitable[BaseModel]]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    risk_level: RiskLevel
    minimum_role: Role
    handler: ToolHandler
    timeout_seconds: float = 15.0
    # A rate-limit policy name registered in `app.core.ratelimit.policy.POLICY`.
    # None for now; filled in alongside that policy entry in a later phase.
    rate_limit_rule: str | None = None

    async def invoke(self, ctx: AgentContext, raw_params: dict[str, Any]) -> BaseModel:
        """Validate `raw_params` against this tool's own input model, call
        its handler, and check the result's shape — the one place every
        tool call passes through, so a handler never receives anything but
        a validated, typed object and never returns anything but its
        declared result type.
        """
        params = self.input_model.model_validate(raw_params)
        result = await self.handler(ctx, params)
        if not isinstance(result, self.output_model):
            raise TypeError(
                f"tool {self.name!r} handler returned {type(result).__name__}, "
                f"expected {self.output_model.__name__}"
            )
        return result
