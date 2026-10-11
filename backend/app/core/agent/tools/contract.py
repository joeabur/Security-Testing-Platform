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

from app.core.config import get_settings
from app.core.ratelimit.dependency import limiter
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


class ToolExecutionError(Exception):
    """The tool refused to act — the tool-call analogue of a 409.

    For a domain-level refusal a handler expects and can explain (a disabled
    workflow, an invalid gate, authorization not currently valid): the same
    shape `HTTPException(409, ...)` gives an HTTP caller, but a plain
    exception, because a tool handler has no HTTP response to raise into.
    """


class ToolRateLimitedError(ToolExecutionError):
    """This identity has exceeded `Tool.rate_limit_rule`'s own budget — the
    tool-call analogue of a 429, not a 409: the caller did nothing wrong
    about *this* call, the window just has not rolled over yet.

    A subclass of `ToolExecutionError` rather than a sibling, deliberately:
    `app/core/agent/runtime.py::run_plan` already catches
    `(ToolNotFoundError, ToolExecutionError)` as one case and stops the
    investigation — exactly the right outcome for a runaway planning loop
    that has hit its own budget, with no second exception type for that
    caller to learn about. An HTTP caller (`app/api/v1/routers/agent.py`)
    catches this one specifically, ahead of the general `ToolExecutionError`
    clause, to answer 429 with `Retry-After` rather than 409.
    """

    def __init__(self, rule_name: str, retry_after_seconds: int) -> None:
        self.rule_name = rule_name
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"rate limit exceeded ({rule_name}); retry after {retry_after_seconds}s"
        )


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
    #: A rate-limit policy name registered in `app.core.ratelimit.policy.POLICY`
    #: — `invoke()` below consumes it directly, keyed on `ctx.user_id`.
    rate_limit_rule: str | None = None

    async def invoke(self, ctx: AgentContext, raw_params: dict[str, Any]) -> BaseModel:
        """Validate `raw_params` against this tool's own input model, apply
        this tool's own rate-limit budget, call its handler, and check the
        result's shape — the one place every tool call passes through
        (`run_plan` and the direct `.../tools/{name}/call` route both go
        through here), so a handler never receives anything but a
        validated, typed object, never returns anything but its declared
        result type, and a budget declared on a `Tool` can never be
        reachable by a path that forgot to consume it.

        Keyed on `ctx.user_id`, not a client IP: `AgentContext` has no HTTP
        request to derive one from on purpose (`context.py`'s own
        docstring — this is a pure domain object, reused by `run_plan`,
        which has no request either), and every rule registered for
        `rate_limit_rule` is an identity-dimension rule for exactly that
        reason (`app/core/ratelimit/policy.py`). `limiter()` is reused
        rather than `enforce()` (`app/core/ratelimit/dependency.py`)
        because the latter requires a `Request` to derive a client IP this
        call has no use for.
        """
        params = self.input_model.model_validate(raw_params)
        if self.rate_limit_rule is not None and get_settings().rate_limit_enabled:
            decision = await limiter().check(
                self.rate_limit_rule, client_ip="", identity=str(ctx.user_id)
            )
            if not decision.allowed:
                raise ToolRateLimitedError(decision.rule_name, decision.retry_after_seconds)
        result = await self.handler(ctx, params)
        if not isinstance(result, self.output_model):
            raise TypeError(
                f"tool {self.name!r} handler returned {type(result).__name__}, "
                f"expected {self.output_model.__name__}"
            )
        return result
