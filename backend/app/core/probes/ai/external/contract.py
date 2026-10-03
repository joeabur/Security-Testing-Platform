"""The interface an external attack engine (garak, PyRIT) would implement.

This is deliberately **not** a wrapper around either tool — `docs/BUILD_SPEC.md`
§28 says plainly: "Do not build a thin wrapper around garak or promptfoo and
call it a platform." It is the narrower thing the competitive brief asked for
when wrapping was judged unsafe for this pass: "a clean adapter architecture,"
documented, with no engine actually wired in yet
(`docs/competitive-gap-analysis.md`).

## Why this is not shaped like `AiProbe`

`app.core.probes.ai.contract.AiProbe` splits a probe into `plan()` (decide
every prompt up front) and `detect()` (judge one response in isolation). That
split is what makes the trials/baseline/confidence-interval machinery
possible for a *native* probe — but it assumes the probe never needs to see
a response before deciding its next prompt. garak's own probes often don't
either, but PyRIT's orchestrators are explicitly adaptive and multi-turn:
the whole point of a "crescendo" or "TAP" orchestrator is that turn N+1
depends on how the target responded to turn N. Forcing that into
`plan`/`detect` would mean lying about what either tool actually does.

So this protocol instead hands an external engine the same thing a native
probe's driver already uses to reach the target — `Ask`, the scope-gated
callable — and lets the engine run its own loop on top of it, however many
turns that takes. What native probes get from the split (comparable
trial/confidence-interval statistics across every probe) is a cost this
protocol accepts: an external engine's result is a `ScanResult` it builds
itself, not a `ProbeOutcome` this platform's measurement code produced.

## The one property this protocol enforces structurally

No method here is given a transport, a URL, a hostname, or a credential —
only `ask`. An engine that needs to resolve a hostname or open a socket to
do its job cannot be wired in through this protocol; nothing here hands
one out. That is the same reasoning the plugin system's own "a plugin
cannot bypass the scope engine" guarantee rests on
(`docs/plugin-development.md`, proved in `tests/test_plugins.py`) and the
DAST engine's egress gateway (`docs/egress-security.md`) — the thing that
must never exist is a code path with its own idea of what is in scope.
`tests/test_external_ai_engines.py` proves it the same way: a fake engine
driven only through `ask` is refused by the scope engine exactly like a
native probe would be, because `ask` is the only door, and it is already
locked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.core.probes.ai.contract import AiProbeTarget, Ask
from app.core.probes.models import ScanResult


@dataclass(frozen=True)
class ExternalEngineMeta:
    """Identifies the engine for a report and an audit trail — not the
    engine's own internal probe/detector list, which this platform does
    not know about and does not need to."""

    id: str
    name: str
    #: This adapter's own version, not the wrapped tool's — the tool's
    #: version is the engine's own business to report inside its findings
    #: if it chooses to.
    version: str
    #: Where the wrapped tool comes from, e.g. its repository URL, so a
    #: reader of a finding can go verify what actually produced it.
    source: str
    description: str


@runtime_checkable
class ExternalAttackEngine(Protocol):
    """An external attack engine, driven entirely through this platform's
    own `Ask`. See the module docstring for why this is the boundary and
    why it is shaped differently from `AiProbe`."""

    meta: ExternalEngineMeta

    async def run(self, target: AiProbeTarget, ask: Ask, canary: str) -> list[ScanResult]: ...
