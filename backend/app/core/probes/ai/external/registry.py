"""Where an external attack engine (garak, PyRIT) would register itself.

Empty today, on purpose. `docs/competitive-gap-analysis.md`'s "What this
does not do" is explicit: wiring an actual adapter — one that shells out
to garak or drives PyRIT's own orchestrators — was judged a separate,
larger increment than closing the DAST egress gap this same pass added,
and shipping it thin (untested against the real tool, no real findings
verified end to end) would be exactly the "fake implementation" this
codebase's own rules reject. This module exists so the registration point
is real and typed before an adapter is, not after.

Adding one later means: implement `ExternalAttackEngine` in a new module
under this package, append the instance to `_ENGINES` below, and extend
`tests/test_external_ai_engines.py` with that engine's own tests — the
boundary this module's docstring and `contract.py` describe does not
change.
"""

from __future__ import annotations

from app.core.probes.ai.external.contract import ExternalAttackEngine

_ENGINES: tuple[ExternalAttackEngine, ...] = ()


def external_engines() -> tuple[ExternalAttackEngine, ...]:
    """Every registered external attack engine. Empty until one is wired in."""
    return _ENGINES
