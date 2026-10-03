"""The AI security engine's probe set (docs/BUILD_SPEC.md §9, §26 Phase 6).

Two kinds of probe live here, and the difference is honest rather than
incidental:

* **Trial probes** have an adversarial component and a control, so they are
  measured over N trials and reported with an attack success rate
  (`run_ai_probe`).
* **Analysis probes** measure or inspect something with no adversarial
  component — cost scaling, a declared tool surface. An attack success rate
  over those would be a number with nothing behind it, so they do not have
  one.
"""

from app.core.probes.ai.agency import ExcessiveAgencyProbe
from app.core.probes.ai.consumption import ConsumptionProbe
from app.core.probes.ai.contract import AiProbe
from app.core.probes.ai.direct_injection import direct_injection_probes
from app.core.probes.ai.disclosure import HiddenContextProbe, SensitiveDisclosureProbe
from app.core.probes.ai.multiturn.contract import MultiTurnProbe
from app.core.probes.ai.multiturn.instruction_chaining import multi_turn_probes as _multi_turn
from app.core.probes.ai.output_handling import OutputHandlingProbe


def trial_probes() -> list[AiProbe]:
    """Probes measured over trials against a control."""
    probes: list[AiProbe] = list(direct_injection_probes())
    probes.append(SensitiveDisclosureProbe())
    probes.append(HiddenContextProbe())
    probes.append(OutputHandlingProbe())
    return probes


def multi_turn_probes() -> list[MultiTurnProbe]:
    """Probes measured over repeated whole conversations against a control
    conversation, run through `multiturn.runner.run_multi_turn_probe` rather
    than `driver.run_ai_probe` (`docs/ai-security-testing.md`)."""
    return list(_multi_turn())


def consumption_probe() -> ConsumptionProbe:
    return ConsumptionProbe()


def agency_probe() -> ExcessiveAgencyProbe:
    return ExcessiveAgencyProbe()


def all_probe_ids() -> list[str]:
    return sorted(
        [probe.meta.id for probe in trial_probes()]
        + [probe.meta.id for probe in multi_turn_probes()]
        + [consumption_probe().meta.id, agency_probe().meta.id]
    )
