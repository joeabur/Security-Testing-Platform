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
from app.core.probes.ai.cross_identity.contract import CrossIdentityProbe
from app.core.probes.ai.cross_identity.data_leakage import CrossUserDataLeakageProbe
from app.core.probes.ai.direct_injection import direct_injection_probes
from app.core.probes.ai.disclosure import HiddenContextProbe, SensitiveDisclosureProbe
from app.core.probes.ai.multiturn.agent_goal import agent_multi_turn_probes
from app.core.probes.ai.multiturn.contract import MultiTurnProbe
from app.core.probes.ai.multiturn.instruction_chaining import multi_turn_probes as _multi_turn
from app.core.probes.ai.output_handling import OutputHandlingProbe
from app.core.probes.ai.rag_injection import rag_injection_probes


def trial_probes() -> list[AiProbe]:
    """Probes measured over trials against a control."""
    probes: list[AiProbe] = list(direct_injection_probes())
    probes.append(SensitiveDisclosureProbe())
    probes.append(HiddenContextProbe())
    probes.append(OutputHandlingProbe())
    probes.extend(rag_injection_probes())
    return probes


def multi_turn_probes() -> list[MultiTurnProbe]:
    """Probes measured over repeated whole conversations against a control
    conversation, run through `multiturn.runner.run_multi_turn_probe` rather
    than `driver.run_ai_probe` (`docs/ai-security-testing.md`)."""
    return [*_multi_turn(), *agent_multi_turn_probes()]


def cross_identity_probes() -> list[CrossIdentityProbe]:
    """Probes that drive a target through two or more operator-declared
    synthetic identities at once, run through
    `cross_identity.runner.run_cross_identity_probe` rather than
    `driver.run_ai_probe` or `multiturn.runner.run_multi_turn_probe`."""
    return [CrossUserDataLeakageProbe()]


def consumption_probe() -> ConsumptionProbe:
    return ConsumptionProbe()


def agency_probe() -> ExcessiveAgencyProbe:
    return ExcessiveAgencyProbe()


def all_probe_ids() -> list[str]:
    return sorted(
        [probe.meta.id for probe in trial_probes()]
        + [probe.meta.id for probe in multi_turn_probes()]
        + [probe.meta.id for probe in cross_identity_probes()]
        + [consumption_probe().meta.id, agency_probe().meta.id]
    )
