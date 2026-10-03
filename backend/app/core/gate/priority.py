"""P0-P4 engineering priority, derived from severity (docs/BUILD_SPEC.md §23).

`Severity` (§11.1) is the risk model's own vocabulary — CRITICAL down to
INFORMATIONAL — and `GateConfig.fail_on` already acts on it directly. P0-P4
is a second, deliberately separate vocabulary: the one an engineering team's
own ticket tracker and on-call rotation already speak, where "P0" means
drop everything and "P4" means backlog. Reusing severity's own words for
that would blur two different audiences' language into one; publishing the
mapping here instead lets a report say "CRITICAL (P0)" and have both
readers recognise their own term.

The mapping is a straight one-to-one ladder, most severe first, matching
`risk.model.SEVERITY_BANDS`'s own ordering — there is no scoring here, only
a published relabelling, so it carries no model version of its own.
"""

from enum import StrEnum

from app.core.probes.models import Severity


class Priority(StrEnum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


# Published, so a reader can check the relabelling rather than trust the
# ticket's own priority field. Ordered to match `Severity`'s own declaration
# order (INFORMATIONAL first) purely for readability; `priority_for` does not
# depend on the order.
PRIORITY_FOR_SEVERITY: dict[Severity, Priority] = {
    Severity.INFORMATIONAL: Priority.P4,
    Severity.LOW: Priority.P3,
    Severity.MEDIUM: Priority.P2,
    Severity.HIGH: Priority.P1,
    Severity.CRITICAL: Priority.P0,
}

# Most urgent first, for sorting and for the "at or above" comparisons a
# ticket-tracker integration would need (e.g. "open every P0/P1 as a ticket").
PRIORITY_ORDER: tuple[Priority, ...] = (
    Priority.P0,
    Priority.P1,
    Priority.P2,
    Priority.P3,
    Priority.P4,
)


def priority_for(severity: Severity) -> Priority:
    return PRIORITY_FOR_SEVERITY[severity]
