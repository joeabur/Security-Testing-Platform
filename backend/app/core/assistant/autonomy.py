"""How much the AI layer may do on its own
(Implementation Specification §11; Addendum v2.1 §6.3).

The two source documents appear to disagree — one forbids the assistant
executing anything, the other lists `EXECUTE` among its modes — and
`docs/BUILD_SPEC.md` §4.5 row 7 resolves it by asking *execute what*:

* Producing an artifact — a draft, a summary, a report section — is
  something a mode may permit outright.
* Anything that consumes budget, sends a request to a target, grants or
  extends an authorization, or writes a finding's real fields is **never**
  permitted by any mode. Those are not "high autonomy" actions; they are
  actions the AI layer does not have.

That is why `Capability` is a closed set and `TARGET_TOUCHING` is checked
independently of the mode. A mode cannot grant what is not in the table.
"""

from enum import IntEnum, StrEnum


class AutonomyMode(IntEnum):
    """Ordered so that "at least this much autonomy" is a comparison."""

    OFF = 0
    ASSIST = 1
    RECOMMEND = 2
    APPROVAL_REQUIRED = 3
    EXECUTE = 4

    @classmethod
    def parse(cls, value: str) -> "AutonomyMode":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown autonomy mode {value!r}") from exc


# The Implementation Specification says to default to ASSIST or RECOMMEND.
DEFAULT_MODE = AutonomyMode.ASSIST


class Capability(StrEnum):
    """Everything the AI layer can be asked to do. A closed set: a capability
    that is not listed here cannot be requested, so a new power requires a
    deliberate edit to this file and a review of the table below."""

    EXPLAIN_FINDING = "explain_finding"
    DRAFT_REMEDIATION = "draft_remediation"
    DRAFT_SEVERITY_RATIONALE = "draft_severity_rationale"
    SUMMARISE_RUN = "summarise_run"
    CORRELATE_FINDINGS = "correlate_findings"
    PRIORITISE_FINDINGS = "prioritise_findings"
    PROPOSE_SCAN = "propose_scan"
    ANSWER_EVIDENCE_QUESTION = "answer_evidence_question"


# The minimum mode at which each capability is permitted. Every one produces
# an artifact a human then reads; none of them acts on a target.
_MINIMUM_MODE = {
    Capability.EXPLAIN_FINDING: AutonomyMode.ASSIST,
    Capability.DRAFT_REMEDIATION: AutonomyMode.ASSIST,
    Capability.DRAFT_SEVERITY_RATIONALE: AutonomyMode.ASSIST,
    Capability.SUMMARISE_RUN: AutonomyMode.ASSIST,
    Capability.ANSWER_EVIDENCE_QUESTION: AutonomyMode.ASSIST,
    Capability.CORRELATE_FINDINGS: AutonomyMode.RECOMMEND,
    Capability.PRIORITISE_FINDINGS: AutonomyMode.RECOMMEND,
    # Composing a command is a drafting act. *Running* it is the operator's,
    # at every mode — see `TARGET_TOUCHING`.
    Capability.PROPOSE_SCAN: AutonomyMode.RECOMMEND,
}

# Actions no mode permits, listed so the rule is readable rather than
# implied by the absence of an entry above. Checked separately from the mode
# precisely so that raising the mode can never grant one of them.
TARGET_TOUCHING = frozenset(
    {
        "execute_scan",
        "grant_authorization",
        "extend_authorization",
        "modify_scope",
        "change_finding_status",
        "change_finding_severity",
        "send_request_to_target",
    }
)


class AutonomyError(PermissionError):
    """The requested action is not permitted at the configured mode."""


def permits(mode: AutonomyMode, capability: Capability) -> bool:
    return mode is not AutonomyMode.OFF and mode >= _MINIMUM_MODE[capability]


def require(mode: AutonomyMode, capability: Capability) -> None:
    if mode is AutonomyMode.OFF:
        raise AutonomyError(
            "the AI layer is switched off for this organization; every other part of "
            "the platform works without it"
        )
    if not permits(mode, capability):
        raise AutonomyError(
            f"{capability.value} requires autonomy mode "
            f"{_MINIMUM_MODE[capability].name} or higher; the configured mode is "
            f"{mode.name}"
        )


def refuse_target_touching(action: str) -> None:
    """Refuse an action no mode permits.

    Deliberately not parameterised by mode: there is no configuration in
    which these become available, and taking a mode argument would invite a
    future caller to pass one.
    """
    if action in TARGET_TOUCHING:
        raise AutonomyError(
            f"{action} is never performed by the AI layer at any autonomy mode. It "
            "composes and explains; an operator decides and acts."
        )
