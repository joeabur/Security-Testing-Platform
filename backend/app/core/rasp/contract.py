"""What a runtime-protection assessment would need, and what it may never do.

§4.5 row 6 settles a conflict between two source documents: one specifies a
full RASP-effectiveness engine, the other says do not implement RASP and do not
let it complicate the architecture. The later, more restrictive document wins,
so this phase ships **extension points only**. The acceptance criterion is
precise: *a RASP-effectiveness engine can be added without touching the
orchestrator or the scope engine; no RASP agent ships, and a static check
proves no unsafe-mode path exists for that interface.*

This module is that interface. It contains no engine, and the things it
deliberately does not contain are the point.

## The hard line: this platform does not run inside a customer's process

A RASP agent is code that loads into a running application and instruments it.
Shipping one would mean asking an operator to execute this project's code
inside their production process — which is the one thing §2 forbids outright,
and which no amount of configuration would make safe. So:

* there is no agent, no bootstrap, no `sitecustomize`, no import hook, no
  monkey-patch, and no instrumentation of any kind;
* the declaration below records what an operator **claims** is deployed. A
  claim is not a measurement, and everything here is named so that the
  difference stays visible in the data model rather than in a docstring;
* a future engine would establish effectiveness the way every other engine on
  this platform does — by sending authorized requests through the scope engine
  and observing the responses from outside.

## Why a claim is worth recording even though it is not evidence

Two reasons, and neither is "so the report looks fuller".

**It changes what a finding means.** An injection that succeeds against a
target whose operator claims a WAF and an input-validation middleware is a
different fact from the same injection against an unprotected target: it says
the claimed control did not stop it. `ClaimedControl` exists so that
observation can eventually be stated precisely instead of implied.

**It is the honest place to record coverage.** §14 requires a report to say
what it did *not* cover. A target carrying `claimed_controls` that no engine
tested should produce a visible "not tested" line, which is what
`untested_marker` builds. Silence would read as "the controls are fine".

## The unsafe-mode rule

`RuntimeProtectionEngine` takes a `RuntimeProtectionContext`, and that context
has **no field that could relax a control**: no `safe_mode`, no `force`, no
`allow_*`, no `bypass_*`, no `disable_*`, no engine-supplied endpoint. Its
network access is not a parameter at all — an engine reaches a target the same
way every other engine does, through the run's own scope-gated transport, under
the same rules of engagement.

`tests/test_rasp.py` asserts this by walking the dataclass fields and the
protocol's signatures, so adding such a field later is a test failure rather
than a code review someone has to remember to do.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from app.core.probes.models import Category, Confidence, ScanResult, Severity


class ControlKind(StrEnum):
    """Runtime controls an operator may claim.

    A closed set, because free text would mean every deployment describes the
    same control differently and no engine could ever act on it. `OTHER` exists
    so an unusual control is recorded under a name rather than dropped, and it
    is deliberately the only escape hatch.
    """

    WAF = "waf"
    RASP_AGENT = "rasp_agent"
    INPUT_VALIDATION_MIDDLEWARE = "input_validation_middleware"
    OUTPUT_FILTER = "output_filter"
    PROMPT_FIREWALL = "prompt_firewall"
    RATE_LIMITER = "rate_limiter"
    ANOMALY_DETECTION = "anomaly_detection"
    OTHER = "other"


class Evidenced(StrEnum):
    """How well a claimed control is actually known to be there.

    This is the enum that keeps the whole package honest. A claim entered by an
    operator and a control this platform *observed* behaving must never be
    stored in a way that lets a reader confuse them, so the distinction is a
    required field rather than a convention.
    """

    #: An operator said so. This is the only value anything in this repository
    #: can produce today, because nothing here measures runtime protection.
    CLAIMED = "claimed"
    #: An engine observed behaviour consistent with the control being active.
    #: Nothing sets this yet; it exists so a future engine has somewhere to put
    #: a real result without redefining the field.
    OBSERVED = "observed"
    #: An engine tested for the control and did not find it.
    NOT_OBSERVED = "not_observed"


@dataclass(frozen=True)
class ClaimedControl:
    """One control an operator says is deployed in front of a target.

    `vendor` and `notes` are free text and go nowhere near a command line.
    `telemetry_env_var` is a **variable name**, never a value: the same rule
    every credential on this platform follows, for the same reason — a secret
    in a database row is a secret in a backup, a log and a support ticket.
    """

    kind: ControlKind
    evidenced: Evidenced = Evidenced.CLAIMED
    vendor: str | None = None
    #: The NAME of an environment variable holding a telemetry endpoint or
    #: token, resolved (if ever) by the process that would make the request.
    #: Never the endpoint, never the token.
    telemetry_env_var: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if self.evidenced is not Evidenced.CLAIMED:
            # Nothing in this repository measures runtime protection, so
            # nothing in it may construct a control that says it did. A future
            # engine will relax this deliberately, together with the test that
            # asserts it — which is the point of making it fail loudly now
            # rather than letting an unmeasured claim quietly acquire the word
            # "observed".
            raise ValueError(
                f"evidenced={self.evidenced.value!r} claims a measurement, and no "
                "runtime-protection engine exists to have made one. Only "
                "'claimed' may be constructed today (docs/BUILD_SPEC.md §26 Phase 18)."
            )


@dataclass(frozen=True)
class RuntimeProtectionProfile:
    """Everything a target declares about its runtime protection.

    Empty is the normal case and means "nothing declared", which is different
    from "nothing deployed" — `declared` says which it is.
    """

    controls: tuple[ClaimedControl, ...] = ()

    @property
    def declared(self) -> bool:
        return bool(self.controls)

    def kinds(self) -> tuple[ControlKind, ...]:
        return tuple(control.kind for control in self.controls)

    def control_records(self) -> list[dict[str, object]]:
        """The storable form of each control, `evidenced` included.

        `evidenced` is written out rather than assumed, so a row read back
        years from now still says whether anything measured it.
        """
        return [
            {
                "kind": control.kind.value,
                "evidenced": control.evidenced.value,
                "vendor": control.vendor,
                "telemetry_env_var": control.telemetry_env_var,
                "notes": control.notes,
            }
            for control in self.controls
        ]

    def as_record(self) -> dict[str, object]:
        return {"controls": self.control_records()}

    @classmethod
    def from_records(cls, records: Sequence[object]) -> RuntimeProtectionProfile:
        """Rebuild a profile from what a target row stores.

        Unknown kinds map to `OTHER` rather than raising: a profile written by
        a newer version must not make an older one unable to render a target.
        A malformed entry is skipped, because a declaration this platform
        cannot read is not a control it should claim to know about.
        """
        controls: list[ClaimedControl] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            raw_kind = str(record.get("kind") or "").strip().lower()
            try:
                kind = ControlKind(raw_kind)
            except ValueError:
                kind = ControlKind.OTHER
            controls.append(
                ClaimedControl(
                    kind=kind,
                    vendor=(str(record["vendor"]) if record.get("vendor") else None),
                    telemetry_env_var=(
                        str(record["telemetry_env_var"])
                        if record.get("telemetry_env_var")
                        else None
                    ),
                    notes=str(record.get("notes") or ""),
                )
            )
        return cls(controls=tuple(controls))


@dataclass(frozen=True)
class RuntimeProtectionContext:
    """What a future engine would be handed.

    Deliberately, conspicuously minimal. There is no transport here, no base
    URL, no credentials and no flags: an engine reaches a target through the
    run's own scope-gated transport under the run's rules of engagement, which
    is what makes "added without touching the orchestrator or the scope engine"
    true rather than aspirational.

    A field that could relax a control — `safe_mode`, `force`, `allow_*`,
    `bypass_*`, `disable_*` — is forbidden here, and
    `tests/test_rasp.py::test_the_context_has_no_field_that_could_relax_a_control`
    walks these fields to prove none was added.
    """

    profile: RuntimeProtectionProfile
    #: Findings the rest of the run already produced. A RASP-effectiveness
    #: question is "did the claimed control stop this?", which is only
    #: answerable against attacks that were actually attempted.
    observed_findings: Sequence[ScanResult] = field(default_factory=tuple)


@runtime_checkable
class RuntimeProtectionEngine(Protocol):
    """The protocol a future RASP-effectiveness engine would implement.

    Two methods, matching `AppSecEngine` so the registry, the normalizer and
    the report need no new concept. **Nothing implements this today**, and
    `tests/test_rasp.py` asserts that: a shipped implementation would be a RASP
    engine, which this phase does not authorize.
    """

    id: str
    version: str

    def applies_to(self, context: RuntimeProtectionContext) -> bool: ...

    async def run(self, context: RuntimeProtectionContext) -> list[ScanResult]: ...


#: The engine set, which is empty and is expected to stay empty for this phase.
#: Explicit registration, same as every other registry on this platform: an
#: engine that is not deliberately listed does not run. A future phase adds one
#: line here, which is the whole extension point.
RUNTIME_PROTECTION_ENGINES: tuple[RuntimeProtectionEngine, ...] = ()


def untested_marker(profile: RuntimeProtectionProfile) -> ScanResult | None:
    """A visible "not tested" line for declared controls nothing measured.

    Returns `None` when nothing was declared — there is no gap to report about
    a target that claimed nothing. Otherwise it produces the same shape every
    other untested engine produces, so one report path handles it.

    This is the only thing in this package that produces a `ScanResult`, and it
    reports the *absence* of a measurement. That asymmetry is deliberate: the
    package can say "we did not test this" and cannot say "this works".
    """
    if not profile.declared:
        return None

    named = ", ".join(sorted({control.kind.value for control in profile.controls}))
    return ScanResult(
        id="KERVY-RASP-000",
        title="Not tested: claimed runtime protection",
        category=Category.DESIGN,
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.DESIGN_REVIEW,
        endpoint="runtime_protection",
        description=(
            f"This target declares runtime protection ({named}). This assessment "
            "did not measure any of it. No runtime-protection engine exists on this "
            "platform: the declaration is what an operator stated, not something "
            "observed."
        ),
        evidence=(
            "declared controls: "
            + named
            + "\nevidenced: claimed (operator-supplied, unverified)"
            + "\nengines available: none"
        ),
        impact=(
            "Unknown. A claimed control that was never exercised may or may not stop "
            "the attacks in this report, and this assessment does not distinguish the "
            "two."
        ),
        remediation=(
            "Treat the findings in this report as the behaviour observed with these "
            "controls in place, since they were deployed during the assessment. To "
            "establish what each control contributes, test with it disabled in a "
            "non-production environment under its own authorization."
        ),
        probe_id="rasp.declaration",
        probe_version="1.0.0",
    )
