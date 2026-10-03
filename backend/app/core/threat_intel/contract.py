"""The shape a threat-intel correlation provider would have — design only.

No concrete provider ships in this phase, the same "no real vendor account
to verify against" deferral `app/core/cloud/engine.py` already documents
for Azure/GCP and `docs/roadmap.md`'s SIEM write-up documents for a live
Splunk/Sentinel account: correlating a finding's advisory against a real
feed (CISA's Known Exploited Vulnerabilities catalog, FIRST's EPSS score,
a commercial feed) means an API key and a live account this deployment
does not have, and shipping an untested integration against either would
be exactly the kind of unverified claim this codebase's own discipline
refuses to make.

What *is* here is the contract a future provider would implement, so the
shape is reviewed now rather than invented ad hoc when a real feed is
wired up:

* `ThreatIntelContext` — what correlation against one advisory can say:
  whether it is known to be actively exploited, and FIRST's EPSS
  probability-of-exploitation score, each independently absent (`None`)
  rather than guessed when the provider has no opinion. `retrieved_at` is
  required whenever either field is populated, for the same "every claim
  is traceable to when it was checked" reason `frameworks.py` pins a
  retrieval date on every framework version.
* `ThreatIntelProvider` — a `Protocol`, not an ABC, so a provider is
  anything with this one async method; nothing here constrains how it
  gets its data.
* `NullThreatIntelProvider` — the only implementation in this phase.
  It answers every advisory with "not assessed" rather than silently
  returning nothing or raising, so a caller that has not configured a
  real provider gets an honest, typed absence instead of a crash or a
  guess. This is the same role `tool_unavailable()` plays for a missing
  SAST/IaC binary (`app/core/appsec/contract.py`) and the same role
  `_PROVIDERS = {"aws": ...}` plays for `azure`/`gcp` in the cloud engine
  — a named, deliberate "not yet" rather than an absent code path.

Where this would plug in, once a real provider exists: `app/core/
findings/normalize.py::build_finding` is the one place a `Finding` is
created from a `ScanResult`, and a `ThreatIntelContext` keyed by the
result's own `verified_advisories()` output is the natural enrichment
point there — never earlier, because advisory identifiers are only
verified (not invented) at that stage. Any remediation-priority scheme
this platform computes from severity/confidence/exposure alone would
also be a natural consumer: `known_exploited=True` or a high EPSS score
is exactly the kind of signal that ought to bump a finding a
severity-only mapping would otherwise under-prioritize, once this
contract has a real provider behind it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ThreatIntelContext:
    """What one provider knows about one advisory, as of `retrieved_at`.

    Every field is independently optional: a provider may know an
    advisory is actively exploited without having an EPSS score for it
    (or vice versa), and a provider with no opinion on either leaves both
    `None` rather than a borrowed default that would read as a real
    answer.
    """

    advisory: str
    #: True/False from the provider's own catalog; `None` means "this
    #: provider does not track that", not "confirmed not exploited".
    known_exploited: bool | None = None
    #: FIRST's EPSS score: estimated probability (0.0-1.0) that this
    #: advisory sees exploitation in the next 30 days.
    epss_score: float | None = None
    #: Which feed this came from, e.g. "cisa-kev", "first-epss" — reported
    #: on the finding so a reader can judge the source, the same reason
    #: `frameworks.py` records `source` alongside each pinned version.
    source: str | None = None
    #: Required whenever either score field is populated; the "as of
    #: when" every correlated claim needs.
    retrieved_at: datetime | None = None

    def __post_init__(self) -> None:
        if (self.known_exploited is not None or self.epss_score is not None) and (
            self.retrieved_at is None
        ):
            raise ValueError(
                "a populated ThreatIntelContext needs retrieved_at: a correlation "
                "claim with no timestamp cannot be re-checked or expired"
            )
        if self.epss_score is not None and not 0.0 <= self.epss_score <= 1.0:
            raise ValueError(f"epss_score must be in [0.0, 1.0], got {self.epss_score!r}")


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Anything that can correlate advisory identifiers against a feed.

    A `Protocol`, not a base class a provider must inherit from: the only
    contract is this one async method's signature.
    """

    async def correlate(
        self, advisories: tuple[str, ...]
    ) -> dict[str, ThreatIntelContext]:
        """Look up each advisory; omit any this provider has no data for.

        `advisories` are already-verified identifiers
        (`app.core.appsec.identifiers.verified_advisories`'s own output),
        never raw probe text — correlation is enrichment of a confirmed
        identifier, not a second chance to invent one. The result maps
        only the advisories this provider actually has something to say
        about; a caller treats a missing key the same as `None` fields on
        `ThreatIntelContext`, not as an error.
        """
        ...


class NullThreatIntelProvider:
    """The only provider that ships in this phase: every advisory comes
    back unassessed, deliberately and explicitly, rather than omitted.

    A caller using this provider gets `ThreatIntelContext(advisory=...,
    known_exploited=None, epss_score=None)` for everything it asks about —
    visibly "not assessed" wherever a report renders it, never a blank
    that could be misread as "checked and clean"."""

    async def correlate(
        self, advisories: tuple[str, ...]
    ) -> dict[str, ThreatIntelContext]:
        return {advisory: ThreatIntelContext(advisory=advisory) for advisory in advisories}
