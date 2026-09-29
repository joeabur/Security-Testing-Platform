"""Reporting runtimes that no longer receive security patches.

Why this is its own engine rather than a CVE check: an end-of-life runtime has
no CVE, and that is exactly the problem. Nothing will be assigned, nothing will
be backported, and the next vulnerability in it simply stays open. A scanner
that only matched advisories would report a Python 3.7 image as clean.

Three outcomes, and the third is the one that keeps this honest:

* **End of life** — a dated finding, severity by how long ago.
* **Approaching end of life** (within a year of `AS_OF`) — informational, so it
  reaches a plan before it reaches an incident.
* **Not assessed** — the runtime or its series is not in the vendored table.
  Reported explicitly. Saying nothing would let a reader take silence for
  support, which is the failure mode this engine exists to prevent.
"""

from __future__ import annotations

from datetime import date

from app.core.appsec.contract import EngineMeta, Pillar
from app.core.appsec.supplychain.eol import AS_OF, is_end_of_life, lookup
from app.core.appsec.supplychain.manifests import RuntimeDeclaration, runtime_declarations
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity

#: Within this many days of EOL, a runtime is worth planning for.
APPROACHING_DAYS = 365


def _severity(days_past: int) -> Severity:
    """Older means worse, because the backlog of unpatched issues grows.

    Deliberately not CRITICAL: an unsupported runtime is a standing exposure,
    not a demonstrated exploit, and §11 reserves the top band for what was
    shown to work. Calling this critical would devalue the findings that are.
    """
    if days_past >= 730:
        return Severity.HIGH
    if days_past >= 180:
        return Severity.MEDIUM
    return Severity.LOW


class EndOfLifeRuntimeEngine:
    meta = EngineMeta(
        id="appsec.supplychain.eol",
        version="1.0.0",
        name="End-of-life runtime detection",
        pillar=Pillar.SCA,
        tool="built-in",
        description=(
            "Compares declared runtime versions against a vendored end-of-life "
            "table. Reads files only; makes no network calls."
        ),
    )

    def __init__(self, *, today: date | None = None) -> None:
        # Injectable so the tests are not time bombs: a fixed date keeps a
        # "this is EOL" assertion true next year.
        self._today = today or AS_OF

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(runtime_declarations(workspace))

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        declarations = runtime_declarations(workspace)
        if not declarations:
            return []

        results: list[ScanResult] = []
        unassessed: list[RuntimeDeclaration] = []
        seen: set[tuple[str, str, str]] = set()

        for declaration in declarations:
            key = (declaration.runtime, declaration.version, declaration.source)
            if key in seen:
                continue
            seen.add(key)

            entry = lookup(declaration.runtime, declaration.version)
            if entry is None:
                unassessed.append(declaration)
                continue

            days = (self._today - entry.end_of_life).days
            if is_end_of_life(entry, today=self._today):
                results.append(
                    ScanResult(
                        id="KERVY-SUPPLY-010",
                        title=(
                            f"End-of-life runtime: {declaration.runtime} "
                            f"{entry.series} in {declaration.source}"
                        ),
                        category=Category.INFRASTRUCTURE,
                        severity=_severity(days),
                        confidence=Confidence.HIGH,
                        endpoint=f"{declaration.source}:{declaration.runtime}",
                        description=(
                            f"{declaration.source} pins {declaration.runtime} "
                            f"{declaration.version} (declared as {declaration.raw!r}). The "
                            f"{declaration.runtime} {entry.series} series reached end of life "
                            f"on {entry.end_of_life.isoformat()}, {days} days before the "
                            f"end-of-life data this check used ({AS_OF.isoformat()})."
                        ),
                        evidence=(
                            f"{declaration.source}: {declaration.raw}\n"
                            f"Series {entry.series} EOL {entry.end_of_life.isoformat()} "
                            f"per {entry.source}\n"
                            f"End-of-life table compiled {AS_OF.isoformat()}"
                        ),
                        impact=(
                            "Security fixes are no longer published for this series, so "
                            "the next vulnerability found in it stays open. No CVE will be "
                            "assigned against your use of it, which is why an advisory "
                            "scan reports this as clean."
                        ),
                        remediation=(
                            f"Move to a supported {declaration.runtime} series. If the move "
                            "cannot happen yet, record it as accepted risk with a date, so "
                            "it is a decision rather than an oversight."
                        ),
                        probe_id=self.meta.id,
                        probe_version=self.meta.version,
                    )
                )
            elif -days <= APPROACHING_DAYS:
                results.append(
                    ScanResult(
                        id="KERVY-SUPPLY-011",
                        title=(
                            f"Runtime approaching end of life: {declaration.runtime} {entry.series}"
                        ),
                        category=Category.INFRASTRUCTURE,
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                        endpoint=f"{declaration.source}:{declaration.runtime}",
                        description=(
                            f"{declaration.runtime} {entry.series} reaches end of life on "
                            f"{entry.end_of_life.isoformat()}, within a year of the "
                            f"end-of-life data this check used ({AS_OF.isoformat()})."
                        ),
                        evidence=(
                            f"{declaration.source}: {declaration.raw}\n"
                            f"Series {entry.series} EOL {entry.end_of_life.isoformat()} "
                            f"per {entry.source}"
                        ),
                        impact="None today. It becomes unsupported on the date above.",
                        remediation="Plan the upgrade before the date rather than after it.",
                        probe_id=self.meta.id,
                        probe_version=self.meta.version,
                    )
                )

        if unassessed:
            listed = "\n".join(
                f"{item.source}: {item.runtime} {item.version} ({item.raw})"
                for item in sorted(unassessed, key=lambda item: (item.source, item.runtime))
            )
            results.append(
                ScanResult(
                    id="KERVY-SUPPLY-019",
                    title="Not assessed: runtimes outside the end-of-life table",
                    category=Category.INFRASTRUCTURE,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.DESIGN_REVIEW,
                    endpoint="supplychain/eol",
                    description=(
                        f"{len(unassessed)} declared runtime version(s) are not in the "
                        f"vendored end-of-life table (compiled {AS_OF.isoformat()}), so this "
                        "assessment says nothing about whether they are still supported. "
                        "This is not a statement that they are."
                    ),
                    evidence=listed,
                    impact=(
                        "Unknown. An unassessed runtime may be years past end of life; "
                        "nothing here has checked."
                    ),
                    remediation=(
                        "Check the vendor's support schedule for these versions, or extend "
                        "app/core/appsec/supplychain/eol.py with a dated entry."
                    ),
                    probe_id=self.meta.id,
                    probe_version=self.meta.version,
                )
            )
        return results
