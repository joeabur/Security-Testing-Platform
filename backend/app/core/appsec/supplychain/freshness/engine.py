"""Four thin engines flagging a dependency whose resolved version was
published suspiciously recently (`docs/supply-chain.md`'s "no registry
lookup... no 'package published yesterday' signal" gap — the
publish-recency half of it; see this package's `__init__.py` for the half
deliberately not attempted here).

**Why a 7-day window, not npm/pnpm's own 24-hour install-time cooldown.**
pnpm 11 and Yarn Berry 4.x both default to a 24-hour `minimumReleaseAge`
specifically to let a bad release get caught and pulled before an install
picks it up (confirmed via research) — but that is an install-time gate,
preventing adoption outright. This is a scan of an *already-resolved*
lockfile, after the fact: the dependency is already in the build, so the
question is "is this still worth a human's attention," not "should this
be blocked." A week gives a real review signal without flagging every
routine dependency bump a project makes, the same reasoning JFrog's own
documented 7-day `minimumReleaseAge` configuration example uses for
teams wanting a stricter-than-default policy.

**Why this reuses `allow_advisory_lookup` rather than a new flag.** The
disclosure shape is identical to what this flag already gates for
pip-audit and every OSV engine: sending a resolved dependency's name and
version to a third party. Landing a second feature on this flag also
means it lands on a flag that is *already* operator-settable in
production — see `docs/roadmap.md`'s "Advisory-lookup consent, wired for
real" section.

**Why one aggregated finding per run, not one per dependency.** Mirrors
`NameConfusionEngine`'s own choice for the same reason: this is a single
circumstantial signal across a routine lockfile, not a confirmed,
individually-actionable vulnerability per package, so per-dependency
finding-count explosion on an ordinary dependency-bump day would be
worse than useful.

**Why `Confidence.MEDIUM`, not `DESIGN_REVIEW` like `NameConfusionEngine`.**
`NameConfusionEngine` picks `DESIGN_REVIEW` because "nothing was executed
and no registry was consulted" — stated explicitly in its own docstring.
This engine *does* consult a live registry: the publish date itself is a
confirmed, observed fact, even though what it implies about risk is still
circumstantial, which is why severity stays at `LOW` regardless.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from app.core.appsec.contract import EngineMeta, Pillar
from app.core.appsec.osv.cargo_lock import cargo_lock_packages
from app.core.appsec.osv.go_sum import go_sum_packages
from app.core.appsec.osv.npm_lockfile import npm_lockfile_packages
from app.core.appsec.osv.pypi_requirements import pypi_requirements_packages
from app.core.appsec.workspace import Workspace
from app.core.probes.models import Category, Confidence, ScanResult, Severity
from app.core.scope.context import RunContext
from app.core.scope.transport import GatedTransport

from .crates_client import CratesRegistryClient, CratesRegistryClientError
from .egress import (
    crates_egress_context,
    go_proxy_egress_context,
    npm_egress_context,
    pypi_egress_context,
)
from .go_client import GoProxyClient, GoProxyClientError
from .npm_client import NpmRegistryClient, NpmRegistryClientError
from .pypi_client import PypiRegistryClient, PypiRegistryClientError

#: A version published within this window of "now" is flagged. See the
#: module docstring for why 7 days, not npm/pnpm's own 24-hour
#: install-time cooldown default.
FRESHNESS_WINDOW = timedelta(days=7)

#: crates.io-only corroborating detail: a publishing account created
#: within this window of "now" is named alongside a flagged version, as
#: additive text — never its own finding, never a severity change. Wider
#: than `FRESHNESS_WINDOW` because this is a secondary, corroborating
#: signal, not the primary gate.
PUBLISHER_ACCOUNT_WINDOW = timedelta(days=90)

#: However many dependencies a lockfile resolves, at most this many are
#: looked up per engine run — the same "bounded, stated plainly" idiom as
#: `osv/client.py`'s `MAX_DETAIL_LOOKUPS` and
#: `enrichment/advisory_detail.py`'s `MAX_ENRICHMENT_LOOKUPS`.
MAX_FRESHNESS_LOOKUPS = 50

#: One shared marker so the base class's loop can catch any of the four
#: clients' own typed errors without catching `Exception` broadly. Each
#: subclass's `_lookup()` is the one place a client's own error type is
#: named.
class FreshnessLookupError(Exception):
    """A single dependency's freshness lookup could not be completed."""


class _FreshnessEngineBase:
    """Everything about this check that does not depend on which registry
    a concrete subclass talks to: manifest discovery, the consent gate,
    the bounded lookup loop, and finding shape are all generic. A
    subclass supplies only which manifests to look for, how to parse one
    into `(name, version)` pairs (reusing the same `osv/` lockfile parsers
    the OSV engines already use), which egress context and client to
    build, and how to call that client.
    """

    meta: EngineMeta
    _manifest_names: tuple[str, ...]
    _ecosystem: str

    def __init__(self, *, allow_advisory_lookup: bool = False) -> None:
        self._allow_lookup = allow_advisory_lookup

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        raise NotImplementedError

    def _egress_context(self) -> RunContext:
        raise NotImplementedError

    def _build_client(self) -> object:
        raise NotImplementedError

    async def _lookup(
        self, client: object, ctx: RunContext, name: str, version: str
    ) -> tuple[datetime, datetime | None] | None:
        """`(published_at, publisher_account_created_at)` for `name`
        `version`, or `None` if the registry has no record of it.
        Raises `FreshnessLookupError` for anything else that went wrong."""
        raise NotImplementedError

    def _manifests(self, workspace: Workspace) -> list[str]:
        declared = [
            str(path.relative_to(workspace.root))
            for path in workspace.manifests()
            if path.name in self._manifest_names
        ]
        if declared:
            return declared
        return [
            str(path.relative_to(workspace.root))
            for path in workspace.files
            if path.name in self._manifest_names
        ]

    def applies_to(self, workspace: Workspace) -> bool:
        return bool(self._manifests(workspace))

    async def run(self, workspace: Workspace) -> list[ScanResult]:
        manifests = self._manifests(workspace)
        if not manifests:
            return []

        if not self._allow_lookup:
            return [self._lookup_disabled(manifests)]

        ctx = self._egress_context()
        client = self._build_client()
        now = datetime.now(UTC)

        attempted = 0
        succeeded = 0
        last_error = ""
        flagged: list[tuple[str, str, datetime, datetime | None]] = []

        for manifest in manifests:
            if attempted >= MAX_FRESHNESS_LOOKUPS:
                break
            for name, version in self._packages_for(workspace.root / manifest):
                if attempted >= MAX_FRESHNESS_LOOKUPS:
                    break
                attempted += 1
                try:
                    detail = await self._lookup(client, ctx, name, version)
                except FreshnessLookupError as exc:
                    last_error = str(exc)
                    continue
                succeeded += 1
                if detail is None:
                    continue
                published_at, publisher_created_at = detail
                if now - published_at <= FRESHNESS_WINDOW:
                    flagged.append((name, version, published_at, publisher_created_at))

        if attempted > 0 and succeeded == 0:
            return [self._query_failed(last_error)]
        if not flagged:
            return []
        return [self._finding(flagged, now)]

    def _finding(
        self, flagged: list[tuple[str, str, datetime, datetime | None]], now: datetime
    ) -> ScanResult:
        lines = []
        for name, version, published_at, publisher_created_at in sorted(
            flagged, key=lambda item: (item[0], item[1])
        ):
            age_days = (now - published_at).days
            line = (
                f"{self._ecosystem}:{name}@{version} — published "
                f"{published_at.date()} ({age_days} day(s) ago)"
            )
            if (
                publisher_created_at is not None
                and now - publisher_created_at <= PUBLISHER_ACCOUNT_WINDOW
            ):
                account_age_days = (now - publisher_created_at).days
                line += (
                    f"; published by an account created {publisher_created_at.date()} "
                    f"({account_age_days} day(s) ago)"
                )
            lines.append(line)

        count = len(flagged)
        return ScanResult(
            id="KERVY-SUPPLY-050",
            title=(
                f"{count} {self._ecosystem} dependenc{'y' if count == 1 else 'ies'} "
                f"published within the last {FRESHNESS_WINDOW.days} days"
            ),
            category=Category.DESIGN,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            endpoint=f"supplychain/freshness/{self._ecosystem.lower()}",
            description=(
                "These dependencies' resolved versions were published recently "
                "enough that an attacker who compromised the package would have "
                "had little time to be caught before this build picked it up. "
                "That is a reason to look, not a finding of wrongdoing: most new "
                "releases are entirely legitimate, including routine maintenance "
                "bumps."
            ),
            evidence="\n".join(lines),
            impact=(
                "A malicious or compromised release has the least time to be "
                "caught and pulled before builds start consuming it."
            ),
            remediation=(
                "Review each dependency's release notes and diff against the "
                "prior version before trusting it in a production build; "
                "consider a cooldown period before adopting a brand-new release."
            ),
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )

    def _lookup_disabled(self, manifests: list[str]) -> ScanResult:
        return ScanResult(
            id="KERVY-APPSEC-000",
            title=f"Not tested: {self._ecosystem} dependency freshness check",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=Pillar.SCA.value,
            description=(
                f"{self._ecosystem} manifests were found but not checked against "
                f"the {self._ecosystem} registry, so this assessment says nothing "
                "about whether any dependency was published suspiciously recently."
            ),
            evidence=(
                f"in-scope manifests: {', '.join(manifests)}\n\n"
                "The freshness check sends the resolved dependency list to a "
                f"third-party registry. That is a disclosure the operator opts "
                "into per assessment, so it is off unless enabled."
            ),
            impact="Unknown — no freshness check was performed.",
            remediation="Enable allow_advisory_lookup for this assessment.",
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )

    def _query_failed(self, reason: str) -> ScanResult:
        return ScanResult(
            id="KERVY-APPSEC-000",
            title=f"Not tested: {self._ecosystem} dependency freshness check",
            category=Category.INFRASTRUCTURE,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.DESIGN_REVIEW,
            endpoint=Pillar.SCA.value,
            description=(
                f"The {self._ecosystem} registry could not be queried, so this "
                "assessment says nothing about whether any dependency was "
                "published suspiciously recently."
            ),
            evidence=reason,
            impact="Unknown — the query did not complete.",
            remediation="Re-run once the registry is reachable, or check egress policy.",
            probe_id=self.meta.id,
            probe_version=self.meta.version,
        )


class FreshnessNpmEngine(_FreshnessEngineBase):
    meta = EngineMeta(
        id="appsec.supplychain.freshness_npm",
        version="1.0.0",
        name="Dependency freshness check (npm)",
        pillar=Pillar.SCA,
        tool="registry.npmjs.org",
        description=(
            "Parses npm lockfiles and flags a resolved version published "
            "within the last 7 days, via a direct, unauthenticated query to "
            "the npm registry."
        ),
    )
    _manifest_names = ("package-lock.json",)
    _ecosystem = "npm"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return npm_lockfile_packages(path)

    def _egress_context(self) -> RunContext:
        return npm_egress_context()

    def _build_client(self) -> NpmRegistryClient:
        return NpmRegistryClient(transport=GatedTransport())

    async def _lookup(
        self, client: object, ctx: RunContext, name: str, version: str
    ) -> tuple[datetime, datetime | None] | None:
        npm_client = cast(NpmRegistryClient, client)
        try:
            published_at = await npm_client.get_publish_time(ctx, name, version)
        except NpmRegistryClientError as exc:
            raise FreshnessLookupError(str(exc)) from exc
        return None if published_at is None else (published_at, None)


class FreshnessPypiEngine(_FreshnessEngineBase):
    meta = EngineMeta(
        id="appsec.supplychain.freshness_pypi",
        version="1.0.0",
        name="Dependency freshness check (PyPI)",
        pillar=Pillar.SCA,
        tool="pypi.org",
        description=(
            "Parses pinned Python requirements files and flags a resolved "
            "version published within the last 7 days, via a direct, "
            "unauthenticated query to PyPI's JSON API."
        ),
    )
    _manifest_names = ("requirements.txt", "requirements.in")
    _ecosystem = "PyPI"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return pypi_requirements_packages(path)

    def _egress_context(self) -> RunContext:
        return pypi_egress_context()

    def _build_client(self) -> PypiRegistryClient:
        return PypiRegistryClient(transport=GatedTransport())

    async def _lookup(
        self, client: object, ctx: RunContext, name: str, version: str
    ) -> tuple[datetime, datetime | None] | None:
        pypi_client = cast(PypiRegistryClient, client)
        try:
            published_at = await pypi_client.get_publish_time(ctx, name, version)
        except PypiRegistryClientError as exc:
            raise FreshnessLookupError(str(exc)) from exc
        return None if published_at is None else (published_at, None)


class FreshnessGoEngine(_FreshnessEngineBase):
    meta = EngineMeta(
        id="appsec.supplychain.freshness_go",
        version="1.0.0",
        name="Dependency freshness check (Go)",
        pillar=Pillar.SCA,
        tool="proxy.golang.org",
        description=(
            "Parses go.sum and flags a resolved version published within "
            "the last 7 days, via a direct, unauthenticated query to the "
            "Go module proxy."
        ),
    )
    _manifest_names = ("go.sum",)
    _ecosystem = "Go"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return go_sum_packages(path)

    def _egress_context(self) -> RunContext:
        return go_proxy_egress_context()

    def _build_client(self) -> GoProxyClient:
        return GoProxyClient(transport=GatedTransport())

    async def _lookup(
        self, client: object, ctx: RunContext, name: str, version: str
    ) -> tuple[datetime, datetime | None] | None:
        go_client = cast(GoProxyClient, client)
        try:
            published_at = await go_client.get_publish_time(ctx, name, version)
        except GoProxyClientError as exc:
            raise FreshnessLookupError(str(exc)) from exc
        return None if published_at is None else (published_at, None)


class FreshnessRustEngine(_FreshnessEngineBase):
    meta = EngineMeta(
        id="appsec.supplychain.freshness_rust",
        version="1.0.0",
        name="Dependency freshness check (Rust)",
        pillar=Pillar.SCA,
        tool="crates.io",
        description=(
            "Parses Cargo.lock and flags a resolved version published "
            "within the last 7 days, via a direct, unauthenticated query "
            "to crates.io — the one ecosystem here where the registry "
            "also reports the publishing account's own creation date."
        ),
    )
    _manifest_names = ("Cargo.lock",)
    _ecosystem = "Rust"

    def _packages_for(self, path: Path) -> list[tuple[str, str]]:
        return cargo_lock_packages(path)

    def _egress_context(self) -> RunContext:
        return crates_egress_context()

    def _build_client(self) -> CratesRegistryClient:
        return CratesRegistryClient(transport=GatedTransport())

    async def _lookup(
        self, client: object, ctx: RunContext, name: str, version: str
    ) -> tuple[datetime, datetime | None] | None:
        crates_client = cast(CratesRegistryClient, client)
        try:
            detail = await crates_client.get_version_detail(ctx, name, version)
        except CratesRegistryClientError as exc:
            raise FreshnessLookupError(str(exc)) from exc
        if detail is None:
            return None
        return (detail.published_at, detail.publisher_account_created_at)
