"""The four "freshly-published dependency version" engines
(`app/core/appsec/supplychain/freshness/engine.py`): manifest discovery
(reusing the same `osv/` lockfile parsers the OSV engines already use),
the disclosure-consent gate, a fresh version producing the aggregated
finding, an old version producing none, a total registry failure
producing the `KERVY-APPSEC-000` gap, the `MAX_FRESHNESS_LOOKUPS` bound,
and Rust's extra publisher-account-age clause.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.appsec.supplychain.freshness.crates_client import CrateVersionDetail
from app.core.appsec.supplychain.freshness.engine import (
    MAX_FRESHNESS_LOOKUPS,
    FreshnessGoEngine,
    FreshnessLookupError,
    FreshnessNpmEngine,
    FreshnessPypiEngine,
    FreshnessRustEngine,
)
from app.core.appsec.workspace import CodeScope, Workspace, resolve_workspace

_NOW = datetime(2026, 10, 11, tzinfo=UTC)


class _FrozenDatetime(datetime):
    """Patched over `engine.py`'s own `datetime` import so `datetime.now(UTC)`
    there returns a fixed instant, making "is this within N days of now"
    deterministic rather than a function of wall-clock time."""

    @classmethod
    def now(cls, tz: object = None) -> "_FrozenDatetime":
        return cls.fromtimestamp(_NOW.timestamp(), tz=UTC)


def _npm_workspace(tmp_path: Path) -> Workspace:
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/left-pad": {"version": "1.3.0"}}}',
        encoding="utf-8",
    )
    return resolve_workspace(tmp_path, CodeScope(allowed_paths=("package-lock.json",)))


class _FakeNpmClient:
    def __init__(self, times: dict[str, datetime | None], *, error: bool = False) -> None:
        self._times = times
        self._error = error
        self.calls: list[tuple[str, str]] = []

    async def get_publish_time(self, ctx: object, name: str, version: str) -> datetime | None:
        self.calls.append((name, version))
        if self._error:
            from app.core.appsec.supplychain.freshness.npm_client import NpmRegistryClientError

            raise NpmRegistryClientError("registry unreachable")
        return self._times.get(name)


async def test_applies_to_is_true_only_with_an_in_scope_lockfile(tmp_path: Path) -> None:
    workspace = _npm_workspace(tmp_path)
    assert FreshnessNpmEngine().applies_to(workspace) is True


async def test_applies_to_is_false_without_a_lockfile(tmp_path: Path) -> None:
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("*.txt",)))
    assert FreshnessNpmEngine().applies_to(workspace) is False


async def test_lookup_disabled_reports_a_disclosure_gap_not_a_clean_result(
    tmp_path: Path,
) -> None:
    workspace = _npm_workspace(tmp_path)

    results = await FreshnessNpmEngine(allow_advisory_lookup=False).run(workspace)

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "disclosure" in results[0].evidence.lower()


async def test_a_recently_published_version_is_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _npm_workspace(tmp_path)
    client = _FakeNpmClient({"left-pad": _NOW - timedelta(days=2)})
    engine = FreshnessNpmEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: client)
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    results = await engine.run(workspace)

    assert [r.id for r in results] == ["KERVY-SUPPLY-050"]
    assert "left-pad@1.3.0" in results[0].evidence
    assert results[0].severity.value == "LOW"
    assert results[0].confidence.value == "MEDIUM"


async def test_an_old_version_produces_no_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _npm_workspace(tmp_path)
    client = _FakeNpmClient({"left-pad": _NOW - timedelta(days=400)})
    engine = FreshnessNpmEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: client)
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    assert await engine.run(workspace) == []


async def test_a_version_with_no_registry_record_produces_no_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _npm_workspace(tmp_path)
    client = _FakeNpmClient({})
    engine = FreshnessNpmEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: client)
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    assert await engine.run(workspace) == []


async def test_a_total_registry_failure_is_a_gap_not_a_clean_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _npm_workspace(tmp_path)
    client = _FakeNpmClient({}, error=True)
    engine = FreshnessNpmEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: client)

    results = await engine.run(workspace)

    assert [r.id for r in results] == ["KERVY-APPSEC-000"]
    assert "unreachable" in results[0].evidence


async def test_a_mix_of_fresh_and_old_only_lists_the_fresh_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {'
        '"node_modules/left-pad": {"version": "1.3.0"},'
        '"node_modules/braces": {"version": "2.3.2"}'
        "}}",
        encoding="utf-8",
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("package-lock.json",)))
    client = _FakeNpmClient(
        {"left-pad": _NOW - timedelta(days=1), "braces": _NOW - timedelta(days=365)}
    )
    engine = FreshnessNpmEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: client)
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    [result] = await engine.run(workspace)

    assert "left-pad" in result.evidence
    assert "braces" not in result.evidence


async def test_lookups_beyond_the_bound_are_not_fetched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packages = {
        f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(MAX_FRESHNESS_LOOKUPS + 10)
    }
    import json

    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8"
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("package-lock.json",)))
    client = _FakeNpmClient({f"pkg-{i}": _NOW - timedelta(days=1) for i in range(200)})
    engine = FreshnessNpmEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: client)
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    await engine.run(workspace)

    assert len(client.calls) == MAX_FRESHNESS_LOOKUPS


# --- the other three ecosystems: applies_to + basic wiring ------------------


async def test_pypi_applies_to_a_pinned_requirements_file(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("requirements.txt",)))
    assert FreshnessPypiEngine().applies_to(workspace) is True


async def test_pypi_flags_a_recently_published_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("requirements.txt",)))

    class _FakePypiClient:
        async def get_publish_time(self, ctx: object, name: str, version: str) -> datetime:
            return _NOW - timedelta(days=1)

    engine = FreshnessPypiEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: _FakePypiClient())
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    [result] = await engine.run(workspace)
    assert "requests@2.31.0" in result.evidence


async def test_go_applies_to_a_go_sum_file(tmp_path: Path) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n",
        encoding="utf-8",
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("go.sum",)))
    assert FreshnessGoEngine().applies_to(workspace) is True


async def test_go_lookup_failure_wraps_the_clients_own_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "go.sum").write_text(
        "github.com/pkg/errors v0.9.1 h1:abc=\ngithub.com/pkg/errors v0.9.1/go.mod h1:def=\n",
        encoding="utf-8",
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("go.sum",)))

    class _FailingGoClient:
        async def get_publish_time(self, ctx: object, module: str, version: str) -> None:
            from app.core.appsec.supplychain.freshness.go_client import GoProxyClientError

            raise GoProxyClientError("timed out")

    engine = FreshnessGoEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: _FailingGoClient())

    results = await engine.run(workspace)
    assert [r.id for r in results] == ["KERVY-APPSEC-000"]


async def test_rust_applies_to_a_cargo_lock_file(tmp_path: Path) -> None:
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.229"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("Cargo.lock",)))
    assert FreshnessRustEngine().applies_to(workspace) is True


async def test_rust_finding_names_a_recently_created_publisher_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "evil-crate"\nversion = "0.1.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("Cargo.lock",)))

    class _FakeCratesClient:
        async def get_version_detail(
            self, ctx: object, name: str, version: str
        ) -> CrateVersionDetail:
            return CrateVersionDetail(
                published_at=_NOW - timedelta(days=1),
                publisher_account_created_at=_NOW - timedelta(days=5),
            )

    engine = FreshnessRustEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: _FakeCratesClient())
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    [result] = await engine.run(workspace)
    assert "published by an account created" in result.evidence


async def test_rust_finding_omits_the_publisher_clause_when_the_account_is_old(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.229"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8",
    )
    workspace = resolve_workspace(tmp_path, CodeScope(allowed_paths=("Cargo.lock",)))

    class _FakeCratesClient:
        async def get_version_detail(
            self, ctx: object, name: str, version: str
        ) -> CrateVersionDetail:
            return CrateVersionDetail(
                published_at=_NOW - timedelta(days=1),
                publisher_account_created_at=_NOW - timedelta(days=5000),
            )

    engine = FreshnessRustEngine(allow_advisory_lookup=True)
    monkeypatch.setattr(engine, "_build_client", lambda: _FakeCratesClient())
    monkeypatch.setattr("app.core.appsec.supplychain.freshness.engine.datetime", _FrozenDatetime)

    [result] = await engine.run(workspace)
    assert "published by an account created" not in result.evidence


def test_freshness_lookup_error_is_a_real_exception_type() -> None:
    assert issubclass(FreshnessLookupError, Exception)
