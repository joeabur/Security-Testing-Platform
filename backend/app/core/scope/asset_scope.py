"""Resolves `RulesOfEngagementRecord.asset_scope` into the validated, pure
domain type a CONTAINER/CLOUD_ACCOUNT/VIRTUAL_MACHINE/DOMAIN target's engine
needs — the same "ABORT RUN on anything malformed or unstated" contract
`resolve_rules_of_engagement` already enforces for network scope, applied to
the four newer asset kinds.

One generalized `asset_scope` JSON column carries all four shapes (plus the
pentest depth declaration); each `resolve_*_scope` function here validates
only its own kind's sub-shape and is the single place that shape is defined.
A fifth asset kind is a new function here and a new `TargetKind` value —
never a migration to this module's structure.

Every scope type below fails closed the same way `CodeScope`/RoE's schema
already do: an empty or absent allowlist is refused, never treated as
"everything." Engines are added in later phases; this module exists now so
every later engine reads from one place, not five bespoke parsers.
"""

import enum
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from app.core.scope.errors import AssetScopeValidationError


class TestDepth(enum.StrEnum):
    """How far a pentest tool may go against a discovered/authorized asset.
    Strictly ordered — a tool declared for a deeper tier never runs unless
    the RoE's `PentestScope.max_depth` is at least that deep. This is the
    concrete implementation of "clearly distinguish discovery, vulnerability
    assessment, validation, and exploitation."
    """

    DISCOVERY = "discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    VALIDATION = "validation"
    EXPLOITATION = "exploitation"

    @property
    def rank(self) -> int:
        return _DEPTH_ORDER.index(self)

    def at_least(self, minimum: "TestDepth") -> bool:
        return self.rank >= minimum.rank


_DEPTH_ORDER = (
    TestDepth.DISCOVERY,
    TestDepth.VULNERABILITY_SCAN,
    TestDepth.VALIDATION,
    TestDepth.EXPLOITATION,
)


class ContainerScope(BaseModel):
    image_ref: str = Field(min_length=1)
    allowed_registries: list[str] = Field(default_factory=list)
    allow_live_pull: bool = False


class CloudScope(BaseModel):
    provider: Literal["aws", "azure", "gcp"]
    account_ref: str = Field(min_length=1)
    credential_env_var: str = Field(min_length=1)
    allowed_regions: list[str] = Field(default_factory=list)
    # Not a caller-settable field: read-only is enforced by which SDK calls
    # the cloud engines are built to make at all (Phase 4), not by a flag a
    # request could flip. Present here only so a stored document's shape is
    # self-describing; a `True` value is rejected at resolve time.
    read_only: bool = True


class VmScope(BaseModel):
    host: str = Field(min_length=1)
    allowed_ports: list[int] = Field(default_factory=list)
    ssh_credential_env_var: str | None = None


class DomainScope(BaseModel):
    root_domain: str = Field(min_length=1)
    allowed_subdomain_patterns: list[str] = Field(default_factory=list)


class PentestScope(BaseModel):
    max_depth: TestDepth = TestDepth.DISCOVERY
    approved_modules: list[str] = Field(default_factory=list)


def resolve_container_scope(raw: dict[str, Any] | None) -> ContainerScope:
    scope = _parse(raw, ContainerScope)
    if not scope.allowed_registries:
        raise AssetScopeValidationError(
            "container asset_scope must declare allowed_registries — an unstated "
            "registry allowlist is not a permissive one"
        )
    return scope


def resolve_cloud_scope(raw: dict[str, Any] | None) -> CloudScope:
    scope = _parse(raw, CloudScope)
    if not scope.read_only:
        raise AssetScopeValidationError(
            "cloud asset_scope must be read_only — a mutating cloud call is a "
            "higher authorization tier this engine does not grant"
        )
    return scope


def resolve_vm_scope(raw: dict[str, Any] | None) -> VmScope:
    scope = _parse(raw, VmScope)
    if not scope.allowed_ports:
        raise AssetScopeValidationError(
            "vm asset_scope must declare allowed_ports — an unstated port "
            "allowlist is not a permissive one"
        )
    return scope


def resolve_domain_scope(raw: dict[str, Any] | None) -> DomainScope:
    return _parse(raw, DomainScope)


def resolve_pentest_scope(raw: dict[str, Any] | None) -> PentestScope:
    # Unlike the four asset scopes above, pentest tooling is an *additive*
    # capability layered on top of whatever target kind is already being
    # scanned — a target makes no statement about pentest tools at all by
    # default, and that silence means "discovery only" (passive, budget- and
    # scope-bounded like any other check), not "refuse to run." Only a
    # declared max_depth is ever validated against its own requirements.
    if raw is None:
        return PentestScope()
    try:
        scope = PentestScope.model_validate(raw)
    except ValidationError as exc:
        raise AssetScopeValidationError(f"asset_scope failed validation: {exc}") from exc
    if scope.max_depth is TestDepth.EXPLOITATION and not scope.approved_modules:
        raise AssetScopeValidationError(
            "pentest asset_scope declares max_depth=exploitation but lists no "
            "approved_modules — exploitation never runs against an unenumerated set"
        )
    return scope


def _parse[T: BaseModel](raw: dict[str, Any] | None, schema: type[T]) -> T:
    if raw is None:
        raise AssetScopeValidationError(f"asset_scope is required for a {schema.__name__} target")
    try:
        return schema.model_validate(raw)
    except ValidationError as exc:
        raise AssetScopeValidationError(f"asset_scope failed validation: {exc}") from exc
