import re
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.rasp.contract import ControlKind
from app.models.target import TargetEnvironment, TargetKind

if TYPE_CHECKING:
    from app.models.target import Target


class DeclaredToolIn(BaseModel):
    """A tool the operator declares the agent can call.

    Declared, never discovered: docs/BUILD_SPEC.md §9 requires the tool
    surface to come from an operator, a manifest or an MCP adapter, because
    a permission graph inferred from a model's answers reads as
    authoritative and is fiction.
    """

    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=500)
    writes: bool = False
    irreversible: bool = False
    external: bool = False
    requires_confirmation: bool = False


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    environment: TargetEnvironment
    kind: TargetKind
    base_url: str = Field(min_length=1, max_length=2048)


class CodeScopeIn(BaseModel):
    """Which paths inside a checkout may be read.

    `allowed_paths` has no default: an unstated boundary is not a permissive
    one, and the engines refuse to run until it is declared
    (docs/BUILD_SPEC.md §4.5, §6.2).
    """

    allowed_paths: list[str] = Field(min_length=1, max_length=200)
    excluded_paths: list[str] = Field(default_factory=list, max_length=200)
    max_repo_size_mb: int = Field(default=500, ge=1, le=10_000)
    # Required before a remote repository can be cloned. Left empty, only a
    # local checkout is possible — which is the safe default.
    allowed_repo_hosts: list[str] = Field(default_factory=list, max_length=20)


class TargetCodeUpdate(BaseModel):
    repo_ref: str = Field(min_length=1, max_length=2048)
    languages: list[str] = Field(default_factory=list, max_length=20)
    build_manifest_paths: list[str] = Field(default_factory=list, max_length=50)
    code_scope: CodeScopeIn


class DomainScopeIn(BaseModel):
    """What a `DOMAIN` target's engine may enumerate and test.

    `root_domain` has no default — the same "an unstated boundary is not
    permissive" rule `CodeScopeIn.allowed_paths` already enforces.
    `allowed_subdomain_patterns` defaults to empty, which the domain engine's
    resolver reads as "probe only the root domain itself," never "every
    subdomain discovery turns up."
    """

    root_domain: str = Field(min_length=1, max_length=253)
    allowed_subdomain_patterns: list[str] = Field(default_factory=list, max_length=50)


class ContainerScopeIn(BaseModel):
    """What a `CONTAINER` target's engine may pull and scan.

    `allowed_registries` has no default — the same "an unstated allowlist is
    not a permissive one" rule `resolve_container_scope` enforces at run
    time; this schema does not relax it, it only moves the same refusal
    earlier, to the point of configuration rather than the point of a run.
    `allow_live_pull` defaults to `False`: declaring a registry allowlist is
    not, by itself, authorization to reach the network — an operator opts
    in to the live pull explicitly, a separate decision from which
    registries would be acceptable if they did.
    """

    image_ref: str = Field(min_length=1, max_length=2048)
    allowed_registries: list[str] = Field(default_factory=list, max_length=20)
    allow_live_pull: bool = False


class ClaimedControlIn(BaseModel):
    """One runtime control an operator says is deployed.

    `telemetry_env_var` is a variable NAME. The field is validated as one so a
    value pasted in by mistake is rejected at the edge rather than stored: a
    secret in a database row is a secret in every backup, log and support
    ticket taken afterwards.

    There is no `evidenced` field. It would be the only field on this object a
    caller could use to assert a measurement nobody made, and the API is not
    the place to let that happen — everything stored through here is
    `claimed`, and `app/core/rasp/contract.py` refuses to construct anything
    else while no engine exists.
    """

    kind: ControlKind
    vendor: str | None = Field(default=None, max_length=120)
    telemetry_env_var: str | None = Field(default=None, max_length=128)
    notes: str = Field(default="", max_length=500)

    @field_validator("telemetry_env_var")
    @classmethod
    def _must_be_a_variable_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", value):
            raise ValueError(
                "telemetry_env_var must be an environment variable NAME "
                "(A-Z, 0-9 and underscore), never its value."
            )
        return value


class TargetRuntimeProtectionUpdate(BaseModel):
    """What an operator declares is protecting this target.

    An empty list is meaningful and allowed: it clears the declaration.
    """

    controls: list[ClaimedControlIn] = Field(default_factory=list, max_length=20)


class TargetAdapterUpdate(BaseModel):
    """Which adapter speaks to this target's chat surface, and how."""

    adapter_kind: Literal["chat_http", "openai_compatible"]
    adapter_config: dict[str, Any] = Field(default_factory=dict)
    declared_tools: list[DeclaredToolIn] = Field(default_factory=list, max_length=100)


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    environment: TargetEnvironment
    kind: TargetKind
    base_url: str
    adapter_kind: str | None
    adapter_config: dict[str, Any]
    code_repo_ref: str | None
    runtime_protection: list[dict[str, Any]] = Field(default_factory=list)
    code_languages: list[str]
    code_build_manifest_paths: list[str]
    declared_tools: list[dict[str, Any]]
    has_authorization: bool
    has_rules_of_engagement: bool
    created_at: datetime


def target_read(target: "Target") -> TargetRead:
    """The canonical `Target` -> `TargetRead` conversion.

    Not a plain `TargetRead.model_validate(target, from_attributes=True)`:
    `has_authorization`/`has_rules_of_engagement` are derived from the
    relationships, not an ORM attribute of the same name, so every reader
    of a target — the targets router and the native agent's `get_asset`/
    `search_assets` tools alike — goes through this one function rather
    than each recomputing the derivation and risking the two drifting.
    """
    return TargetRead(
        id=target.id,
        organization_id=target.organization_id,
        name=target.name,
        environment=target.environment,
        kind=target.kind,
        base_url=target.base_url,
        adapter_kind=target.adapter_kind,
        code_repo_ref=target.code_repo_ref,
        code_languages=[str(item) for item in (target.code_languages or [])],
        code_build_manifest_paths=[str(item) for item in (target.code_build_manifest_paths or [])],
        adapter_config=dict(target.adapter_config or {}),
        declared_tools=list(target.declared_tools or []),
        runtime_protection=[
            dict(item) for item in (target.runtime_protection or []) if isinstance(item, dict)
        ],
        has_authorization=target.authorization is not None,
        has_rules_of_engagement=target.rules_of_engagement is not None,
        created_at=target.created_at,
    )
