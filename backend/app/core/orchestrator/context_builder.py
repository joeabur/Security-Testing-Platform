"""The one seam where a persisted `Target` (SQLAlchemy) meets the
DB-independent `RunContext` the scope engine operates on.

Kept out of `app/core/scope/` deliberately: every file in that package is
free of any SQLAlchemy/DB import, which is exactly what makes it trivially
unit-testable (docs/BUILD_SPEC.md §6, §22). This module is the bridge, not
part of the pure engine.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path

from app.core.appsec.workspace import (
    DEFAULT_MAX_REPO_SIZE_MB,
    CodeScope,
    CodeScopeError,
    Workspace,
    resolve_workspace,
)
from app.core.discovery.openapi import (
    DiscoveredBodyField,
    DiscoveredOperation,
    DiscoveredParameter,
)
from app.core.probes.ai.contract import AiProbeTarget, DeclaredTool
from app.core.probes.credentials import AuthorizationTestPlan, CredentialSet, SyntheticAccount
from app.core.probes.protocol import ProbeTarget
from app.core.scope.budgets import BudgetTracker
from app.core.scope.context import RunContext
from app.core.scope.errors import RoEValidationError
from app.core.scope.kill_switch import KillSwitch
from app.core.scope.models import ResolvedAuthorization
from app.core.scope.resolve import resolve_authorization, resolve_rules_of_engagement
from app.core.scope.transport import GatedTransport
from app.core.targets.chat_http import ChatHttpAdapter, ChatHttpConfig
from app.core.targets.openai_compatible import OpenAiCompatibleAdapter, OpenAiCompatibleConfig
from app.core.targets.protocol import ConversationalAdapter
from app.models.surface_endpoint import SurfaceEndpoint
from app.models.synthetic_account import SyntheticAccount as SyntheticAccountRecord
from app.models.target import Target


def build_run_context(target: Target) -> RunContext:
    """Resolve `target.authorization` and `target.rules_of_engagement` into
    a fresh `RunContext`. Raises `AuthorizationRequiredError` or
    `RoEValidationError` if either is missing or invalid — the same
    fail-closed refusal the scope engine itself enforces, just one step
    earlier, before any `RunContext` even exists.
    """
    authorization = resolve_authorization(
        ResolvedAuthorization(
            valid_from=target.authorization.valid_from,
            valid_until=target.authorization.valid_until,
        )
        if target.authorization is not None
        else None
    )

    if target.rules_of_engagement is None:
        raise RoEValidationError("No Rules of Engagement are configured for this target.")

    roe_row = target.rules_of_engagement
    roe = resolve_rules_of_engagement(
        {
            "allowed_domains": roe_row.allowed_domains,
            "excluded_domains": roe_row.excluded_domains,
            "allowed_ip_ranges": roe_row.allowed_ip_ranges,
            "allowed_paths": roe_row.allowed_paths,
            "excluded_paths": roe_row.excluded_paths,
            "allowed_methods": roe_row.allowed_methods,
            "forbidden_headers": roe_row.forbidden_headers,
            "budgets": roe_row.budgets,
            "safe_mode": roe_row.safe_mode,
            "allow_state_mutation": roe_row.allow_state_mutation,
            "blackout_windows": roe_row.blackout_windows,
        }
    )

    return RunContext(
        roe=roe,
        authorization=authorization,
        budgets=BudgetTracker(roe.budgets),
        kill_switch=KillSwitch(),
    )


def build_probe_target(
    target: Target,
    endpoints: "Sequence[SurfaceEndpoint]",
    accounts: "Sequence[SyntheticAccountRecord]",
    *,
    safe_mode: bool,
    environ: "Mapping[str, str] | None" = None,
) -> ProbeTarget:
    """Turn persisted surface and account rows into what a probe may see.

    Only enabled endpoints are passed through: disabling an endpoint is an
    operator's instruction about what not to touch, and a probe should not
    be able to see — let alone request — something that was excluded.

    Credentials are resolved from the worker's environment here and nowhere
    else. The database supplies only variable *names* (§2), so this is the
    single point where a secret enters the process, and it goes straight
    into a `CredentialSet` that exposes it only as a request header.
    """
    return ProbeTarget(
        base_url=target.base_url,
        operations=tuple(_operation_from_row(row) for row in endpoints if row.enabled),
        safe_mode=safe_mode,
        authorization=_authorization_plan(accounts, environ),
    )


def _operation_from_row(row: "SurfaceEndpoint") -> DiscoveredOperation:
    return DiscoveredOperation(
        method=row.method,
        path=row.path,
        operation_id=row.operation_id,
        summary=row.summary,
        parameters=tuple(
            DiscoveredParameter(
                name=str(parameter.get("name", "")),
                location=str(parameter.get("in", "query")),
                required=bool(parameter.get("required", False)),
                schema_type=parameter.get("type"),
            )
            for parameter in row.parameters
            if isinstance(parameter, dict)
        ),
        request_body_content_types=tuple(row.request_body_content_types),
        body_fields=tuple(
            DiscoveredBodyField(
                name=str(field.get("name", "")),
                schema_type=field.get("type"),
                required=bool(field.get("required", False)),
                read_only=bool(field.get("read_only", False)),
                enum_values=tuple(str(value) for value in field.get("enum", []) or []),
                minimum=field.get("minimum"),
                maximum=field.get("maximum"),
                max_length=field.get("max_length"),
            )
            for field in row.body_fields
            if isinstance(field, dict)
        ),
        body_required=row.body_required,
        security_schemes=tuple(row.security_schemes),
        requires_auth=row.requires_auth,
    )


def _authorization_plan(
    accounts: "Sequence[SyntheticAccountRecord]", environ: "Mapping[str, str] | None"
) -> AuthorizationTestPlan:
    declared = tuple(
        SyntheticAccount(
            label=row.label,
            credential_env_var=row.credential_env_var,
            header_name=row.header_name,
            value_template=row.value_template,
            owned_object_ids=tuple(str(value) for value in row.owned_object_ids),
            is_privileged=row.is_privileged,
        )
        for row in accounts
    )
    return AuthorizationTestPlan(
        accounts=declared,
        credentials=CredentialSet.from_environment(declared, environ),
    )


def build_conversational_adapter(
    target: Target, transport: "GatedTransport"
) -> "ConversationalAdapter | None":
    """The adapter for this target's chat surface, or `None`.

    `None` means the operator did not configure one, and the AI engine then
    declines rather than guessing an endpoint and a wire format. A guessed
    adapter would send adversarial prompts at a URL nobody authorized in
    that shape.
    """
    kind = (target.adapter_kind or "").strip().lower()
    if not kind:
        return None

    config = dict(target.adapter_config or {})
    config.setdefault("base_url", target.base_url)

    if kind == "chat_http":
        return ChatHttpAdapter(ChatHttpConfig(**config), transport)
    if kind == "openai_compatible":
        return OpenAiCompatibleAdapter(OpenAiCompatibleConfig(**config), transport)
    raise ValueError(f"unknown adapter kind {target.adapter_kind!r}")


def build_ai_probe_target(
    target: Target,
    *,
    safe_mode: bool,
    trials: int | None = None,
    accounts: "Sequence[SyntheticAccountRecord]" = (),
    environ: "Mapping[str, str] | None" = None,
) -> AiProbeTarget:
    """The AI engine's view of the target, including its declared tools.

    `accounts` reuses the exact same `SyntheticAccountRecord` rows and
    `_authorization_plan` resolution `build_probe_target` already uses for
    the REST authorization probes, so cross-identity AI probes
    (app/core/probes/ai/cross_identity/) see the identical set of
    operator-declared test accounts the BOLA probe does.
    """
    return AiProbeTarget(
        name=target.name,
        surface=f"{(target.adapter_kind or 'chat').upper()} {target.base_url}",
        safe_mode=safe_mode,
        declared_tools=tuple(
            DeclaredTool(
                name=str(tool.get("name", "")),
                description=str(tool.get("description", "")),
                writes=bool(tool.get("writes", False)),
                irreversible=bool(tool.get("irreversible", False)),
                external=bool(tool.get("external", False)),
                requires_confirmation=bool(tool.get("requires_confirmation", False)),
            )
            for tool in (target.declared_tools or [])
            if isinstance(tool, dict) and tool.get("name")
        ),
        trials=trials,
        authorization=_authorization_plan(accounts, environ),
    )


def build_workspace(target: Target, checkout: "Path") -> "Workspace":
    """Resolve a target's declared code scope against a local checkout.

    Raises `CodeScopeError` when the Rules of Engagement carry no
    `code_scope`. That is the same fail-closed refusal §6.2 applies to an
    unresolved URL scope: a checkout with no stated boundary may contain a
    second project, or a developer's credentials, and "everything" is never
    the safe reading of silence.
    """
    roe = target.rules_of_engagement
    raw = dict(roe.code_scope or {}) if roe is not None else {}
    if not raw:
        raise CodeScopeError(
            "No code_scope is configured for this target. Declare which paths may be "
            "scanned before running the SAST, SCA, secrets or IaC engines."
        )

    scope = CodeScope(
        allowed_paths=tuple(str(item) for item in raw.get("allowed_paths", [])),
        excluded_paths=tuple(str(item) for item in raw.get("excluded_paths", [])),
        max_repo_size_mb=int(raw.get("max_repo_size_mb", DEFAULT_MAX_REPO_SIZE_MB)),
        allowed_repo_hosts=tuple(str(item) for item in raw.get("allowed_repo_hosts", [])),
    )
    return resolve_workspace(
        checkout,
        scope,
        languages=tuple(str(item) for item in (target.code_languages or [])),
        build_manifest_paths=tuple(str(item) for item in (target.code_build_manifest_paths or [])),
    )
