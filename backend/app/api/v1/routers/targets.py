import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.audit.service import record_event
from app.auth.dependencies import DbSession, require_membership
from app.core.orchestrator.context_builder import build_run_context
from app.core.rasp.contract import ClaimedControl, RuntimeProtectionProfile
from app.core.scope.asset_scope import resolve_domain_scope
from app.core.scope.dns import DnsResolver, SystemDnsResolver
from app.core.scope.engine import ScopeEngine
from app.core.scope.errors import (
    AssetScopeValidationError,
    AuthorizationRequiredError,
    RoEValidationError,
)
from app.core.scope.resolve import resolve_rules_of_engagement
from app.core.targets.chat_http import ChatHttpConfig
from app.core.targets.openai_compatible import OpenAiCompatibleConfig
from app.models.authorization import Authorization
from app.models.organization import Membership, Role
from app.models.rules_of_engagement import RulesOfEngagementRecord
from app.models.target import Target, TargetKind
from app.schemas.authorization import AuthorizationGrant, AuthorizationRead
from app.schemas.scope import (
    RulesOfEngagementRead,
    ScopeExplainRequest,
    ScopeExplainResponse,
)
from app.schemas.target import (
    DomainScopeIn,
    TargetAdapterUpdate,
    TargetCodeUpdate,
    TargetCreate,
    TargetRead,
    TargetRuntimeProtectionUpdate,
    target_read,
)

router = APIRouter(prefix="/organizations/{organization_id}/targets", tags=["targets"])

_engine = ScopeEngine()


def get_dns_resolver() -> DnsResolver:
    """A FastAPI dependency (not a hardcoded module-level singleton)
    specifically so tests can override it with a fake resolver — real DNS
    lookups for synthetic test hostnames like `ai.example.test` would
    otherwise fail or hit the network."""
    return SystemDnsResolver()


async def load_target(organization_id: uuid.UUID, target_id: uuid.UUID, db: DbSession) -> Target:
    result = await db.execute(
        select(Target)
        .where(Target.id == target_id, Target.organization_id == organization_id)
        .options(
            selectinload(Target.authorization),
            selectinload(Target.rules_of_engagement),
            selectinload(Target.api_spec),
        )
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    organization_id: uuid.UUID,
    payload: TargetCreate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> TargetRead:
    target = Target(
        organization_id=organization_id,
        name=payload.name,
        environment=payload.environment,
        kind=payload.kind,
        base_url=payload.base_url,
        created_by_user_id=membership.user_id,
    )
    # A freshly created row has no authorization/RoE yet, but SQLAlchemy
    # still treats those relationships as "unloaded" on a persistent
    # object rather than inferring that from the empty constructor call —
    # accessing them without this would trigger a lazy-load, which fails
    # under async SQLAlchemy (MissingGreenlet) outside an awaited context.
    target.authorization = None
    target.rules_of_engagement = None
    db.add(target)
    await db.flush()

    await record_event(
        db,
        action="target.create",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"name": target.name, "environment": target.environment.value},
    )
    await db.commit()

    return target_read(target)


@router.get("", response_model=list[TargetRead])
async def list_targets(
    organization_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> list[TargetRead]:
    result = await db.execute(
        select(Target)
        .where(Target.organization_id == organization_id)
        .options(selectinload(Target.authorization), selectinload(Target.rules_of_engagement))
        .order_by(Target.created_at)
    )
    return [target_read(t) for t in result.scalars().all()]


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> TargetRead:
    target = await load_target(organization_id, target_id, db)
    return target_read(target)


@router.put("/{target_id}/rules-of-engagement", response_model=RulesOfEngagementRead)
async def set_rules_of_engagement(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: dict[str, Any],
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> RulesOfEngagementRead:
    """Replaces the target's Rules of Engagement wholesale.

    Validated through the exact same `resolve_rules_of_engagement` the
    scope engine itself uses (docs/BUILD_SPEC.md §6.1 "RoE fails schema
    validation -> RUN REFUSED") before anything is persisted, so a bad
    document is rejected here rather than only discovered at run time.
    """
    target = await load_target(organization_id, target_id, db)

    try:
        roe = resolve_rules_of_engagement(payload)
    except RoEValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    budgets_dict = {
        "max_requests": roe.budgets.max_requests,
        "max_concurrency": roe.budgets.max_concurrency,
        "requests_per_second": roe.budgets.requests_per_second,
        "max_tokens_sent": roe.budgets.max_tokens_sent,
        "max_tokens_received": roe.budgets.max_tokens_received,
        "max_estimated_cost_usd": roe.budgets.max_estimated_cost_usd,
        "max_wall_clock_minutes": roe.budgets.max_wall_clock_minutes,
    }
    blackout_dicts = [
        {"starts_at": w.starts_at.isoformat(), "ends_at": w.ends_at.isoformat()}
        for w in roe.blackout_windows
    ]

    if target.rules_of_engagement is None:
        record = RulesOfEngagementRecord(target_id=target.id)
        db.add(record)
    else:
        record = target.rules_of_engagement

    record.allowed_domains = list(roe.allowed_domains)
    record.excluded_domains = list(roe.excluded_domains)
    record.allowed_ip_ranges = list(roe.allowed_ip_ranges)
    record.allowed_paths = list(roe.allowed_paths)
    record.excluded_paths = list(roe.excluded_paths)
    record.allowed_methods = list(roe.allowed_methods)
    record.forbidden_headers = list(roe.forbidden_headers)
    record.budgets = budgets_dict
    record.safe_mode = roe.safe_mode
    record.allow_state_mutation = roe.allow_state_mutation
    record.blackout_windows = blackout_dicts
    await db.flush()

    await record_event(
        db,
        action="target.rules_of_engagement.set",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return RulesOfEngagementRead.model_validate(record)


@router.get("/{target_id}/rules-of-engagement", response_model=RulesOfEngagementRead)
async def get_rules_of_engagement(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> RulesOfEngagementRead:
    target = await load_target(organization_id, target_id, db)
    if target.rules_of_engagement is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No Rules of Engagement configured")
    return RulesOfEngagementRead.model_validate(target.rules_of_engagement)


@router.post(
    "/{target_id}/authorization",
    response_model=AuthorizationRead,
    status_code=status.HTTP_201_CREATED,
)
async def grant_authorization(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: AuthorizationGrant,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> AuthorizationRead:
    """Only Owner/Admin may grant authorization (docs/BUILD_SPEC.md §17.2) —
    `require_membership(Role.ADMIN)` enforces exactly that. Granting a new
    authorization for a target replaces any existing one (§models/authorization.py).
    """
    target = await load_target(organization_id, target_id, db)

    if target.authorization is None:
        record = Authorization(target_id=target.id)
        db.add(record)
    else:
        record = target.authorization

    record.authorized_by_name = payload.authorized_by_name
    record.authorized_by_role = payload.authorized_by_role
    record.authorized_by_email = payload.authorized_by_email
    record.reference = payload.reference
    record.valid_from = payload.valid_from
    record.valid_until = payload.valid_until
    record.accepted_by_user_id = membership.user_id
    record.accepted_at = datetime.now(UTC)
    await db.flush()

    await record_event(
        db,
        action="target.authorization.grant",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={"reference": payload.reference},
    )
    await db.commit()

    return AuthorizationRead.model_validate(record)


@router.get("/{target_id}/authorization", response_model=AuthorizationRead)
async def get_authorization(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> AuthorizationRead:
    target = await load_target(organization_id, target_id, db)
    if target.authorization is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No authorization on file")
    return AuthorizationRead.model_validate(target.authorization)


@router.post("/{target_id}/scope/explain", response_model=ScopeExplainResponse)
async def explain_scope(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: ScopeExplainRequest,
    db: DbSession,
    dns_resolver: DnsResolver = Depends(get_dns_resolver),  # noqa: B008
    membership: Membership = Depends(require_membership(Role.VIEWER)),  # noqa: B008
) -> ScopeExplainResponse:
    """The dry-run preview: reports what decision a real request would get
    without sending anything or consuming any budget
    (docs/BUILD_SPEC.md §6.2, §18 `aegis-ai scope explain`).
    """
    target = await load_target(organization_id, target_id, db)

    try:
        ctx = build_run_context(target)
    except AuthorizationRequiredError as exc:
        return ScopeExplainResponse(allowed=False, rule="authorization_required", reason=str(exc))
    except RoEValidationError as exc:
        return ScopeExplainResponse(allowed=False, rule="roe_not_configured", reason=str(exc))

    decision = await _engine.explain(
        ctx,
        dns_resolver=dns_resolver,
        method=payload.method,
        url=payload.url,
        headers=payload.headers,
        estimated_tokens_sent=payload.estimated_tokens_sent,
        estimated_tokens_received=payload.estimated_tokens_received,
        estimated_cost_usd=payload.estimated_cost_usd,
    )
    return ScopeExplainResponse(
        allowed=decision.allowed, rule=decision.rule, reason=decision.reason
    )


@router.put("/{target_id}/adapter", response_model=TargetRead)
async def configure_adapter(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: TargetAdapterUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.SECURITY_ENGINEER)),  # noqa: B008
) -> TargetRead:
    """Configure the conversational adapter and declare the tool surface.

    The configuration is validated by constructing the adapter here rather
    than at scan time, so a bad response path or a missing prompt
    placeholder is a 422 now instead of a failed run later
    (docs/BUILD_SPEC.md §8).
    """
    target = await load_target(organization_id, target_id, db)

    config = dict(payload.adapter_config)
    config.setdefault("base_url", target.base_url)
    try:
        if payload.adapter_kind == "chat_http":
            ChatHttpConfig(**config)
        else:
            OpenAiCompatibleConfig(**config)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"invalid {payload.adapter_kind} configuration: {exc}",
        ) from exc

    target.adapter_kind = payload.adapter_kind
    target.adapter_config = config
    target.declared_tools = [tool.model_dump() for tool in payload.declared_tools]
    await db.flush()

    await record_event(
        db,
        action="target.adapter.configure",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "adapter_kind": payload.adapter_kind,
            "declared_tools": len(payload.declared_tools),
        },
    )
    await db.commit()

    return target_read(target)


@router.put("/{target_id}/code", response_model=TargetRead)
async def configure_code_scope(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: TargetCodeUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> TargetRead:
    """Declare the source-code surface and the paths that may be scanned.

    Admin-only, like the authorization grant: pointing an assessment at a
    repository asserts entitlement to read it. Rules of Engagement must
    already exist, because `code_scope` lives on them — the boundary is part
    of the engagement, not a property of the target
    (docs/BUILD_SPEC.md §4.5; Addendum v2.1 §3).
    """
    target = await load_target(organization_id, target_id, db)
    if target.rules_of_engagement is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                "Configure Rules of Engagement before declaring a code scope: the "
                "scope is part of the engagement."
            ),
        )

    target.code_repo_ref = payload.repo_ref
    target.code_languages = list(payload.languages)
    target.code_build_manifest_paths = list(payload.build_manifest_paths)
    target.rules_of_engagement.code_scope = {
        "allowed_paths": list(payload.code_scope.allowed_paths),
        "excluded_paths": list(payload.code_scope.excluded_paths),
        "max_repo_size_mb": payload.code_scope.max_repo_size_mb,
        "allowed_repo_hosts": list(payload.code_scope.allowed_repo_hosts),
    }
    await db.flush()

    await record_event(
        db,
        action="target.code_scope.configure",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "repo_ref": payload.repo_ref,
            "allowed_paths": len(payload.code_scope.allowed_paths),
            "excluded_paths": len(payload.code_scope.excluded_paths),
        },
    )
    await db.commit()

    return target_read(target)


@router.put("/{target_id}/domain-scope", response_model=TargetRead)
async def configure_domain_scope(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: DomainScopeIn,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> TargetRead:
    """Declare what a `DOMAIN` target's engine may enumerate and test.

    Admin-only, the same reasoning `configure_code_scope` documents: pointing
    an assessment at a domain asserts entitlement to test it. Rules of
    Engagement must already exist, because `asset_scope` lives on them — the
    boundary is part of the engagement, not a property of the target.
    """
    target = await load_target(organization_id, target_id, db)
    if target.kind is not TargetKind.DOMAIN:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"This target is registered as {target.kind.value!r}, not 'domain'.",
        )
    if target.rules_of_engagement is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                "Configure Rules of Engagement before declaring a domain scope: the "
                "scope is part of the engagement."
            ),
        )

    scope = {
        "root_domain": payload.root_domain,
        "allowed_subdomain_patterns": list(payload.allowed_subdomain_patterns),
    }
    # Validated through the same resolver the run pipeline uses, so a
    # malformed document is rejected here rather than silently stored and
    # only discovered when a run tries to use it.
    try:
        resolve_domain_scope(scope)
    except AssetScopeValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    target.rules_of_engagement.asset_scope = scope
    await db.flush()

    await record_event(
        db,
        action="target.domain_scope.configure",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        metadata={
            "root_domain": payload.root_domain,
            "allowed_subdomain_patterns": len(payload.allowed_subdomain_patterns),
        },
    )
    await db.commit()

    return target_read(target)


@router.put("/{target_id}/runtime-protection", response_model=TargetRead)
async def declare_runtime_protection(
    organization_id: uuid.UUID,
    target_id: uuid.UUID,
    payload: TargetRuntimeProtectionUpdate,
    request: Request,
    db: DbSession,
    membership: Membership = Depends(require_membership(Role.ADMIN)),  # noqa: B008
) -> TargetRead:
    """Record what the operator claims protects this target.

    Admin, because a declaration here changes how this target's findings read:
    an injection that succeeds against a target claiming a prompt firewall is a
    statement about that firewall. Someone accountable should be the one making
    the claim.

    **This endpoint stores a claim and measures nothing.** No engine on this
    platform tests runtime protection (docs/BUILD_SPEC.md §4.5 row 6), so every
    entry is stored as `evidenced: claimed` and a report over this target
    carries an explicit "not tested" line rather than letting the declaration
    read as a control that was verified.
    """
    target = await load_target(organization_id, target_id, db)

    # Built through the contract's own dataclass rather than assembled inline:
    # `ClaimedControl.__post_init__` is what refuses to mint anything but a
    # claim, and routing the write through it means the API cannot become a
    # second place that decides what "evidenced" may say.
    profile = RuntimeProtectionProfile(
        controls=tuple(
            ClaimedControl(
                kind=control.kind,
                vendor=control.vendor,
                telemetry_env_var=control.telemetry_env_var,
                notes=control.notes,
            )
            for control in payload.controls
        )
    )
    target.runtime_protection = profile.control_records()
    await db.flush()

    await record_event(
        db,
        action="target.runtime_protection.declare",
        resource_type="target",
        resource_id=str(target.id),
        result="allow",
        organization_id=organization_id,
        user_id=membership.user_id,
        ip_address=request.client.host if request.client else None,
        # Kinds and the variable NAME only. A vendor string is free text an
        # operator typed, and the audit log is not the place to find out it
        # contained something it should not have.
        metadata={
            "controls": [control.kind.value for control in payload.controls],
            "telemetry_env_vars": [
                control.telemetry_env_var
                for control in payload.controls
                if control.telemetry_env_var
            ],
        },
    )
    await db.commit()
    await db.refresh(target)
    return target_read(target)
