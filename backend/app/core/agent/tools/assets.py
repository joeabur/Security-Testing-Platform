"""`search_assets` / `get_asset` — read-only tools over `Target`.

Each runs the exact query `GET /targets`/`GET /targets/{id}` already runs
and reuses `target_read()`, the same `Target` -> `TargetRead` conversion
the router uses — so a tool's answer can never diverge from what the same
organization's member would see calling the API themselves.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.agent.context import AgentContext
from app.core.agent.tools.contract import RiskLevel, Tool, ToolNotFoundError
from app.models.organization import Role
from app.models.target import Target
from app.schemas.target import TargetRead, target_read


class SearchAssetsParams(BaseModel):
    pass


class SearchAssetsResult(BaseModel):
    targets: list[TargetRead] = Field(default_factory=list)


async def _search_assets(ctx: AgentContext, params: SearchAssetsParams) -> SearchAssetsResult:
    result = await ctx.db.execute(
        select(Target)
        .where(Target.organization_id == ctx.organization_id)
        .options(selectinload(Target.authorization), selectinload(Target.rules_of_engagement))
        .order_by(Target.created_at)
    )
    return SearchAssetsResult(targets=[target_read(t) for t in result.scalars().all()])


SEARCH_ASSETS = Tool(
    name="search_assets",
    description="List every target (asset) in this organization.",
    input_model=SearchAssetsParams,
    output_model=SearchAssetsResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_search_assets,
    rate_limit_rule="agent_tool_call",
)


class GetAssetParams(BaseModel):
    target_id: uuid.UUID


class GetAssetResult(BaseModel):
    target: TargetRead


async def _get_asset(ctx: AgentContext, params: GetAssetParams) -> GetAssetResult:
    result = await ctx.db.execute(
        select(Target)
        .where(Target.id == params.target_id, Target.organization_id == ctx.organization_id)
        .options(selectinload(Target.authorization), selectinload(Target.rules_of_engagement))
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise ToolNotFoundError(f"target {params.target_id} not found")
    return GetAssetResult(target=target_read(target))


GET_ASSET = Tool(
    name="get_asset",
    description="Get one target (asset) by id.",
    input_model=GetAssetParams,
    output_model=GetAssetResult,
    risk_level=RiskLevel.READ_ONLY,
    minimum_role=Role.VIEWER,
    handler=_get_asset,
    rate_limit_rule="agent_tool_call",
)
