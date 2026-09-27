import enum
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.api_spec import ApiSpec
    from app.models.authorization import Authorization
    from app.models.rules_of_engagement import RulesOfEngagementRecord
    from app.models.surface_endpoint import SurfaceEndpoint
    from app.models.synthetic_account import SyntheticAccount


class TargetEnvironment(enum.StrEnum):
    STAGING = "staging"
    TEST = "test"
    DEV = "dev"
    PRODUCTION = "production"


class TargetKind(enum.StrEnum):
    LLM_APP = "llm_app"
    AGENT = "agent"
    RAG = "rag"
    API = "api"
    MCP_SERVER = "mcp_server"
    MODEL_ENDPOINT = "model_endpoint"
    # Added by Addendum v2.1 §4.2 for classic DAST targets: a web application
    # with no AI layer, tested by crawling and by third-party scanners.
    WEB_APP = "web_app"
    # A source-code repository with no live network surface at all — the
    # "add a repository" flow (app/core/repositories/service.py). Deliberately
    # its own kind rather than reusing WEB_APP: `app/workers/tasks.py` builds
    # a `DastCheck` for every `WEB_APP` target, and a repository has no
    # `base_url` to crawl. A `CODE_REPO` target gets no reachability probe,
    # no DAST, no AI check — only the AppSec engines, over its checkout.
    CODE_REPO = "code_repo"


class Target(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """The technical description of what is being tested
    (docs/BUILD_SPEC.md §5.1 "Target"/"Asset").

    Phase 2 keeps this to the fields the scope engine needs (a name and a
    base URL to seed scope checks against). The richer per-adapter
    configuration (`adapters: [...]` in §5.1 — chat_http templates, OpenAPI
    spec refs, credential references) lands with the adapter layer in
    Phase 3.
    """

    __tablename__ = "targets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    environment: Mapped[TargetEnvironment] = mapped_column(
        Enum(TargetEnvironment, name="target_environment_enum"), nullable=False
    )
    kind: Mapped[TargetKind] = mapped_column(
        Enum(TargetKind, name="target_kind_enum"), nullable=False
    )
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Conversational adapter configuration (docs/BUILD_SPEC.md §8): which
    # adapter speaks to this target and how. Absent means the target has no
    # chat surface, so the AI engine declines rather than guessing one.
    adapter_kind: Mapped[str | None] = mapped_column(String(50), nullable=True)
    adapter_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # Tools the operator declared for an agentic target. §9 is explicit that
    # a tool surface is never inferred, so an empty list means "not
    # declared" and the agency probe says so.
    declared_tools: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    # Source-code surface (Addendum v2.1 §3). Absent means the SAST, SCA,
    # secrets-in-source and IaC engines refuse to run — the same fail-closed
    # rule the scope engine applies to a URL, applied to a checkout.
    #: What the operator CLAIMS is deployed in front of this target, in the
    #: shape `app/core/rasp/contract.py` defines. A claim, never a measurement:
    #: nothing on this platform tests runtime protection, and the `evidenced`
    #: field on each entry keeps that visible in the data rather than in a
    #: comment (docs/BUILD_SPEC.md §5.1, §26 Phase 18).
    runtime_protection: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    code_repo_ref: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    code_languages: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    code_build_manifest_paths: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    authorization: Mapped["Authorization | None"] = relationship(
        back_populates="target", uselist=False, cascade="all, delete-orphan"
    )
    rules_of_engagement: Mapped["RulesOfEngagementRecord | None"] = relationship(
        back_populates="target", uselist=False, cascade="all, delete-orphan"
    )
    api_spec: Mapped["ApiSpec | None"] = relationship(
        back_populates="target", uselist=False, cascade="all, delete-orphan"
    )
    surface_endpoints: Mapped[list["SurfaceEndpoint"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    synthetic_accounts: Mapped[list["SyntheticAccount"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
