import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import expression

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.target import Target


class RulesOfEngagementRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """docs/BUILD_SPEC.md §5.3. One RoE per target, replaced wholesale on
    update (no partial-field PATCH) so there is never a moment where the
    persisted RoE is a half-applied mix of old and new rules — the exact
    hazard the scope engine exists to prevent elsewhere.
    """

    __tablename__ = "rules_of_engagement"

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    allowed_domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    excluded_domains: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_ip_ranges: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    excluded_paths: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_methods: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    forbidden_headers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    budgets: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    safe_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Separate from `safe_mode` on purpose: safe mode bounds how a probe
    # behaves, this decides whether state-changing tooling may run at all.
    # Default false, so a DAST run is non-destructive unless someone said
    # otherwise in writing.
    allow_state_mutation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=expression.false()
    )
    blackout_windows: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
    # Which paths inside a checkout may be read (Addendum v2.1 §3). An empty
    # allowlist is not "everything" — the code engines refuse to run until
    # the boundary is stated, exactly as §6.2 refuses an unresolved URL scope.
    code_scope: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # Kept separate from `budgets` because crawling a repository and calling a
    # model are not the same resource: one scanner run must not be able to
    # spend the token budget an AI assessment was granted.
    appsec_budgets: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # What a CONTAINER/CLOUD_ACCOUNT/VIRTUAL_MACHINE/DOMAIN target's engine
    # may touch — one generalized column rather than one per kind, so adding
    # a fifth asset type later is a new resolver function, not a new
    # migration. Each kind's engine validates its own sub-shape out of this
    # (app/core/scope/asset_scope.py) the same way CodeScanCheck validates
    # `code_scope` — absent or malformed means that engine declines to run,
    # never "everything is in scope."
    asset_scope: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="rules_of_engagement")
