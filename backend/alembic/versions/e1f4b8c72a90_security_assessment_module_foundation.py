"""security assessment module foundation

Revision ID: e1f4b8c72a90  # pragma: allowlist secret
Revises: c3f8a2e91b4d  # pragma: allowlist secret
Create Date: 2026-09-29

Phase 1 of the security-assessment-and-pentest module (see
`docs/roadmap.md` and the plan this session recorded). Four things land
here, all schema/scaffolding with no engine behaviour yet:

* `target_kind_enum` gains `CONTAINER`, `CLOUD_ACCOUNT`, `VIRTUAL_MACHINE`,
  `DOMAIN` — uppercase, the same gotcha `c3f8a2e91b4d` documents at length
  (`sa.Enum` stores each member's `.name`, not `.value`).
* `rules_of_engagement.asset_scope` — one generalized JSON column for what
  any of those four target kinds' engine may touch, rather than one column
  per kind. Each engine validates its own sub-shape out of it (mirrors how
  `code_scope` already works for `CODE_REPO` targets).
* `discovered_assets` — things a scan turns up incidentally (a subdomain, a
  cloud resource, a container image, an open service) that are not
  themselves authorized `Target`s. Promotion to a real `Target` is a
  separate, explicit human action (`promoted_to_target_id`), never
  automatic — the mechanism behind "never automatically expand testing to
  targets outside the approved scope."
* `run_tool_invocations` — one row per subprocess any engine (existing or
  new) launches, so "exactly which tools, tests, and checks were executed"
  has a real, queryable answer platform-wide, not just for the new asset
  types.

Both new tables carry a direct `organization_id` column and join the
existing tenant-isolation RLS policy (`b2e6f4a91c7d`'s pattern), in this
same migration rather than a follow-up — a new table with no RLS policy
would be the exact gap that migration's own docstring warns against.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e1f4b8c72a90"  # pragma: allowlist secret
down_revision: str | None = "c3f8a2e91b4d"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same predicate `b2e6f4a91c7d` uses for every RLS-covered table — reused
# verbatim rather than redefined, so the two new tables fail closed exactly
# the way the original fourteen do.
_POLICY_USING = "organization_id = NULLIF(current_setting('aegis.org_id', true), '')::uuid"
_NEW_RLS_TABLES = ("discovered_assets", "run_tool_invocations")


def upgrade() -> None:
    op.execute("ALTER TYPE target_kind_enum ADD VALUE IF NOT EXISTS 'CONTAINER'")
    op.execute("ALTER TYPE target_kind_enum ADD VALUE IF NOT EXISTS 'CLOUD_ACCOUNT'")
    op.execute("ALTER TYPE target_kind_enum ADD VALUE IF NOT EXISTS 'VIRTUAL_MACHINE'")
    op.execute("ALTER TYPE target_kind_enum ADD VALUE IF NOT EXISTS 'DOMAIN'")

    op.add_column("rules_of_engagement", sa.Column("asset_scope", sa.JSON(), nullable=True))

    op.create_table(
        "discovered_assets",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("parent_target_id", sa.UUID(), nullable=False),
        sa.Column(
            "asset_kind",
            sa.Enum(
                "SUBDOMAIN",
                "CLOUD_RESOURCE",
                "CONTAINER_IMAGE",
                "OPEN_SERVICE",
                name="asset_kind_enum",
            ),
            nullable=False,
        ),
        sa.Column("identifier", sa.String(length=2048), nullable=False),
        sa.Column("asset_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("risk_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("promoted_to_target_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["promoted_to_target_id"], ["targets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.alter_column("discovered_assets", "asset_metadata", server_default=None)
    op.alter_column("discovered_assets", "risk_summary", server_default=None)

    op.create_table(
        "run_tool_invocations",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("tool_version", sa.String(length=120), nullable=True),
        sa.Column("network_use", sa.String(length=30), nullable=False),
        sa.Column("command_summary", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_status", sa.Integer(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["assessment_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    for table in _NEW_RLS_TABLES:
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                f"USING ({_POLICY_USING}) WITH CHECK ({_POLICY_USING})"
            )
        )


def downgrade() -> None:
    for table in _NEW_RLS_TABLES:
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
        op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))

    op.drop_table("run_tool_invocations")
    op.drop_table("discovered_assets")
    sa.Enum(name="asset_kind_enum").drop(op.get_bind(), checkfirst=True)

    op.drop_column("rules_of_engagement", "asset_scope")

    # Postgres cannot drop a single enum label — same no-op trade every
    # other enum-widening migration in this project already makes.
