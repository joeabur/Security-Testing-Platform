"""agent tool registry (AgentTool)

Revision ID: a3d7e05c1f92  # pragma: allowlist secret
Revises: f2a8c91e6b3d  # pragma: allowlist secret
Create Date: 2026-09-28

Phase 2 of the native AI agent framework. One table:

* `agent_tools` — per-organization enable/disable (and, later, a tighter
  role requirement) for a tool the code registry
  (`app/core/agent/tools/registry.py`) defines. Code stays the source of
  truth for a tool's schema, risk level and logic; this table is
  configuration only.

Joins the existing tenant-isolation RLS policy in this same migration, and
extends `tests/security/test_agent_boundary.py`'s closed table-set pin —
still no conversation, prompt, response, or tool-output column anywhere.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a3d7e05c1f92"  # pragma: allowlist secret
down_revision: str | None = "f2a8c91e6b3d"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY_USING = "organization_id = NULLIF(current_setting('aegis.org_id', true), '')::uuid"


def upgrade() -> None:
    op.create_table(
        "agent_tools",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("minimum_role_override", sa.String(length=30), nullable=True),
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "tool_name", name="uq_agent_tool_org_name"),
    )

    op.execute(sa.text('ALTER TABLE "agent_tools" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "agent_tools" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "agent_tools" '
            f"USING ({_POLICY_USING}) WITH CHECK ({_POLICY_USING})"
        )
    )


def downgrade() -> None:
    op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "agent_tools"'))
    op.execute(sa.text('ALTER TABLE "agent_tools" NO FORCE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "agent_tools" DISABLE ROW LEVEL SECURITY'))
    op.drop_table("agent_tools")
