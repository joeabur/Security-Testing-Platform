"""agent framework foundation (Agent, AgentProvider)

Revision ID: f2a8c91e6b3d  # pragma: allowlist secret
Revises: e1f4b8c72a90  # pragma: allowlist secret
Create Date: 2026-09-28

Phase 1 of the native AI agent framework (see docs/roadmap.md and the plan
this session recorded). Two tables land here:

* `agent_providers` — an organization-configured AI provider the agent may
  call (Anthropic, OpenAI, Gemini, or an OpenAI-compatible/self-hosted
  endpoint). `api_key_env_var` is a variable NAME, never a secret value —
  identical discipline to every other credential reference in this
  codebase.
* `agents` — one row per organization: whether the agent is enabled here,
  its default provider, and its default autonomy mode.

Neither table, nor any table this subsystem will ever add, holds a
conversation, a prompt, a response, or tool output —
`tests/security/test_agent_boundary.py` pins the closed set of tables this
subsystem may create and grep-checks every column name.

Both join the existing tenant-isolation RLS policy in this same migration,
per the pattern `b2e6f4a91c7d`/`e1f4b8c72a90` already established.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f2a8c91e6b3d"  # pragma: allowlist secret
down_revision: str | None = "e1f4b8c72a90"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Same predicate every RLS-covered table in this codebase uses — reused
# verbatim rather than redefined.
_POLICY_USING = "organization_id = NULLIF(current_setting('aegis.org_id', true), '')::uuid"
_NEW_RLS_TABLES = ("agent_providers", "agents")


def upgrade() -> None:
    op.create_table(
        "agent_providers",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "ANTHROPIC",
                "OPENAI",
                "GEMINI",
                "OPENAI_COMPATIBLE",
                name="agent_provider_kind_enum",
            ),
            nullable=False,
        ),
        sa.Column("endpoint", sa.String(length=2048), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("api_key_env_var", sa.String(length=128), nullable=True),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
    )

    op.create_table(
        "agents",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("default_provider_id", sa.UUID(), nullable=True),
        sa.Column(
            "autonomy_mode",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'assist'"),
        ),
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
        sa.ForeignKeyConstraint(
            ["default_provider_id"], ["agent_providers.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", name="uq_agent_organization"),
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

    op.drop_table("agents")
    op.drop_table("agent_providers")
    sa.Enum(name="agent_provider_kind_enum").drop(op.get_bind(), checkfirst=True)
