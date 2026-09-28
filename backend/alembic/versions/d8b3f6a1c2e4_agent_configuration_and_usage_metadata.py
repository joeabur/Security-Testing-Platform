"""agent configuration and usage metadata (AgentConfiguration, AgentUsageMetadata)

Revision ID: d8b3f6a1c2e4  # pragma: allowlist secret
Revises: a3d7e05c1f92  # pragma: allowlist secret
Create Date: 2026-09-28

Phase 3 of the native AI agent framework. Two tables:

* `agent_configurations` — one row per `Agent`, holding its tool allowlist
  and per-tool rate-limit overrides as a small schema-validated JSON
  document. Configuration only, same relationship `Workflow.gate_config` has
  to the workflow engine.
* `agent_usage_metadata` — an append-only row per tool call: tool name,
  provider, model, token counts, cost, duration, status, error code. No
  content column exists on it, and `tests/security/test_agent_boundary.py`
  now column-allowlists this table specifically so one can never be added
  without a deliberate, reviewed edit.

Both are the last two tables in the agent subsystem's closed allowlist —
`Agent`, `AgentProvider`, `AgentTool` (Phases 1-2) plus these two complete
the set `docs/agent.md` (a later phase) documents in full. Joins the
existing tenant-isolation RLS policy, same as every prior agent migration.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d8b3f6a1c2e4"  # pragma: allowlist secret
down_revision: str | None = "a3d7e05c1f92"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY_USING = "organization_id = NULLIF(current_setting('aegis.org_id', true), '')::uuid"

_TABLES = ("agent_configurations", "agent_usage_metadata")


def upgrade() -> None:
    op.create_table(
        "agent_configurations",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.UUID(), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=False),
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
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", name="uq_agent_configuration_agent"),
    )

    op.create_table(
        "agent_usage_metadata",
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("agent_id", sa.UUID(), nullable=True),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("provider", sa.String(length=60), nullable=True),
        sa.Column("model", sa.String(length=200), nullable=True),
        sa.Column("tokens_sent", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("tokens_received", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("cost_usd", sa.Float(), nullable=False, server_default=sa.text("0")),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_code", sa.String(length=60), nullable=True),
        sa.Column("request_id", sa.String(length=80), nullable=False),
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
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    for table in _TABLES:
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                f"USING ({_POLICY_USING}) WITH CHECK ({_POLICY_USING})"
            )
        )


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
        op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
        op.drop_table(table)
