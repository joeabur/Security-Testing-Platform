"""workflow automation

Revision ID: 822b11ffe07c
Revises: d8b3f6a1c2e4
Create Date: 2026-09-29 06:16:01.425118
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "822b11ffe07c"
down_revision: str | None = "d8b3f6a1c2e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "workflows", sa.Column("schedule_interval_minutes", sa.Integer(), nullable=True)
    )
    op.add_column(
        "workflows", sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True)
    )
    # NOT NULL on a populated table: create with a default to backfill,
    # then drop it so a future missing value is an error, not a silent
    # empty — the same two-step every earlier boolean-column migration here
    # uses.
    op.add_column(
        "workflows",
        sa.Column("webhook_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("workflows", "webhook_enabled", server_default=None)
    op.add_column(
        "workflows", sa.Column("webhook_secret_encrypted", sa.LargeBinary(), nullable=True)
    )

    op.add_column(
        "workflow_runs", sa.Column("approved_by_user_id", sa.UUID(), nullable=True)
    )
    op.add_column(
        "workflow_runs", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_foreign_key(
        "fk_workflow_runs_approved_by_user_id",
        "workflow_runs",
        "users",
        ["approved_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_workflow_runs_approved_by_user_id", "workflow_runs", type_="foreignkey")
    op.drop_column("workflow_runs", "approved_at")
    op.drop_column("workflow_runs", "approved_by_user_id")

    op.drop_column("workflows", "webhook_secret_encrypted")
    op.drop_column("workflows", "webhook_enabled")
    op.drop_column("workflows", "next_run_at")
    op.drop_column("workflows", "schedule_interval_minutes")
