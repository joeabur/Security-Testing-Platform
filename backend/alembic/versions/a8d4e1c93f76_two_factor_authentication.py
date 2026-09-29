"""two-factor authentication (TOTP)

Revision ID: a8d4e1c93f76
Revises: f9c3b6e21a48
Create Date: 2026-09-29

TOTP-based two-factor login. `users.totp_secret_encrypted` and
`users.totp_enabled` mirror `oauth_identities`/`password_reset_tokens`'
own tier: keyed by `user_id`/on `users` itself, no `organization_id`
column, no RLS policy — identity data, not tenant data.

`totp_recovery_codes` follows the same shape as `password_reset_tokens`:
a SHA-256 digest of a one-time value, never the plaintext.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a8d4e1c93f76"
down_revision: str | None = "f9c3b6e21a48"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.LargeBinary(), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("users", "totp_enabled", server_default=None)

    op.create_table(
        "totp_recovery_codes",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_digest", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_digest", name="uq_totp_recovery_codes_digest"),
    )
    op.create_index("ix_totp_recovery_codes_user_id", "totp_recovery_codes", ["user_id"])
    op.create_index("ix_totp_recovery_codes_code_digest", "totp_recovery_codes", ["code_digest"])


def downgrade() -> None:
    op.drop_index("ix_totp_recovery_codes_code_digest", table_name="totp_recovery_codes")
    op.drop_index("ix_totp_recovery_codes_user_id", table_name="totp_recovery_codes")
    op.drop_table("totp_recovery_codes")

    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret_encrypted")
