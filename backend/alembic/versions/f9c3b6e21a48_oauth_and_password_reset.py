"""oauth identities and password reset tokens

Revision ID: f9c3b6e21a48  # pragma: allowlist secret
Revises: e1d16423a6b1  # pragma: allowlist secret
Create Date: 2026-09-29

Social OAuth login (Google, GitHub) and a self-service password reset flow.

`users.password_hash` becomes nullable: an account created by "Continue with
Google" has never set a local password, and storing an empty string or a
hash of a random value there would be a lie the column tells about itself.
`app/auth/security.py::verify_password` is never called against a null hash —
every caller checks for `None` first (`app/models/user.py`'s own docstring).

Neither new table gets an `organization_id` column or an RLS policy: both
are keyed by `user_id`, the same tier as `users` and `user_sessions`
(`docs/security-model.md` guarantee #26 — RLS covers tenant-scoped tables,
and a user's identity is not tenant data).
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f9c3b6e21a48"  # pragma: allowlist secret
down_revision: str | None = "e1d16423a6b1"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("users", "password_hash", existing_type=sa.String(length=255), nullable=True)

    op.create_table(
        "oauth_identities",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("email_at_link", sa.String(length=320), nullable=False),
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
        sa.UniqueConstraint("provider", "provider_user_id", name="uq_oauth_identity_subject"),
    )
    op.create_index("ix_oauth_identities_user_id", "oauth_identities", ["user_id"])

    op.create_table(
        "password_reset_tokens",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.UniqueConstraint("token_digest", name="uq_password_reset_tokens_digest"),
    )
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
    op.create_index(
        "ix_password_reset_tokens_token_digest", "password_reset_tokens", ["token_digest"]
    )


def downgrade() -> None:
    op.drop_index("ix_password_reset_tokens_token_digest", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_user_id", table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")

    op.drop_index("ix_oauth_identities_user_id", table_name="oauth_identities")
    op.drop_table("oauth_identities")

    op.alter_column("users", "password_hash", existing_type=sa.String(length=255), nullable=False)
