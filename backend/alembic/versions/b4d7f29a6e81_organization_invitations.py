"""organization invitations

Revision ID: b4d7f29a6e81  # pragma: allowlist secret
Revises: e91f4a6c2d85  # pragma: allowlist secret
Create Date: 2026-10-02

`organizations.py`'s `invite_member` has only ever been able to add an
*existing* user — email invitations for a not-yet-registered address were
deferred. `organization_invitations` closes that gap: one row per pending
invite, holding only the SHA-256 digest of its token (the plaintext lives
in the email and the accept URL, same as `password_reset_tokens`), the
invited email and role, and two independent terminal-state timestamps
(`used_at`, `revoked_at` — an admin can cancel an unused invite before it
expires, which `password_reset_tokens` never needed).

Joins the existing tenant-isolation RLS policy, same as every other
organization-scoped table.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b4d7f29a6e81"  # pragma: allowlist secret
down_revision: str | None = "e91f4a6c2d85"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY_USING = "organization_id = NULLIF(current_setting('kervy.org_id', true), '')::uuid"


def upgrade() -> None:
    op.create_table(
        "organization_invitations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column(
            "role",
            sa.Enum(
                "OWNER",
                "ADMIN",
                "SECURITY_ENGINEER",
                "ANALYST",
                "VIEWER",
                name="role_enum",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("invited_by_user_id", sa.UUID(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest"),
    )
    op.create_index(
        "ix_organization_invitations_email", "organization_invitations", ["email"]
    )
    op.create_index(
        "ix_organization_invitations_token_digest",
        "organization_invitations",
        ["token_digest"],
    )

    op.execute(sa.text('ALTER TABLE "organization_invitations" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "organization_invitations" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "organization_invitations" '
            f"USING ({_POLICY_USING}) WITH CHECK ({_POLICY_USING})"
        )
    )


def downgrade() -> None:
    op.drop_table("organization_invitations")
