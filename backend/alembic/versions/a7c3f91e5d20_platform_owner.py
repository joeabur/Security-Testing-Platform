"""platform owner

Revision ID: a7c3f91e5d20  # pragma: allowlist secret
Revises: c2e8b6f19a4d  # pragma: allowlist secret
Create Date: 2026-10-02

Every authorization decision in this codebase has been organization-scoped
since Phase 2's own foundation — `Role.OWNER` is the ceiling, but it is a
ceiling *within one organization*, enforced by `require_membership` reading
an `organization_id` path parameter (app/auth/dependencies.py). Nothing above
that has existed: no account with authority over the deployment itself
(platform-wide integration defaults, or granting/revoking another account
that authority).

`users.platform_role` adds exactly that, as a nullable column rather than a
new table: platform authority is opt-in per user, most users have none of
it, and the hierarchy this models allows a second, lower tier later (see
`app.models.user.PlatformRole`'s own docstring) without another migration —
only a new enum member. It is set by `backend/scripts/bootstrap_platform_owner.py`
once, at deployment setup, or by an existing platform owner through
`POST /platform/owners` — never inferred from a user's email or any other
request-time fact, which is the whole reason it needs to be a stored column
at all rather than a comparison in the authorization dependency.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "a7c3f91e5d20"  # pragma: allowlist secret
down_revision: str | None = "c2e8b6f19a4d"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # `create_table` creates an ENUM type it needs; `add_column` does not, so
    # the type is created explicitly here or the ALTER fails with
    # "type platform_role_enum does not exist".
    sa.Enum("OWNER", name="platform_role_enum").create(op.get_bind(), checkfirst=True)
    op.add_column(
        "users",
        sa.Column(
            "platform_role",
            postgresql.ENUM("OWNER", name="platform_role_enum", create_type=False),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "platform_role")
    sa.Enum(name="platform_role_enum").drop(op.get_bind(), checkfirst=True)
