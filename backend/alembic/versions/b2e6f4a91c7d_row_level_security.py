"""row_level_security

Revision ID: b2e6f4a91c7d  # pragma: allowlist secret
Revises: a1c7e29f4d83  # pragma: allowlist secret
Create Date: 2026-09-25

Postgres Row-Level Security as a second, independent tenant-isolation
boundary behind the application's own `organization_id` filters
(app/db/tenant_context.py has the full design). This is defense in depth,
not a replacement: every tenant-scoped query already filters explicitly,
and RLS exists so a query that *forgot* that filter fails closed instead of
returning another organization's rows.

Scope: the 14 tables with a direct, non-nullable `organization_id` column.
Three tenant-adjacent tables are deliberately excluded, each for a stated
reason rather than an oversight:

- `memberships` — `GET /organizations` legitimately lists every
  organization a user belongs to, a genuine cross-organization query; a
  single-org equality policy here would break it.
- `organizations` — self-referential (its own primary key, not a foreign
  key to itself); no `organization_id` column to filter on.
- `audit_logs` — `organization_id` is nullable (platform-level events have
  none), which needs a null-aware policy rather than a plain equality one;
  left for a follow-up migration rather than folded in here.

**Operator requirement**: RLS is silently a no-op if the runtime database
role is a superuser, or owns these tables without `FORCE ROW LEVEL
SECURITY` (both exempt a role from RLS entirely, with no warning when they
do). `FORCE` is set below specifically to close the table-owner case, since
the runtime role in every deployment this project documents *is* the table
owner (it is the role the migrations themselves run as). The superuser
case has no in-database mitigation; `docs/deployment.md` states the
requirement that the runtime role must not be one.
"""

import sqlalchemy as sa

from alembic import op

revision = "b2e6f4a91c7d"  # pragma: allowlist secret
down_revision = "a1c7e29f4d83"  # pragma: allowlist secret
branch_labels = None
depends_on = None

TABLES = [
    "ai_drafts",
    "api_keys",
    "assessment_runs",
    "findings",
    "notification_channels",
    "notification_deliveries",
    "remediation_tasks",
    "retest_results",
    "scan_results",
    "targets",
    "vcs_connections",
    "pull_request_posts",
    "workflows",
    "workflow_runs",
]

# `current_setting('aegis.org_id', true)` — the `true` (missing_ok) argument
# means an unset GUC returns NULL rather than raising, so a connection that
# never called `set_config` (a stray script, a forgotten code path) gets a
# policy of `organization_id = NULL`, which matches no row, rather than an
# error that would be easy to work around by catching it.
POLICY_USING = (
    "organization_id = NULLIF(current_setting('aegis.org_id', true), '')::uuid"
)


def upgrade() -> None:
    for table in TABLES:
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                f"USING ({POLICY_USING}) WITH CHECK ({POLICY_USING})"
            )
        )


def downgrade() -> None:
    for table in TABLES:
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
        op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
