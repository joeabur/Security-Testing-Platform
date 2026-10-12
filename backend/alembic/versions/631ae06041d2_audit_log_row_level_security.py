"""audit log row level security

Revision ID: 631ae06041d2  # pragma: allowlist secret
Revises: fc7a77b3611c  # pragma: allowlist secret
Create Date: 2026-10-12

`b2e6f4a91c7d`'s own docstring named `audit_logs` as deliberately excluded
from Row-Level Security, not an oversight: `organization_id` is nullable
(platform-level events — login, register, logout, 2FA, forgot-password,
platform-owner grant/revoke — have none), which needs a null-aware policy
rather than the plain equality clause the other 23 tenant-scoped tables
use. This migration is that stated follow-up.

A plain reuse of the existing `organization_id = NULLIF(current_setting(
'kervy.org_id', true), '')::uuid` clause on `audit_logs` would break every
platform-level write outright: `current_setting('kervy.org_id', true)` is
unset (empty string) for those routes, since none of them call
`require_membership`/`set_tenant_context` — there is no org to scope them
to. `NULLIF('', '')::uuid` is `NULL`, and `organization_id = NULL` is never
true even when `organization_id` is itself `NULL`, so every platform-level
`INSERT` would be rejected by `WITH CHECK`, and every platform-level row
already in the table would vanish from `SELECT` under `USING`. Confirmed
live against a non-superuser, `FORCE`-owned role before writing the policy
below: the naive equality clause does exactly that.

The policy here instead treats "no org context" and "no org on the row"
as the one case they are — a session with an unset `kervy.org_id` sees and
may insert only rows with `organization_id IS NULL`; a session scoped to
an organization sees and may insert only that organization's own rows,
never the platform-level ones and never another organization's. Verified
live, against the same non-superuser `FORCE`-owned role:

- No org context, inserting `organization_id = NULL` — succeeds.
- Org A's context, inserting a row for org A — succeeds.
- Org A's context, inserting a row forged as org B — rejected.
- Org A's context, `SELECT` — returns only org A's rows, never the
  platform-level ones.
- No org context, `SELECT` — returns only the platform-level rows, never
  org A's.

As with `b2e6f4a91c7d`, `FORCE ROW LEVEL SECURITY` is required because the
runtime role in every deployment this project documents is this table's
owner, which Postgres otherwise exempts from its own table's policies; a
superuser is exempt unconditionally regardless of `FORCE`, with no
in-database mitigation, which is why the live verification above was done
as a dedicated non-superuser role rather than trusted from this project's
own `postgres`-superuser test suite.
"""

import sqlalchemy as sa

from alembic import op

revision = "631ae06041d2"  # pragma: allowlist secret
down_revision = "fc7a77b3611c"  # pragma: allowlist secret
branch_labels = None
depends_on = None

_TABLE = "audit_logs"
_POLICY = "tenant_isolation"

# A row with no organization_id is visible/insertable only to a session
# with no org context set; a row with an organization_id is visible/
# insertable only to a session scoped to that same organization.
_USING = (
    "(organization_id IS NULL "
    "AND NULLIF(current_setting('kervy.org_id', true), '') IS NULL) "
    "OR (organization_id IS NOT NULL "
    "AND organization_id = NULLIF(current_setting('kervy.org_id', true), '')::uuid)"
)
_WITH_CHECK = _USING


def upgrade() -> None:
    op.execute(sa.text(f'ALTER TABLE "{_TABLE}" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text(f'ALTER TABLE "{_TABLE}" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            f'CREATE POLICY {_POLICY} ON "{_TABLE}" USING ({_USING}) WITH CHECK ({_WITH_CHECK})'
        )
    )


def downgrade() -> None:
    op.execute(sa.text(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"'))
    op.execute(sa.text(f'ALTER TABLE "{_TABLE}" NO FORCE ROW LEVEL SECURITY'))
    op.execute(sa.text(f'ALTER TABLE "{_TABLE}" DISABLE ROW LEVEL SECURITY'))
