"""rename rls session variable to kervy

Revision ID: e1d16423a6b1
Revises: 822b11ffe07c
Create Date: 2026-09-29 07:00:18.542301

The Aegis -> Kervy rebrand. Every `tenant_isolation` policy created so far
(across `b2e6f4a91c7d_row_level_security.py` and the four later migrations
that each added their own tenant-scoped table) reads a Postgres session
variable named `aegis.org_id` — a name baked into the policy's own SQL
text, so renaming it requires `ALTER POLICY`, not an edit to any of those
five historical migration files, which stay exactly as they were run.

`app/db/tenant_context.py` now sets `kervy.org_id` (`SET LOCAL`/
`set_config`), so this migration and that code change ship together: a
deployment that ran the old code against the new policy (or vice versa)
would see every RLS-covered query return nothing, the same fail-closed
behaviour an unset variable already produces — never another
organization's rows.

The table list is queried from `pg_policies` at migration-authoring time
rather than retyped from the five source migrations by hand, so it is the
actual current set, not a transcription of it.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e1d16423a6b1"
down_revision: str | None = "822b11ffe07c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Every table currently carrying the `tenant_isolation` policy (confirmed
# against `pg_policies` at authoring time — the full, current set of
# RLS-covered tables, not a transcription of any one earlier migration).
TABLES = (
    "agent_configurations",
    "agent_providers",
    "agent_tools",
    "agent_usage_metadata",
    "agents",
    "ai_drafts",
    "api_keys",
    "assessment_runs",
    "discovered_assets",
    "findings",
    "notification_channels",
    "notification_deliveries",
    "pull_request_posts",
    "remediation_tasks",
    "retest_results",
    "run_tool_invocations",
    "scan_results",
    "targets",
    "vcs_connections",
    "workflow_runs",
    "workflows",
)


def _using(session_var: str) -> str:
    return f"organization_id = NULLIF(current_setting('{session_var}', true), '')::uuid"


def upgrade() -> None:
    new_using = _using("kervy.org_id")
    for table in TABLES:
        op.execute(
            f'ALTER POLICY tenant_isolation ON "{table}" '
            f"USING ({new_using}) WITH CHECK ({new_using})"
        )


def downgrade() -> None:
    old_using = _using("aegis.org_id")
    for table in TABLES:
        op.execute(
            f'ALTER POLICY tenant_isolation ON "{table}" '
            f"USING ({old_using}) WITH CHECK ({old_using})"
        )
