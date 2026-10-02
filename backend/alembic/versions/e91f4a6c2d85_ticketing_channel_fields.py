"""ticketing channel fields

Revision ID: e91f4a6c2d85  # pragma: allowlist secret
Revises: d4f8e2a91c73  # pragma: allowlist secret
Create Date: 2026-10-02

Adds the columns `notification_channels` needs for two new `ChannelKind`
values (external ticketing — Jira Cloud, ServiceNow): five Jira fields
(`jira_site`, `jira_email`, `jira_api_token_env_var`, `jira_project_key`,
`jira_issue_type`) and four ServiceNow fields (`servicenow_instance`,
`servicenow_table`, `servicenow_username`, `servicenow_password_env_var`).
All nullable: an existing Slack/Teams/generic/email channel row has none
of them.

Per `app/models/integration.py`'s own module docstring, only what is
genuinely a credential is held by env-var reference —
`jira_api_token_env_var` and `servicenow_password_env_var`. The rest (a
site label, an account email, a project key, an issue type name, an
instance label, a table name, a username) are identifiers, not secrets,
and are stored directly, the same way `smtp_host`/`smtp_username` already
are for the email channel.

Also adds `notification_deliveries.external_reference`: the ticket key or
number a ticketing adapter's creation call returned, so a delivery row
can be linked back to the record it created. Null for every delivery that
is not a ticket, and for a ticket delivery that never reached a 2xx.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e91f4a6c2d85"  # pragma: allowlist secret
down_revision: str | None = "d4f8e2a91c73"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "notification_channels",
        sa.Column("jira_site", sa.String(length=63), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("jira_email", sa.String(length=320), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("jira_api_token_env_var", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("jira_project_key", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("jira_issue_type", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("servicenow_instance", sa.String(length=63), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("servicenow_table", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("servicenow_username", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("servicenow_password_env_var", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "notification_deliveries",
        sa.Column("external_reference", sa.String(length=200), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("notification_deliveries", "external_reference")
    op.drop_column("notification_channels", "servicenow_password_env_var")
    op.drop_column("notification_channels", "servicenow_username")
    op.drop_column("notification_channels", "servicenow_table")
    op.drop_column("notification_channels", "servicenow_instance")
    op.drop_column("notification_channels", "jira_issue_type")
    op.drop_column("notification_channels", "jira_project_key")
    op.drop_column("notification_channels", "jira_api_token_env_var")
    op.drop_column("notification_channels", "jira_email")
    op.drop_column("notification_channels", "jira_site")
