"""siem channel fields

Revision ID: d4f8e2a91c73  # pragma: allowlist secret
Revises: a7c3f91e5d20  # pragma: allowlist secret
Create Date: 2026-10-02

Adds the columns `notification_channels` needs for three new `ChannelKind`
values (Pentest module's SIEM integration — Splunk HEC, Microsoft Sentinel,
generic CEF): `auth_token_env_var` for Splunk's HEC token, and five columns
for Sentinel's Logs Ingestion API (`sentinel_endpoint`, `azure_tenant_id`,
`azure_client_id`, `azure_client_secret_env_var`,
`sentinel_dcr_immutable_id`, `sentinel_stream_name`). All nullable: an
existing Slack/Teams/generic/email channel row has none of them.

Per `app/models/integration.py`'s own module docstring, only what is
genuinely a credential is held by env-var reference — `auth_token_env_var`
and `azure_client_secret_env_var`. The rest (a DCE endpoint URL with no
token in its path, a tenant id, a client id, a DCR id, a stream name) are
identifiers, not secrets, and are stored directly, the same way
`smtp_host` already is for the email channel.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d4f8e2a91c73"  # pragma: allowlist secret
down_revision: str | None = "a7c3f91e5d20"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "notification_channels",
        sa.Column("auth_token_env_var", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("sentinel_endpoint", sa.String(length=300), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("azure_tenant_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("azure_client_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("azure_client_secret_env_var", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("sentinel_dcr_immutable_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "notification_channels",
        sa.Column("sentinel_stream_name", sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("notification_channels", "sentinel_stream_name")
    op.drop_column("notification_channels", "sentinel_dcr_immutable_id")
    op.drop_column("notification_channels", "azure_client_secret_env_var")
    op.drop_column("notification_channels", "azure_client_id")
    op.drop_column("notification_channels", "azure_tenant_id")
    op.drop_column("notification_channels", "sentinel_endpoint")
    op.drop_column("notification_channels", "auth_token_env_var")
