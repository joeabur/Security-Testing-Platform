"""agent provider IP allowlist

Revision ID: b6f1d84a2c19  # pragma: allowlist secret
Revises: a8d4e1c93f76  # pragma: allowlist secret
Create Date: 2026-09-29

`agent_providers.allowed_ip_ranges` mirrors `RulesOfEngagement.allowed_ip_ranges`
(app/core/scope/models.py): `GatedTransport` blocks loopback/RFC1918 ranges
unless explicitly listed, and a self-hosted `openai_compatible` endpoint
(Ollama, vLLM, llama.cpp) almost always lives at exactly such an address.
Without this column, the local/free provider path the model already
supports (`AgentProviderKind.OPENAI_COMPATIBLE`) was unreachable in
practice: `platform_egress_context` had no way to authorize the private
address a local model server actually runs at.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b6f1d84a2c19"  # pragma: allowlist secret
down_revision: str | None = "a8d4e1c93f76"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_providers",
        sa.Column("allowed_ip_ranges", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.alter_column("agent_providers", "allowed_ip_ranges", server_default=None)


def downgrade() -> None:
    op.drop_column("agent_providers", "allowed_ip_ranges")
