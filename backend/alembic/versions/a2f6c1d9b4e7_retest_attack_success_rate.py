"""retest attack success rate

Revision ID: a2f6c1d9b4e7  # pragma: allowlist secret
Revises: b4d7f29a6e81  # pragma: allowlist secret
Create Date: 2026-10-04

A retest's verdict was presence/absence by fingerprint only, even though
`Finding.attack_success_rate` already carries a real Wilson-interval
measurement for any finding whose probe ran under the trial driver.
Adds `before_attack_success_rate`/`after_attack_success_rate` to
`retest_results`, the same before/after pair already kept for evidence
refs, so `app.core.measure.asr.asr_delta` has real numbers to compare.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a2f6c1d9b4e7"  # pragma: allowlist secret
down_revision: str | None = "b4d7f29a6e81"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "retest_results", sa.Column("before_attack_success_rate", sa.JSON(), nullable=True)
    )
    op.add_column(
        "retest_results", sa.Column("after_attack_success_rate", sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("retest_results", "after_attack_success_rate")
    op.drop_column("retest_results", "before_attack_success_rate")
