"""finding duplicate link

Revision ID: c2e8b6f19a4d  # pragma: allowlist secret
Revises: f4a9c1d3e7b2  # pragma: allowlist secret
Create Date: 2026-09-30

Closes the "cross-engine deduplication" gap stated as deferred since the
findings service's own Phase 14/16 write-ups: a SAST finding and a DAST
finding describing the same underlying defect get different `probe_id`
prefixes and therefore different fingerprints, so they have always been
two separate `Finding` rows inflating counts. Rather than invent a
correlation heuristic — `docs/roadmap.md` is explicit that "faking a
correlation heuristic would be worse than the honest gap" — this adds a
human-verified link: an analyst may explicitly mark one finding as a
duplicate of another (see `app/core/findings/service.py::link_duplicate`),
and both the findings list and report generation exclude a marked
duplicate from their counts by default.

`duplicate_of_finding_id` is a nullable self-referential foreign key on
`findings`, `ondelete="SET NULL"` — deleting the primary finding a
duplicate points to un-links it rather than cascading, since a deleted
primary is not evidence the duplicate itself no longer exists.
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c2e8b6f19a4d"  # pragma: allowlist secret
down_revision: str | None = "f4a9c1d3e7b2"  # pragma: allowlist secret
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings", sa.Column("duplicate_of_finding_id", sa.UUID(), nullable=True)
    )
    op.add_column("findings", sa.Column("duplicate_note", sa.Text(), nullable=True))
    op.add_column(
        "findings", sa.Column("duplicate_linked_by_user_id", sa.UUID(), nullable=True)
    )
    op.add_column(
        "findings",
        sa.Column("duplicate_linked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "findings_duplicate_of_finding_id_fkey",
        "findings",
        "findings",
        ["duplicate_of_finding_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "findings_duplicate_linked_by_user_id_fkey",
        "findings",
        "users",
        ["duplicate_linked_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_findings_duplicate_of_finding_id", "findings", ["duplicate_of_finding_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_findings_duplicate_of_finding_id", table_name="findings")
    op.drop_constraint(
        "findings_duplicate_linked_by_user_id_fkey", "findings", type_="foreignkey"
    )
    op.drop_constraint("findings_duplicate_of_finding_id_fkey", "findings", type_="foreignkey")
    op.drop_column("findings", "duplicate_linked_at")
    op.drop_column("findings", "duplicate_linked_by_user_id")
    op.drop_column("findings", "duplicate_note")
    op.drop_column("findings", "duplicate_of_finding_id")
