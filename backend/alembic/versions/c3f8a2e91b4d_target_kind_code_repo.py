"""target_kind_code_repo

Revision ID: c3f8a2e91b4d  # pragma: allowlist secret
Revises: b2e6f4a91c7d  # pragma: allowlist secret
Create Date: 2026-09-26

Adds `CODE_REPO` to `target_kind_enum` — the "add a repository" flow
(app/core/repositories/service.py) creates a `Target` of this kind, with no
`base_url` to crawl and no adapter to talk to. `app/workers/tasks.py` builds
a `DastCheck` only for `kind is TargetKind.WEB_APP` and an `AiSecurityCheck`
only when an adapter is configured, so a `CODE_REPO` target runs only the
AppSec engines over its checkout, exactly like the existing single-repo-per-
target code scan this flow builds on.

Also adds `WEB_APP`, which this same enum was missing — a genuine, separate
gap this migration happened to surface: `sa.Enum(TargetKind, name=...)`
stores each member's `.name` (`"WEB_APP"`, uppercase), not its `.value`
(`"web_app"`), and the migration that introduced `TargetKind.WEB_APP`
(Addendum v2.1 §4.2) never added it to the Postgres type — only to the
Python enum. Any database built by running the migrations in order (rather
than by `Base.metadata.create_all()`, which regenerates the type fresh from
the current Python enum every time and so never showed this) has never been
able to store a `web_app` target kind. Caught here by hitting the same class
of mistake for `CODE_REPO` first: this migration originally added it as
`'code_repo'` — lowercase, the enum member's `.value` — and inserting a
`Target` of that kind failed with `invalid input value for enum
target_kind_enum: "CODE_REPO"`, because the column was asking for the
uppercase name the same way `WEB_APP` needed to be.

`ADD VALUE` runs fine inside Alembic's transaction as long as the new label
is not also *used* in this same transaction — this migration only adds it.

Postgres has no `DROP VALUE` for an enum, so `downgrade` cannot cleanly
remove either label; it is a no-op, the same trade every other
enum-widening migration in this project already makes.
"""

from alembic import op

revision = "c3f8a2e91b4d"  # pragma: allowlist secret
down_revision = "b2e6f4a91c7d"  # pragma: allowlist secret
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE target_kind_enum ADD VALUE IF NOT EXISTS 'WEB_APP'")
    op.execute("ALTER TYPE target_kind_enum ADD VALUE IF NOT EXISTS 'CODE_REPO'")


def downgrade() -> None:
    # Postgres cannot drop a single enum label. Rolling back this migration
    # rolls back nothing; a deployment that needs either value gone would
    # have to recreate the type, which is destructive enough to require a
    # deliberate, hand-written migration rather than an automatic downgrade.
    pass
