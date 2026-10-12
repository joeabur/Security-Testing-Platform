"""audit log append only enforcement

Revision ID: fc7a77b3611c  # pragma: allowlist secret
Revises: a2f6c1d9b4e7  # pragma: allowlist secret
Create Date: 2026-10-12

`app/models/audit.py`'s own docstring named this precisely: the
append-only invariant was enforced by never exposing an update/delete path
in `app.audit.service`, not by the database — a gap tracked in
`docs/roadmap.md` since Phase 1 (also named in `docs/configuration.md`,
`docs/deployment.md`, `docs/security-model.md` and `docs/threat-model.md`).

A `REVOKE` alone does not close it. The runtime database role in every
deployment this project documents *is* the table owner (the role the
migrations themselves run as) — the same fact `b2e6f4a91c7d`'s own
docstring already had to reckon with for Row-Level Security, where it
required `FORCE ROW LEVEL SECURITY` for exactly this reason. A table
owner's own `REVOKE` on their own table is not self-binding: Postgres
still lets the owner `GRANT` the privilege back to themselves at will, so
an owner-equals-runtime-role deployment gets no real protection from the
grant system alone. A trigger has no such escape hatch — it fires on
every `UPDATE`/`DELETE` attempt against the table regardless of who is
making it, table owner or not. (A session that explicitly sets
`session_replication_role = replica` — a superuser-only action a
deployment's own runtime role should never be granted — bypasses triggers
too, same as any other admin-level override; that is a deployment
permissions question, not something this migration can close from inside
the database.)

The `REVOKE` is kept anyway, as the cheap, zero-cost defense-in-depth
layer the docs already named — it costs an attacker (or a bug) one extra
step in deployments where the runtime role is *not* the table owner, even
though the trigger is what makes the guarantee real everywhere.
"""

import sqlalchemy as sa

from alembic import op

revision = "fc7a77b3611c"  # pragma: allowlist secret
down_revision = "a2f6c1d9b4e7"  # pragma: allowlist secret
branch_labels = None
depends_on = None

_FUNCTION_NAME = "audit_logs_block_mutation"
_TRIGGER_NAME = "audit_logs_append_only"


def upgrade() -> None:
    op.execute(
        sa.text(
            f"""
            CREATE FUNCTION {_FUNCTION_NAME}() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION
                    'audit_logs is append-only: % is not permitted', TG_OP;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            CREATE TRIGGER {_TRIGGER_NAME}
            BEFORE UPDATE OR DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION {_FUNCTION_NAME}()
            """
        )
    )
    op.execute(sa.text("REVOKE UPDATE, DELETE ON audit_logs FROM PUBLIC"))


def downgrade() -> None:
    op.execute(sa.text("GRANT UPDATE, DELETE ON audit_logs TO PUBLIC"))
    op.execute(sa.text(f"DROP TRIGGER IF EXISTS {_TRIGGER_NAME} ON audit_logs"))
    op.execute(sa.text(f"DROP FUNCTION IF EXISTS {_FUNCTION_NAME}()"))
