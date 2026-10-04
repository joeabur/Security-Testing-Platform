"""Database-level tenant isolation: Postgres Row-Level Security as a second,
independent boundary behind the application's own `organization_id` filters.

**This is defense in depth, not a replacement.** Every tenant-scoped query in
`app/api` and `app/workers` already filters by `organization_id` explicitly,
and that filtering is what the tenant-isolation tests assert on
(`docs/security-model.md` guarantee #12). RLS exists so that a query which
*forgot* that filter — the one bug class application-level filtering cannot
catch, because the missing line is invisible in a review — fails closed
instead of returning another organization's rows.

## How the current organization reaches Postgres

A Postgres RLS policy reads a *session-local* setting
(`current_setting('kervy.org_id', true)`), not an application variable — the
database has no idea what "the current request" is. The bridge is:

1. `set_tenant_context(db, org_id)` stores the id in a `ContextVar` *and*
   immediately issues `SET LOCAL` on `db`'s current transaction itself —
   called once per request (`require_membership`, the single dependency
   every organization-scoped route already goes through) or once per
   Celery task (`app.workers.tasks`, immediately after the run's own
   organization is loaded). The immediate `SET LOCAL` matters because by
   this point a transaction has nearly always already begun: identifying
   *who* is calling (`get_current_user`, which every route depends on
   before it can reach `require_membership`) itself queries the database,
   autobeginning this request's one transaction before this module's own
   "begin" event below ever had an organization id to read.
2. An SQLAlchemy `"begin"` event, registered on every engine this process
   creates, fires whenever a transaction actually starts on a connection —
   including the second and later transactions in a request that calls
   `db.commit()` mid-handler and keeps querying, which the naive "set it
   once at the top" approach would silently stop protecting. The listener
   reads the `ContextVar` and issues `SET LOCAL` on that transaction — this
   is what covers every transaction *after* the first one `set_tenant_context`
   already corrected directly.
3. `SET LOCAL` is transaction-scoped by Postgres itself: it is cleared by
   COMMIT and by ROLLBACK, which is also what SQLAlchemy's pool does to a
   connection before returning it to the pool. A connection handed to the
   next request never carries the previous request's organization forward —
   this is what makes reusing pooled connections across different tenants
   safe.

## Why this fails closed, not open

The policy an unset or wrong `kervy.org_id` produces is `organization_id =
NULL`, which matches no row. A code path that forgot to call
`set_current_organization` does not see another organization's data — it
sees nothing, and the resulting empty response is generally very quickly
noticed rather than silently wrong. That is what makes this checkable by
running the existing test suite unchanged: any test that unexpectedly gets
an empty result names the code path that needed the call added.

## The one thing that has to be true for this to do anything

Postgres exempts the table owner from `ROW LEVEL SECURITY` unless the table
also has `FORCE ROW LEVEL SECURITY` (`docs/deployment.md` migration adds
both), **and exempts superusers from RLS unconditionally, with no override**.
If the application's runtime database role is a superuser, or is the table
owner without `FORCE ROW LEVEL SECURITY`, every policy here is silently a
no-op — not an error, not a warning, a policy that is simply never
evaluated. `docs/deployment.md` states the operator requirement this
implies: the runtime role must be a plain, non-superuser role.
"""

from contextvars import ContextVar
from uuid import UUID

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

# One process, one "current organization for whichever request or task is
# running right now". A ContextVar rather than a plain module global because
# each request/task runs on its own asyncio Task, and a ContextVar is scoped
# per-Task the same way a thread-local would be scoped per-thread — two
# concurrent requests for two different organizations do not see each
# other's value.
_current_organization: ContextVar[str | None] = ContextVar(
    "kervy_current_organization", default=None
)


def set_current_organization(organization_id: UUID | str | None) -> None:
    """Record which organization the rest of this request/task acts as.

    Pass `None` to explicitly clear it — used where a code path is known to
    run outside any single organization's context (platform-level
    background work), so a stray RLS-scoped query there fails closed rather
    than silently reusing whatever the previous task happened to set.
    """
    _current_organization.set(str(organization_id) if organization_id is not None else None)


def get_current_organization() -> str | None:
    return _current_organization.get()


async def set_tenant_context(db: AsyncSession, organization_id: UUID | str | None) -> None:
    """Set the current organization, and assert it on `db`'s *already open*
    transaction, not just the next one `register_tenant_context_listener`
    happens to see begin.

    Every organization-scoped route depends on `get_current_user` before it
    reaches the point where its own organization id is even known (it has to
    — identity comes first) — and `get_current_user` queries the database.
    That query autobegins this request's one transaction, which means the
    "begin" event has already fired, and already asked Postgres for
    whatever `get_current_organization()` returned at that moment: nothing,
    since the caller had not identified an organization yet. `SET LOCAL` is
    not restricted to the instant a transaction begins, though — it holds
    for the rest of whichever transaction is open when it runs, so calling
    it again *here*, now that the organization id is known, corrects the
    value for every query this request or task still has left to make,
    without requiring every future call site to reason about exactly which
    dependency queries the database first.

    Every call site that used to call `set_current_organization` directly —
    `require_membership` and each Celery task that loads its own row before
    it knows that row's organization — must call this instead; the bare
    ContextVar setter now exists only for `register_tenant_context_listener`
    itself to read, and for the rarer transaction that begins *after* this
    one commits, where the "begin" listener alone is already correct.
    """
    set_current_organization(organization_id)
    await db.execute(
        text("SELECT set_config('kervy.org_id', :org_id, true)"),
        {"org_id": str(organization_id) if organization_id is not None else ""},
    )


def register_tenant_context_listener(engine: AsyncEngine) -> None:
    """Attach the RLS session-variable bridge to one engine.

    SQLAlchemy's DBAPI-level events fire on the sync engine that backs an
    async one (`AsyncEngine.sync_engine`), which is also why this takes an
    engine to attach to rather than working off a global: `get_engine()`
    creates a new engine per Celery task (see `dispose_engine`), and each
    one needs its own listener.
    """

    @event.listens_for(engine.sync_engine, "begin")
    def _set_tenant_context(connection: Connection) -> None:
        organization_id = get_current_organization()
        # set_config's third argument is `is_local` — true means this call
        # behaves like `SET LOCAL`: scoped to the transaction that is just
        # now beginning, gone at COMMIT or ROLLBACK. Using set_config rather
        # than a literal `SET LOCAL ... = '<value>'` string means the value
        # is a bind parameter, not text assembled from the caller's input.
        #
        # `text()` through `Connection.execute()` (not `exec_driver_sql`,
        # which bypasses SQLAlchemy's compiler and demands the raw DBAPI
        # driver's own paramstyle — asyncpg's is positional `$1`, not the
        # `%(name)s` pyformat style SQLAlchemy normally accepts) so this
        # works regardless of which DBAPI/dialect is behind the engine.
        connection.execute(
            text("SELECT set_config('kervy.org_id', :org_id, true)"),
            {"org_id": organization_id or ""},
        )
