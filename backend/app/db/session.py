from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.db.tenant_context import register_tenant_context_listener

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
        # Row-Level Security (app/db/tenant_context.py) needs the current
        # organization set as a session variable on every transaction this
        # engine opens. `dispose_engine` recreates the engine per Celery
        # task, so each new instance needs its own listener attached here
        # rather than once at import time.
        register_tenant_context_listener(_engine)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    session_factory = get_session_factory()
    async with session_factory() as session:
        yield session


async def dispose_engine() -> None:
    """Drop the pooled connections and the engine that owns them.

    A Celery worker runs each task under its own `asyncio.run()`, and an
    asyncpg connection is bound to the loop that opened it. Without this, the
    *second* task in a worker process would pick a pooled connection from the
    first task's dead loop and fail with "attached to a different loop", so
    the worker must dispose the engine at the end of every task.
    """
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
