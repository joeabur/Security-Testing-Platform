"""Worker wiring tests.

Both cases here are regressions for bugs that a green unit suite happily
hid: the API queued runs that no worker would ever execute, and a worker
process could only ever execute one run.
"""

from app.db.session import dispose_engine, get_engine, get_session_factory
from app.workers.celery_app import celery_app


def test_the_assessment_task_is_registered_on_the_worker() -> None:
    """`Dockerfile.worker` boots the app in `app.workers.celery_app`, which
    only registers tasks in modules it imports. Without `include`, the worker
    starts fine and then discards every run as an unregistered task while the
    API keeps reporting them as queued."""
    # Exactly what a worker does on boot; `include` is lazy until then.
    celery_app.loader.import_default_modules()

    assert "kervy.run_assessment" in celery_app.tasks
    assert celery_app.tasks["kervy.run_assessment"].name == "kervy.run_assessment"


async def test_disposing_the_engine_lets_the_next_event_loop_start_clean() -> None:
    """Celery runs each task under its own `asyncio.run`, and an asyncpg
    connection belongs to the loop that opened it. The task must therefore
    leave no pooled connection behind, or the *second* run in a worker
    process dies with "attached to a different loop"."""
    first_engine = get_engine()
    first_factory = get_session_factory()

    await dispose_engine()

    assert get_engine() is not first_engine
    assert get_session_factory() is not first_factory
