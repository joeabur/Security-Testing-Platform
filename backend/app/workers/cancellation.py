"""Cross-process run cancellation.

A cancellation is requested in the API process but must stop a run executing
in a Celery worker, so the signal travels through Redis: the API sets a key,
and the worker's `KillSwitch` probes it before every outbound request
(docs/BUILD_SPEC.md §6.2 requires the switch to take effect "within one
request-interval").

Redis is a *transport* for the signal, not the source of truth — the run's
terminal status lives in Postgres, and `KillSwitch` latches once tripped, so
a key expiring or Redis restarting can never resume a stopped run.
"""

import contextlib

import redis

from app.core.config import get_settings

_KEY_TEMPLATE = "kervy:run:{run_id}:cancel"
# Long enough to outlive any run permitted by the wall-clock budget cap.
_TTL_SECONDS = 24 * 60 * 60


def _client() -> redis.Redis:
    return redis.Redis.from_url(get_settings().redis_url)


def request_cancellation(run_id: str) -> None:
    _client().set(_KEY_TEMPLATE.format(run_id=run_id), "1", ex=_TTL_SECONDS)


def is_cancellation_requested(run_id: str) -> bool:
    try:
        return bool(_client().exists(_KEY_TEMPLATE.format(run_id=run_id)))
    except redis.RedisError:
        # Fail *open* for the switch specifically: an unreachable Redis must
        # not silently stop every run, and the scope engine's own budget,
        # authorization and wall-clock checks still bound the run. A genuine
        # cancellation also writes a terminal status to Postgres, which the
        # worker observes when it finishes.
        return False


def clear_cancellation(run_id: str) -> None:
    with contextlib.suppress(redis.RedisError):
        _client().delete(_KEY_TEMPLATE.format(run_id=run_id))
