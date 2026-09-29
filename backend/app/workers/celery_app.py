from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "aegis_ai_security",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # Without this the worker starts happily but never registers
    # `aegis.run_assessment`, and every queued run is discarded as an
    # "unregistered task" while the API reports it as queued.
    include=["app.workers.tasks", "app.workers.notifications"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Celery Beat (pentest-module Phase 8): a 60s tick against a ≥60-minute
    # `Workflow.schedule_interval_minutes` floor is ample headroom, not a
    # tight race — the dispatcher itself only ever fires a workflow whose
    # `next_run_at` has actually passed.
    beat_schedule={
        "dispatch-scheduled-workflows": {
            "task": "aegis.dispatch_scheduled_workflows",
            "schedule": 60.0,
        },
    },
)


@celery_app.task(name="aegis.health_check")
def health_check() -> dict[str, str]:
    """Liveness probe for the worker/broker wiring. Makes no outbound
    request of its own; assessment work lives in `app.workers.tasks`."""
    return {"status": "ok"}
