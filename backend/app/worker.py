"""
MAP — Celery Worker Configuration

Configures the Celery app for background tasks.
"""

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "map_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

# Celery settings
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
)

# Auto-discover tasks in all domain packages
celery_app.autodiscover_tasks(
    [
        "app.analysis",
        "app.memory",
        "app.detection",
    ]
)
