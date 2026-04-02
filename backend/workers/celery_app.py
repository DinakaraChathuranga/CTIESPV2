# workers/celery_app.py
from celery import Celery
from celery.schedules import crontab
from core.config import settings
import logging

logger = logging.getLogger(__name__)

app = Celery(
    "cti_platform",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["workers.tasks"],
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "workers.tasks.poll_nvd_task":   {"queue": "cti_feeds"},
        "workers.tasks.poll_cisa_task":  {"queue": "cti_feeds"},
        "workers.tasks.poll_rss_task":   {"queue": "cti_feeds"},
        "workers.tasks.poll_epss_task":  {"queue": "cti_feeds"},
        "workers.tasks.generate_report_task": {"queue": "reports"},
    },
    beat_schedule={
        "poll-nvd-every-6h": {
            "task": "workers.tasks.poll_nvd_task",
            "schedule": crontab(minute=0, hour="*/6"),
        },
        "poll-cisa-every-6h": {
            "task": "workers.tasks.poll_cisa_task",
            "schedule": crontab(minute=30, hour="*/6"),
        },
        "poll-rss-every-30m": {
            "task": "workers.tasks.poll_rss_task",
            "schedule": crontab(minute="*/30"),
        },
        "poll-epss-daily": {
            "task": "workers.tasks.poll_epss_task",
            "schedule": crontab(minute=0, hour=4),
        },
    },
)
