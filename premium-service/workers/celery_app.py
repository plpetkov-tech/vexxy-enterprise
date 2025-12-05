"""
Celery application configuration
"""

from celery import Celery  # type: ignore[import-untyped]
from celery.signals import task_prerun, task_postrun, task_failure  # type: ignore[import-untyped]
from celery.schedules import crontab  # type: ignore[import-untyped]
import logging

from config.settings import settings

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "premium-vex-worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

# Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.celery_task_time_limit,
    task_soft_time_limit=settings.celery_task_soft_time_limit,
    worker_prefetch_multiplier=1,  # Only fetch one task at a time
    task_acks_late=True,  # Acknowledge after task completes
    task_reject_on_worker_lost=True,  # Requeue if worker dies
)

# Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    # Reconcile orphaned deployments every 10 minutes
    "reconcile-orphaned-deployments": {
        "task": "cleanup.reconcile_orphaned_deployments",
        "schedule": 600.0,  # Every 10 minutes
        "options": {"expires": 300},  # Expire after 5 minutes if not picked up
    },
    # Clean up old completed jobs once per day at 2 AM
    "cleanup-old-jobs": {
        "task": "cleanup.cleanup_old_jobs",
        "schedule": crontab(hour=2, minute=0),
        "args": (30,),  # Delete jobs older than 30 days
        "options": {"expires": 3600},
    },
}


# Task signals
@task_prerun.connect
def task_prerun_handler(
    sender=None, task_id=None, task=None, args=None, kwargs=None, **extra
):
    """Called before task execution"""
    logger.info(f"Task {task.name} [{task_id}] starting")


@task_postrun.connect
def task_postrun_handler(
    sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, **extra
):
    """Called after task execution"""
    logger.info(f"Task {task.name} [{task_id}] completed")


@task_failure.connect
def task_failure_handler(
    sender=None,
    task_id=None,
    exception=None,
    args=None,
    kwargs=None,
    traceback=None,
    einfo=None,
    **extra,
):
    """Called when task fails"""
    logger.error(f"Task {sender.name} [{task_id}] failed: {exception}")
    logger.error(f"Traceback: {traceback}")
