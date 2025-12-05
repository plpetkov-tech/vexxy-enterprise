"""
Celery workers for Premium VEX Service
"""

from .celery_app import celery_app

# Try to import tasks with fallback
try:
    from .tasks import run_premium_analysis
    from .cleanup_tasks import reconcile_orphaned_deployments, cleanup_old_jobs

    __all__ = [
        "celery_app",
        "run_premium_analysis",
        "reconcile_orphaned_deployments",
        "cleanup_old_jobs",
    ]
except ImportError as e:
    print(f"Warning: Could not import tasks: {e}")
    __all__ = ["celery_app"]
