"""
Celery workers for Premium VEX Service
"""
from .celery_app import celery_app

# Try to import tasks with fallback
try:
    from .tasks import run_premium_analysis
    __all__ = ["celery_app", "run_premium_analysis"]
except ImportError as e:
    print(f"Warning: Could not import tasks: {e}")
    __all__ = ["celery_app"]
