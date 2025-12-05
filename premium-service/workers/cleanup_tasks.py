"""
Cleanup and reconciliation tasks for orphaned Kubernetes resources
"""

import logging
from datetime import datetime, timedelta
from typing import Dict

from kubernetes import client
from sqlalchemy import select

from config.settings import settings
from database.session import get_db
from models.analysis import PremiumAnalysisJob, JobStatus
from services.kubescape import KubescapeService
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="cleanup.reconcile_orphaned_deployments")
def reconcile_orphaned_deployments() -> Dict[str, int]:
    """
    Find and clean up orphaned analysis deployments.

    An orphaned deployment is one where:
    - The corresponding analysis job is COMPLETED or FAILED
    - The deployment is older than the job completion time

    This task runs periodically to prevent resource leaks from failed cleanup.

    Returns:
        Dict with cleanup statistics
    """
    logger.info("Starting orphaned deployment reconciliation")

    stats = {
        "deployments_found": 0,
        "deployments_cleaned": 0,
        "errors": 0,
    }

    try:
        # Initialize Kubernetes client
        kubescape = KubescapeService(
            namespace=settings.analysis_namespace or "vexxy-sandbox"
        )

        # Get all vex-analysis deployments
        apps_v1 = client.AppsV1Api()
        deployments = apps_v1.list_namespaced_deployment(
            namespace=kubescape.namespace, label_selector="app=vexxy-premium"
        )

        # Filter for analysis deployments
        analysis_deployments = [
            d for d in deployments.items if d.metadata.name.startswith("vex-analysis-")
        ]

        stats["deployments_found"] = len(analysis_deployments)
        logger.info(f"Found {len(analysis_deployments)} analysis deployments")

        if not analysis_deployments:
            logger.info("No analysis deployments found")
            return stats

        # Check each deployment against database
        with next(get_db()) as db:
            for deployment in analysis_deployments:
                try:
                    deployment_name = deployment.metadata.name

                    # Extract job ID from deployment name (format: vex-analysis-{job_id[:8]})
                    job_id_prefix = deployment_name.replace("vex-analysis-", "")

                    # Find matching job in database
                    # Convert UUID to string and match prefix
                    from sqlalchemy import Text as SQLText, func as sql_func

                    result = db.execute(
                        select(PremiumAnalysisJob).where(
                            sql_func.cast(PremiumAnalysisJob.id, SQLText).like(
                                f"{job_id_prefix}%"
                            )
                        )
                    )
                    job = result.scalar_one_or_none()

                    if not job:
                        logger.warning(
                            f"Deployment {deployment_name} has no matching job - "
                            f"may be orphaned from deleted job"
                        )
                        # Delete deployments with no matching job (older than 1 hour)
                        created_at = deployment.metadata.creation_timestamp
                        age = datetime.now(created_at.tzinfo) - created_at
                        if age > timedelta(hours=1):
                            logger.info(
                                f"Deleting orphaned deployment {deployment_name} (no job, age: {age})"
                            )
                            kubescape.delete_workload(deployment_name)
                            stats["deployments_cleaned"] += 1
                        continue

                    # Check if job is in terminal state
                    if job.status in [
                        JobStatus.COMPLETE,
                        JobStatus.FAILED,
                        JobStatus.CANCELLED,
                    ]:
                        # Check if deployment should have been cleaned up
                        if job.completed_at:
                            time_since_completion = (
                                datetime.now(job.completed_at.tzinfo) - job.completed_at
                            )

                            # If job completed more than 5 minutes ago, clean up deployment
                            if time_since_completion > timedelta(minutes=5):
                                logger.info(
                                    f"Cleaning up deployment {deployment_name} for "
                                    f"{job.status.value} job {job.id} "
                                    f"(completed {time_since_completion} ago)"
                                )
                                kubescape.delete_workload(deployment_name)
                                stats["deployments_cleaned"] += 1
                            else:
                                logger.debug(
                                    f"Deployment {deployment_name} recently completed, "
                                    f"allowing grace period"
                                )
                    else:
                        logger.debug(
                            f"Deployment {deployment_name} for job {job.id} "
                            f"is still active (status: {job.status.value})"
                        )

                except Exception as e:
                    logger.error(
                        f"Error processing deployment {deployment.metadata.name}: {e}"
                    )
                    stats["errors"] += 1
                    continue

        logger.info(
            f"Reconciliation complete: cleaned {stats['deployments_cleaned']} deployments, "
            f"{stats['errors']} errors"
        )
        return stats

    except Exception as e:
        logger.error(f"Fatal error during reconciliation: {e}", exc_info=True)
        stats["errors"] += 1
        return stats


@celery_app.task(name="cleanup.cleanup_old_jobs")
def cleanup_old_jobs(days: int = 30) -> Dict[str, int]:
    """
    Clean up old completed/failed jobs from database.

    Args:
        days: Delete jobs older than this many days

    Returns:
        Dict with cleanup statistics
    """
    logger.info(f"Cleaning up jobs older than {days} days")

    stats = {
        "jobs_deleted": 0,
        "errors": 0,
    }

    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        with next(get_db()) as db:
            result = db.execute(
                select(PremiumAnalysisJob).where(
                    PremiumAnalysisJob.status.in_(
                        [JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.CANCELLED]
                    ),
                    PremiumAnalysisJob.completed_at < cutoff_date,
                )
            )
            jobs = result.scalars().all()

            stats["jobs_deleted"] = len(jobs)

            for job in jobs:
                logger.info(
                    f"Deleting old job {job.id} (completed: {job.completed_at})"
                )
                db.delete(job)

            db.commit()

        logger.info(f"Deleted {stats['jobs_deleted']} old jobs")
        return stats

    except Exception as e:
        logger.error(f"Error cleaning up old jobs: {e}", exc_info=True)
        stats["errors"] += 1
        return stats
