"""
Celery tasks for premium analysis
"""
from celery import Task
from datetime import datetime
import logging
import traceback

from .celery_app import celery_app
from models import SessionLocal, PremiumAnalysisJob, JobStatus
from .tasks_impl import (
    update_job_status as _update_job_status,
    setup_sandbox as _setup_sandbox,
    start_container_with_profiling as _start_container_with_profiling,
    execute_tests as _execute_tests,
    collect_execution_profile as _collect_execution_profile,
    analyze_reachability as _analyze_reachability,
    generate_vex_document as _generate_vex_document,
    cleanup_sandbox as _cleanup_sandbox,
)

logger = logging.getLogger(__name__)


class AnalysisTask(Task):
    """Base task with database session management and error handling"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(f"Task {task_id} failed: {exc}")

        # Update database
        job_id = kwargs.get('job_id') or (args[0] if args else None)
        if job_id:
            db = SessionLocal()
            try:
                job = db.query(PremiumAnalysisJob).filter(
                    PremiumAnalysisJob.id == job_id
                ).first()

                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(exc)
                    job.error_traceback = str(einfo)
                    job.completed_at = datetime.utcnow()
                    db.commit()
            finally:
                db.close()

    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success"""
        logger.info(f"Task {task_id} succeeded")


@celery_app.task(base=AnalysisTask, bind=True, name="run_premium_analysis")
def run_premium_analysis(self, job_id: str, image_ref: str, image_digest: str, config: dict):
    """
    Main task for premium analysis

    Phases:
    1. Setup sandbox
    2. Run container with profiling
    3. Execute tests/fuzzing
    4. Collect execution profile
    5. Analyze reachability
    6. Generate VEX
    7. Cleanup

    Args:
        job_id: UUID of the analysis job
        image_ref: Container image reference
        image_digest: Image digest (sha256:...)
        config: Analysis configuration dictionary
    """
    logger.info(f"Starting premium analysis for job {job_id}")

    db = SessionLocal()
    sandbox_id = None

    try:
        # Get job from database
        job = db.query(PremiumAnalysisJob).filter(
            PremiumAnalysisJob.id == job_id
        ).first()

        if not job:
            raise ValueError(f"Job {job_id} not found")

        # Update status to running
        _update_job_status(db, job, JobStatus.RUNNING, 0, "Initializing")

        # Phase 1: Setup sandbox
        logger.info(f"[{job_id}] Phase 1: Setting up sandbox")
        _update_job_status(db, job, JobStatus.RUNNING, 10, "Setting up sandbox")
        sandbox_id = _setup_sandbox(job, image_ref, image_digest, config)
        job.sandbox_id = sandbox_id
        db.commit()

        # Phase 2: Start container with profiling
        logger.info(f"[{job_id}] Phase 2: Starting container with profiling")
        _update_job_status(db, job, JobStatus.RUNNING, 30, "Starting container")
        _start_container_with_profiling(sandbox_id, config)

        # Phase 3: Execute tests
        logger.info(f"[{job_id}] Phase 3: Running tests and fuzzing")
        _update_job_status(db, job, JobStatus.RUNNING, 50, "Executing tests")
        _execute_tests(sandbox_id, config)

        # Phase 4: Collect execution profile
        logger.info(f"[{job_id}] Phase 4: Collecting execution profile")
        _update_job_status(db, job, JobStatus.ANALYZING, 70, "Analyzing execution")
        execution_profile = _collect_execution_profile(sandbox_id, str(job.id))
        job.execution_profile = execution_profile
        db.commit()

        # Phase 5: Analyze reachability
        logger.info(f"[{job_id}] Phase 5: Analyzing reachability")
        _update_job_status(db, job, JobStatus.ANALYZING, 85, "Determining reachability")
        reachability_results = _analyze_reachability(execution_profile, image_digest, config, str(job.id))
        job.reachability_results = reachability_results
        db.commit()

        # Phase 6: Generate VEX
        logger.info(f"[{job_id}] Phase 6: Generating VEX document")
        _update_job_status(db, job, JobStatus.ANALYZING, 95, "Generating VEX")
        vex_document = _generate_vex_document(reachability_results, execution_profile, job)

        # Phase 7: Save results
        logger.info(f"[{job_id}] Phase 7: Saving results")
        # TODO: Save VEX to storage and get ID
        # job.generated_vex_id = vex_id

        # Complete
        _update_job_status(db, job, JobStatus.COMPLETE, 100, "Complete")
        logger.info(f"[{job_id}] Analysis completed successfully")

        return {
            "status": "success",
            "job_id": job_id,
            "execution_profile": execution_profile,
            "reachability_results": reachability_results,
        }

    except Exception as e:
        logger.error(f"[{job_id}] Analysis failed: {e}", exc_info=True)

        # Update job status
        if db.is_active:
            try:
                job = db.query(PremiumAnalysisJob).filter(
                    PremiumAnalysisJob.id == job_id
                ).first()
                if job:
                    job.status = JobStatus.FAILED
                    job.error_message = str(e)
                    job.error_traceback = traceback.format_exc()
                    job.completed_at = datetime.utcnow()
                    db.commit()
            except Exception as db_error:
                logger.error(f"Failed to update job status: {db_error}")

        raise

    finally:
        # Always cleanup sandbox
