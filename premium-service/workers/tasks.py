"""
Celery tasks for premium analysis

Uses Kubescape for runtime analysis and VEX generation.
"""
from celery import Task
from datetime import datetime
import logging
import traceback

from .celery_app import celery_app
from models import SessionLocal, PremiumAnalysisJob, JobStatus

# Use Kubescape-based implementation
from .tasks_impl_kubescape import (
    update_job_status as _update_job_status,
    ensure_kubescape_installed as _ensure_kubescape_installed,
    deploy_workload_for_analysis as _deploy_workload,
    wait_for_workload_ready as _wait_for_workload_ready,
    wait_for_kubescape_analysis as _wait_for_kubescape_analysis,
    extract_kubescape_results as _extract_kubescape_results,
    process_kubescape_vex as _process_kubescape_vex,
    generate_analysis_summary as _generate_analysis_summary,
    cleanup_workload as _cleanup_workload,
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
    Main task for premium analysis using Kubescape

    New Phases (Kubescape-based):
    1. Ensure Kubescape is installed
    2. Deploy workload for analysis
    3. Wait for Kubescape runtime analysis
    4. Extract VEX and filtered SBOM from Kubescape
    5. Process and save results
    6. Cleanup

    Args:
        job_id: UUID of the analysis job
        image_ref: Container image reference
        image_digest: Image digest (sha256:...)
        config: Analysis configuration dictionary
    """
    logger.info(f"Starting Kubescape-based premium analysis for job {job_id}")

    db = SessionLocal()
    deployment_name = None

    try:
        # Get job from database
        job = db.query(PremiumAnalysisJob).filter(
            PremiumAnalysisJob.id == job_id
        ).first()

        if not job:
            raise ValueError(f"Job {job_id} not found")

        # Update status to running
        _update_job_status(db, job, JobStatus.RUNNING, 0, "Initializing")

        # Phase 1: Ensure Kubescape is installed
        logger.info(f"[{job_id}] Phase 1: Checking Kubescape installation")
        _update_job_status(db, job, JobStatus.RUNNING, 5, "Checking Kubescape")
        if not _ensure_kubescape_installed():
            raise RuntimeError("Kubescape installation failed")

        # Phase 2: Deploy workload for analysis
        logger.info(f"[{job_id}] Phase 2: Deploying workload for analysis")
        _update_job_status(db, job, JobStatus.RUNNING, 15, "Deploying workload")
        deployment_name = _deploy_workload(job, image_ref, image_digest, config)
        job.sandbox_id = deployment_name  # Store deployment name as sandbox_id
        db.commit()

        # Phase 3: Wait for workload to be ready
        logger.info(f"[{job_id}] Phase 3: Waiting for workload ready")
        _update_job_status(db, job, JobStatus.RUNNING, 25, "Workload starting")
        if not _wait_for_workload_ready(deployment_name, timeout=120):
            raise RuntimeError("Workload failed to become ready")

        # Phase 4: Wait for Kubescape runtime analysis
        logger.info(f"[{job_id}] Phase 4: Kubescape runtime analysis")
        _update_job_status(db, job, JobStatus.RUNNING, 35, "Runtime analysis")

        # Get analysis duration from config (default 5 minutes)
        analysis_duration = config.get("analysis_duration", 300)
        logger.info(f"Runtime analysis will run for {analysis_duration} seconds")

        if not _wait_for_kubescape_analysis(deployment_name, analysis_duration):
            logger.warning("Kubescape analysis timeout, will attempt to extract results anyway")

        # Phase 5: Extract Kubescape results
        logger.info(f"[{job_id}] Phase 5: Extracting Kubescape results")
        _update_job_status(db, job, JobStatus.ANALYZING, 75, "Extracting results")
        kubescape_results = _extract_kubescape_results(
            deployment_name=deployment_name,
            image_digest=image_digest,
            job_id=str(job.id)
        )

        if not kubescape_results.get("has_vex"):
            logger.warning("No VEX document generated by Kubescape")

        if not kubescape_results.get("has_filtered_sbom"):
            logger.warning("No filtered SBOM generated by Kubescape")

        # Phase 6: Process VEX document
        logger.info(f"[{job_id}] Phase 6: Processing VEX document")
        _update_job_status(db, job, JobStatus.ANALYZING, 85, "Processing VEX")
        vex_document = _process_kubescape_vex(
            vex_document=kubescape_results.get("vex_document"),
            job=job
        )

        # Phase 7: Generate summary
        logger.info(f"[{job_id}] Phase 7: Generating analysis summary")
        _update_job_status(db, job, JobStatus.ANALYZING, 95, "Generating summary")
        summary = _generate_analysis_summary(
            vex_document=vex_document,
            filtered_sbom=kubescape_results.get("filtered_sbom")
        )

        # Save results to job
        job.reachability_results = summary
        job.execution_profile = {
            "method": "kubescape_runtime",
            "vex_statements": len(vex_document.get("statements", [])),
            "filtered_components": len(kubescape_results.get("filtered_sbom", {}).get("components", []))
        }
        db.commit()

        # Complete
        _update_job_status(db, job, JobStatus.COMPLETE, 100, "Complete")
        logger.info(f"[{job_id}] Analysis completed successfully")
        logger.info(f"[{job_id}] Summary: {summary}")

        return {
            "status": "success",
            "job_id": job_id,
            "vex_document": vex_document,
            "summary": summary,
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
        # Always cleanup deployment
        if deployment_name:
            try:
                logger.info(f"[{job_id}] Cleaning up deployment {deployment_name}")
                _cleanup_workload(deployment_name)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] Cleanup failed: {cleanup_error}")

        # Close database session
        db.close()
