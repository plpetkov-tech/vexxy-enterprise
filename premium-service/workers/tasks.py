"""
Celery tasks for premium analysis
"""
from celery import Task
from datetime import datetime
import logging
import traceback

from .celery_app import celery_app
from models import SessionLocal, PremiumAnalysisJob, JobStatus

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
        execution_profile = _collect_execution_profile(sandbox_id)
        job.execution_profile = execution_profile
        db.commit()

        # Phase 5: Analyze reachability
        logger.info(f"[{job_id}] Phase 5: Analyzing reachability")
        _update_job_status(db, job, JobStatus.ANALYZING, 85, "Determining reachability")
        reachability_results = _analyze_reachability(execution_profile, image_digest, config)
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
        if sandbox_id:
            try:
                logger.info(f"[{job_id}] Cleaning up sandbox {sandbox_id}")
                _cleanup_sandbox(sandbox_id)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] Sandbox cleanup failed: {cleanup_error}")

        db.close()


# Helper functions (stubs to be implemented)

def _update_job_status(db, job, status: JobStatus, progress: int, phase: str):
    """Update job status in database"""
    job.status = status
    job.progress_percent = progress
    job.current_phase = phase

    if status == JobStatus.RUNNING and not job.started_at:
        job.started_at = datetime.utcnow()
    elif status in [JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.CANCELLED]:
        job.completed_at = datetime.utcnow()

    db.commit()
    logger.info(f"Job {job.id}: {status.value} - {progress}% - {phase}")


def _setup_sandbox(job, image_ref: str, image_digest: str, config: dict) -> str:
    """Setup isolated sandbox environment"""
    logger.info(f"Setting up sandbox for {image_ref}@{image_digest}")

    # TODO: Implement Kubernetes Job creation
    # from services.sandbox import SandboxManager
    # sandbox_manager = SandboxManager()
    # sandbox_id = sandbox_manager.create_sandbox_job(image_ref, image_digest, config)

    # For now, return mock ID
    sandbox_id = f"sandbox-{job.id}"
    logger.info(f"Created sandbox: {sandbox_id}")
    return sandbox_id


def _start_container_with_profiling(sandbox_id: str, config: dict):
    """Start container with eBPF profiling attached"""
    logger.info(f"Starting container in {sandbox_id} with profiling")
    # TODO: Start K8s Job with Tracee sidecar
    pass


def _execute_tests(sandbox_id: str, config: dict):
    """Execute tests and fuzzing"""
    logger.info(f"Running tests in {sandbox_id}")

    # Check if custom test script provided
    if config.get("test_script"):
        logger.info("Executing custom test script")
        # TODO: Execute user-provided script

    # Check if fuzzing enabled
    if config.get("enable_fuzzing", True):
        logger.info("Running OWASP ZAP fuzzing")
        # TODO: Run ZAP fuzzer


def _collect_execution_profile(sandbox_id: str) -> dict:
    """Collect execution profile from profiler"""
    logger.info(f"Collecting execution profile from {sandbox_id}")

    # TODO: Parse Tracee output, get logs, etc.

    # Mock execution profile
    return {
        "sandbox_id": sandbox_id,
        "duration_seconds": 120,
        "files_accessed": [
            "/app/main.py",
            "/app/lib/utils.py",
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        ],
        "syscalls": ["read", "write", "socket", "connect", "open", "close"],
        "network_connections": ["8.8.8.8:443"],
        "loaded_libraries": ["libc.so.6", "libssl.so.1.1"],
        "code_coverage_percent": 24.0
    }


def _analyze_reachability(execution_profile: dict, image_digest: str, config: dict) -> dict:
    """Determine CVE reachability"""
    logger.info("Analyzing reachability")

    # TODO: Implement reachability logic
    # 1. Get CVEs from SBOM
    # 2. Map CVEs to files
    # 3. Check if files were executed
    # 4. Generate reachability results with confidence scores

    # Mock results
    return {
        "cves_analyzed": 10,
        "not_affected": 8,
        "affected": 2,
        "under_investigation": 0,
        "results": [
            {
                "cve_id": "CVE-2024-12345",
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "confidence_score": 0.87,
                "reason": "Vulnerable function libfoo_process() exists but was not executed",
                "vulnerable_files": ["/usr/lib/libfoo.so.1"],
                "executed_files": execution_profile.get("files_accessed", [])
            }
        ]
    }


def _generate_vex_document(reachability_results: dict, execution_profile: dict, job) -> dict:
    """Generate OpenVEX document"""
    logger.info("Generating VEX document")

    # TODO: Generate proper OpenVEX document

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://vexxy.dev/vex/premium/{job.id}",
        "author": "VEXxy Premium Analysis Service",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": 1,
        "statements": []
    }


def _cleanup_sandbox(sandbox_id: str):
    """Cleanup sandbox resources"""
    logger.info(f"Cleaning up sandbox {sandbox_id}")

    # TODO: Delete Kubernetes Job
    # from services.sandbox import SandboxManager
    # sandbox_manager = SandboxManager()
    # sandbox_manager.delete_job(sandbox_id)

    logger.info(f"Sandbox {sandbox_id} cleaned up")
