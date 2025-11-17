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
    run_owasp_zap_scan as _run_owasp_zap_scan,
    wait_for_kubescape_analysis as _wait_for_kubescape_analysis,
    extract_kubescape_results as _extract_kubescape_results,
    process_kubescape_vex as _process_kubescape_vex,
    convert_vex_statements_to_reachability as _convert_vex_to_reachability,
    extract_sbom_component_data as _extract_sbom_component_data,
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

    Phases:
    1. Ensure Kubescape is installed
    2. Deploy workload for analysis
    3. Wait for workload to be ready
    3.5. Create Kubernetes Service (if ports specified)
    3.6. Run OWASP ZAP security scan (if ports and fuzzing enabled)
    4. Wait for Kubescape runtime analysis
    5. Extract VEX and filtered SBOM from Kubescape
    6. Process VEX document
    7. Generate analysis summary
    8. Cleanup (service and deployment)

    Args:
        job_id: UUID of the analysis job
        image_ref: Container image reference
        image_digest: Image digest (sha256:...)
        config: Analysis configuration dictionary (includes ports, enable_fuzzing)
    """
    logger.info(f"Starting Kubescape-based premium analysis for job {job_id}")

    db = SessionLocal()
    deployment_name = None
    service_name = None

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

        # Phase 3.5: Create Service and run OWASP ZAP scan (if ports specified)
        zap_results = None  # Initialize to track ZAP scan results
        ports = config.get("ports", [])
        if ports:
            logger.info(f"[{job_id}] Phase 3.5: Creating service for ports {ports}")
            _update_job_status(db, job, JobStatus.RUNNING, 30, "Creating service")

            from services import KubescapeService
            from config.settings import settings
            kubescape_service = KubescapeService(namespace=settings.k8s_sandbox_namespace)

            service_name = kubescape_service.create_service_for_deployment(
                deployment_name=deployment_name,
                job_id=str(job.id),
                ports=ports
            )

            # Run OWASP ZAP scan
            logger.info(f"[{job_id}] Phase 3.6: Running OWASP ZAP scan")
            _update_job_status(db, job, JobStatus.RUNNING, 32, "Security scanning")

            zap_results = _run_owasp_zap_scan(
                deployment_name=deployment_name,
                namespace=settings.k8s_sandbox_namespace,
                ports=ports,
                job_id=str(job.id),
                enable_fuzzing=config.get("enable_fuzzing", True)
            )

            if zap_results and zap_results.get("status") == "completed":
                logger.info(
                    f"[{job_id}] ZAP scan found {zap_results['summary']['total_alerts']} alerts "
                    f"(High: {zap_results['summary']['high_risk']}, "
                    f"Medium: {zap_results['summary']['medium_risk']})"
                )

        # Phase 4: Wait for Kubescape runtime analysis
        logger.info(f"[{job_id}] Phase 4: Kubescape runtime analysis")
        _update_job_status(db, job, JobStatus.RUNNING, 35, "Runtime analysis")

        # Get analysis duration from config (default 5 minutes)
        analysis_duration = config.get("analysis_duration", 300)
        logger.info(f"Runtime analysis will run for {analysis_duration} seconds")

        if not _wait_for_kubescape_analysis(deployment_name, analysis_duration):
            logger.warning("Kubescape analysis timeout, will attempt to extract results anyway")

        # Phase 5: Extract Kubescape results and Tracee profiling
        logger.info(f"[{job_id}] Phase 5: Extracting Kubescape results and profiling data")
        _update_job_status(db, job, JobStatus.ANALYZING, 75, "Extracting results")
        kubescape_results = _extract_kubescape_results(
            deployment_name=deployment_name,
            image_digest=image_digest,
            job_id=str(job.id),
            enable_profiling=config.get("enable_profiling", True)
        )

        if not kubescape_results.get("has_vex"):
            logger.warning("No VEX document generated by Kubescape")

        if not kubescape_results.get("has_filtered_sbom"):
            logger.warning("No filtered SBOM generated by Kubescape")

        # Phase 6: Process VEX document (brand it with VEXxy metadata)
        logger.info(f"[{job_id}] Phase 6: Processing VEX document")
        _update_job_status(db, job, JobStatus.ANALYZING, 85, "Processing VEX")
        vex_document = _process_kubescape_vex(
            vex_document=kubescape_results.get("vex_document"),
            job=job
        )

        # Store the enhanced VEX document with VEXxy branding
        from services import EvidenceStorage
        evidence_storage = EvidenceStorage()
        vex_id = None
        if vex_document:
            _, vex_id = evidence_storage.store_vex_document(str(job.id), vex_document)
            statements = vex_document.get('statements') or []
            logger.info(f"Stored enhanced VEX document (ID: {vex_id}): {len(statements)} statements")
        else:
            logger.warning("No VEX document to store after processing")

        # Phase 7: Generate summary
        logger.info(f"[{job_id}] Phase 7: Generating analysis summary")
        _update_job_status(db, job, JobStatus.ANALYZING, 95, "Generating summary")
        summary = _generate_analysis_summary(
            vex_document=vex_document,
            filtered_sbom=kubescape_results.get("filtered_sbom")
        )

        # Calculate analysis duration
        analysis_start = job.started_at or job.created_at
        analysis_end = datetime.utcnow()
        duration_seconds = int((analysis_end - analysis_start).total_seconds())

        # Save results to job
        # Convert VEX statements to reachability results
        logger.info(f"[{job_id}] Converting VEX statements to reachability results")
        job.reachability_results = _convert_vex_to_reachability(vex_document)

        # Store VEX ID
        job.generated_vex_id = vex_id
        if job.generated_vex_id:
            logger.info(f"[{job_id}] Generated VEX ID: {job.generated_vex_id}")

        # Build execution profile with runtime data from multiple sources
        tracee_profile = kubescape_results.get("tracee_profile") or {}
        sbom_data = _extract_sbom_component_data(kubescape_results.get("filtered_sbom"))

        # Merge files from Tracee and SBOM (Tracee = runtime access, SBOM = loaded components)
        files_accessed = list(set(
            tracee_profile.get("files_accessed", []) +
            sbom_data.get("component_files", [])
        ))

        # Merge libraries from Tracee and SBOM
        loaded_libraries = list(set(
            tracee_profile.get("loaded_libraries", []) +
            sbom_data.get("loaded_components", [])
        ))

        job.execution_profile = {
            "sandbox_id": job.sandbox_id or "unknown",
            "duration_seconds": tracee_profile.get("duration_seconds", duration_seconds),
            "files_accessed": files_accessed,
            "syscalls": tracee_profile.get("syscalls", []),
            "network_connections": tracee_profile.get("network_connections", []),
            "loaded_libraries": loaded_libraries,
            "code_coverage_percent": tracee_profile.get("code_coverage_percent"),
            # Additional metadata (not in schema but useful for debugging)
            "method": "hybrid_kubescape_tracee_sbom",
            "data_sources": {
                "tracee": tracee_profile is not None and len(tracee_profile) > 0,
                "sbom": sbom_data.get("component_count", 0) > 0,
                "kubescape_vex": len(vex_document.get("statements") or []) > 0
            },
            "vex_statements": len(vex_document.get("statements") or []),
            "filtered_components": sbom_data.get("component_count", 0),
            "profiling_enabled": config.get("enable_profiling", True),
            "profiling_success": kubescape_results.get("has_profiling", False),
            "summary": summary  # Store the summary here for reference
        }

        # Log detailed profiling results
        if tracee_profile:
            logger.info(
                f"[{job_id}] Tracee profiling: {len(tracee_profile.get('files_accessed', []))} files, "
                f"{len(tracee_profile.get('syscalls', []))} unique syscalls, "
                f"{len(tracee_profile.get('network_connections', []))} network connections"
            )
        else:
            logger.warning(f"[{job_id}] No Tracee profiling data available")

        logger.info(
            f"[{job_id}] SBOM analysis: {sbom_data.get('component_count', 0)} loaded components, "
            f"{len(sbom_data.get('component_files', []))} component file paths"
        )

        logger.info(
            f"[{job_id}] Combined execution profile: {len(files_accessed)} total files, "
            f"{len(loaded_libraries)} loaded libraries/components"
        )

        # Store security findings from OWASP ZAP scan (if run)
        if zap_results:
            job.security_findings = {
                "scan_type": "owasp_zap",
                "status": zap_results.get("status", "unknown"),
                "scan_duration_seconds": zap_results.get("scan_duration_seconds"),
                "target_urls": zap_results.get("scanned_urls", []),
                "total_alerts": zap_results.get("summary", {}).get("total_alerts", 0),
                "high_risk": zap_results.get("summary", {}).get("high_risk", 0),
                "medium_risk": zap_results.get("summary", {}).get("medium_risk", 0),
                "low_risk": zap_results.get("summary", {}).get("low_risk", 0),
                "informational": zap_results.get("summary", {}).get("informational", 0),
                "alerts": zap_results.get("alerts", []),  # Detailed findings
                "scan_timestamp": datetime.utcnow().isoformat(),
                "error_message": zap_results.get("error") if zap_results.get("status") == "failed" else None
            }
            logger.info(f"[{job_id}] Stored security findings: {job.security_findings.get('total_alerts')} alerts")
        else:
            logger.info(f"[{job_id}] No security scan results to store")

        db.commit()

        # Complete
        _update_job_status(db, job, JobStatus.COMPLETE, 100, "Complete")
        logger.info(f"[{job_id}] Analysis completed successfully")
        logger.info(f"[{job_id}] Summary: {summary}")

        # Calculate cost and record billing event
        try:
            from services.billing import BillingService

            # Calculate cost based on analysis configuration and duration
            base_cost = 10  # Base cost in credits
            duration_minutes = (datetime.utcnow() - job.created_at).total_seconds() / 60

            # Add cost for enabled features
            cost_credits = base_cost
            if config.get("enable_fuzzing", True):
                cost_credits += 5  # Additional cost for security fuzzing
            if config.get("enable_profiling", True):
                cost_credits += 3  # Additional cost for profiling
            if config.get("enable_code_coverage", False):
                cost_credits += 7  # Additional cost for code coverage

            # Add cost based on duration (1 credit per 5 minutes)
            duration_cost = int(duration_minutes / 5)
            cost_credits += duration_cost

            logger.info(f"[{job_id}] Calculated cost: {cost_credits} credits (base={base_cost}, duration={duration_cost})")

            # Record billing event
            billing_service = BillingService(db)
            billing_service.record_analysis_cost(job_id, cost_credits)

            logger.info(f"[{job_id}] Billing event recorded: {cost_credits} credits")

        except Exception as billing_error:
            logger.error(f"[{job_id}] Failed to record billing event: {billing_error}", exc_info=True)
            # Don't fail the analysis if billing fails

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
        # Always cleanup service and deployment
        if service_name:
            try:
                logger.info(f"[{job_id}] Cleaning up service {service_name}")
                from services import KubescapeService
                from config.settings import settings
                kubescape_service = KubescapeService(namespace=settings.k8s_sandbox_namespace)
                kubescape_service.delete_service(service_name)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] Service cleanup failed: {cleanup_error}")

        if deployment_name:
            try:
                logger.info(f"[{job_id}] Cleaning up deployment {deployment_name}")
                _cleanup_workload(deployment_name)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] Deployment cleanup failed: {cleanup_error}")

        # Close database session
        db.close()
