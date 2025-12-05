"""
Celery tasks for premium analysis

Uses Kubescape for runtime analysis and VEX generation.
"""

from celery import Task
from datetime import datetime
import logging
import time
import traceback

from .celery_app import celery_app
from models import SessionLocal, PremiumAnalysisJob, JobStatus

# Use Kubescape-based implementation
from .tasks_impl_kubescape import (
    update_job_status as _update_job_status,
    ensure_kubescape_installed as _ensure_kubescape_installed,
    deploy_workload_for_analysis as _deploy_workload,
    wait_for_workload_ready as _wait_for_workload_ready,
    verify_application_responding as _verify_application_responding,
    collect_container_logs as _collect_container_logs,
    run_owasp_zap_scan as _run_owasp_zap_scan,
    run_pentest_scan as _run_pentest_scan,
    wait_for_kubescape_analysis as _wait_for_kubescape_analysis,
    extract_kubescape_results as _extract_kubescape_results,
    process_kubescape_vex as _process_kubescape_vex,
    convert_vex_statements_to_reachability as _convert_vex_to_reachability,
    extract_sbom_component_data as _extract_sbom_component_data,
    generate_analysis_summary as _generate_analysis_summary,
    cleanup_workload as _cleanup_workload,
    cleanup_kubescape_crds as _cleanup_kubescape_crds,
    evidence_storage,
)

logger = logging.getLogger(__name__)


def merge_security_findings(zap_results, pentest_results):
    """
    Merge ZAP and pentest findings into combined security findings matching SecurityFindings schema

    Args:
        zap_results: OWASP ZAP scan results dict (optional)
        pentest_results: Pentesting scan results dict (optional)

    Returns:
        Combined security findings dict matching SecurityFindings schema
    """
    from datetime import datetime

    # Determine overall status
    if zap_results and pentest_results:
        # Both ran - status is completed if at least one completed
        if (
            zap_results.get("status") == "completed"
            or pentest_results.get("status") == "completed"
        ):
            status = "completed"
        else:
            status = "failed"
        scan_type = "combined"
    elif zap_results:
        status = zap_results.get("status", "completed")
        scan_type = "owasp_zap"
    elif pentest_results:
        status = pentest_results.get("status", "completed")
        scan_type = "pentest"
    else:
        status = "skipped"
        scan_type = "none"

    # Merge all alerts from both scans
    all_alerts = []
    target_urls = []

    if zap_results and zap_results.get("status") == "completed":
        all_alerts.extend(zap_results.get("alerts", []))
        target_urls.extend(zap_results.get("target_urls", []))

    if pentest_results and pentest_results.get("status") == "completed":
        all_alerts.extend(pentest_results.get("alerts", []))
        target_urls.extend(pentest_results.get("target_urls", []))

    # Calculate combined totals
    total_alerts = len(all_alerts)
    high_risk = sum(1 for a in all_alerts if a.get("risk", "").lower() == "high")
    medium_risk = sum(1 for a in all_alerts if a.get("risk", "").lower() == "medium")
    low_risk = sum(1 for a in all_alerts if a.get("risk", "").lower() == "low")
    informational = sum(
        1 for a in all_alerts if a.get("risk", "").lower() in ["informational", "info"]
    )

    # Return SecurityFindings-compliant structure
    return {
        "scan_type": scan_type,
        "status": status,
        "scan_duration_seconds": None,
        "target_urls": list(set(target_urls)),  # Deduplicate URLs
        "total_alerts": total_alerts,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk,
        "informational": informational,
        "alerts": all_alerts,
        "scan_timestamp": datetime.utcnow().isoformat(),
        "scanner_version": "vexxy-security-scanner-v1",
        "error_message": None,
    }


class AnalysisTask(Task):
    """Base task with database session management and error handling"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(f"Task {task_id} failed: {exc}")

        # Update database
        job_id = kwargs.get("job_id") or (args[0] if args else None)
        if job_id:
            db = SessionLocal()
            try:
                job = (
                    db.query(PremiumAnalysisJob)
                    .filter(PremiumAnalysisJob.id == job_id)
                    .first()
                )

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
def run_premium_analysis(
    self, job_id: str, image_ref: str, image_digest: str, config: dict
):
    """
    Main task for premium analysis using Kubescape

    Phases:
    1. Ensure Kubescape is installed
    2. Deploy workload for analysis
    3. Wait for workload to be ready
    3.5. Create Kubernetes Service (if ports specified)
    3.6. Run OWASP ZAP security scan (if ports and fuzzing enabled)
    3.7. Run penetration testing scan (if ports and pentesting enabled)
    4. Wait for Kubescape runtime analysis
    5. Extract VEX and filtered SBOM from Kubescape
    6. Process VEX document
    7. Generate analysis summary
    8. Cleanup (service and deployment)

    Args:
        job_id: UUID of the analysis job
        image_ref: Container image reference
        image_digest: Image digest (sha256:...)
        config: Analysis configuration dictionary (includes ports, enable_fuzzing, enable_pentesting)
    """
    logger.info(f"Starting Kubescape-based premium analysis for job {job_id}")

    db = SessionLocal()
    deployment_name = None
    service_name = None

    try:
        # Get job from database
        job = (
            db.query(PremiumAnalysisJob).filter(PremiumAnalysisJob.id == job_id).first()
        )

        if not job:
            raise ValueError(f"Job {job_id} not found")

        # Update status to running
        _update_job_status(db, job, JobStatus.RUNNING, 0, "Initializing")

        # Phase 1: Ensure Kubescape is installed
        logger.info(f"[{job_id}] Phase 1: Checking Kubescape installation")
        _update_job_status(db, job, JobStatus.RUNNING, 5, "Checking Kubescape")
        if not _ensure_kubescape_installed():
            raise RuntimeError("Kubescape installation failed")

        # Normalize analysis timing configuration
        raw_analysis_duration = (
            config.get("analysis_duration") or config.get("test_timeout") or 300
        )
        analysis_duration = max(60, min(int(raw_analysis_duration), 3600))
        config["analysis_duration"] = analysis_duration
        config["test_timeout"] = analysis_duration
        time_buffer = config.get("analysis_time_buffer")
        if time_buffer is None:
            time_buffer = max(20, min(int(analysis_duration * 0.3), 40))
        else:
            time_buffer = max(10, min(int(time_buffer), 90))
        total_time_budget = analysis_duration + time_buffer
        analysis_deadline = time.monotonic() + total_time_budget

        logger.info(
            f"[{job_id}] Analysis timing: requested={raw_analysis_duration}s, "
            f"normalized={analysis_duration}s, buffer={time_buffer}s, total_budget={total_time_budget}s"
        )

        def bounded_timeout(maximum: int, *, reserve: int = 0, minimum: int = 5) -> int:
            remaining = analysis_deadline - time.monotonic() - reserve
            allowable = int(max(1, remaining))
            allowable = min(maximum, allowable)
            if allowable < minimum:
                return max(1, allowable)
            return allowable

        # Phase 2: Pre-create Service (if ports specified) to ensure DNS is ready before deployment
        service_name = None
        ports = config.get("ports", [])

        # Import settings and KubescapeService if ports are specified (needed for service creation and scans)
        if ports:
            from services import KubescapeService
            from config.settings import settings

        if ports:
            logger.info(f"[{job_id}] Phase 2: Pre-creating service for ports {ports}")
            _update_job_status(db, job, JobStatus.RUNNING, 10, "Creating service")

            kubescape_service = KubescapeService(
                namespace=settings.k8s_sandbox_namespace
            )

            # Pre-calculate deployment name to match what will be created
            deployment_name = f"vex-analysis-{job_id[:8]}"

            service_name = kubescape_service.create_service_for_deployment(
                deployment_name=deployment_name, job_id=str(job.id), ports=ports
            )
            logger.info(
                f"[{job_id}] Service {service_name} created, DNS ready for pentest sidecar"
            )

        # Phase 3: Deploy workload for analysis
        logger.info(f"[{job_id}] Phase 3: Deploying workload for analysis")
        _update_job_status(db, job, JobStatus.RUNNING, 15, "Deploying workload")
        deployment_name = _deploy_workload(job, image_ref, image_digest, config)
        job.sandbox_id = deployment_name  # Store deployment name as sandbox_id
        db.commit()

        # Phase 4: Wait for workload to be ready
        logger.info(f"[{job_id}] Phase 4: Waiting for workload ready")
        _update_job_status(db, job, JobStatus.RUNNING, 25, "Workload starting")
        reserve_for_later = max(10, min(time_buffer, 20))
        readiness_cap = max(30, analysis_duration // 2)
        workload_ready_timeout = bounded_timeout(
            readiness_cap, reserve=reserve_for_later, minimum=20
        )
        if not _wait_for_workload_ready(
            deployment_name, timeout=workload_ready_timeout
        ):
            raise RuntimeError("Workload failed to become ready")

        # Collect container startup logs for diagnostics
        try:
            container_logs = _collect_container_logs(
                deployment_name=deployment_name,
                namespace=settings.k8s_sandbox_namespace,
                container_name="target",
                tail_lines=500,
            )
            evidence_storage.store_container_logs(
                job.id, container_logs, container_name="target"
            )
            logger.debug(f"[{job_id}] Stored container startup logs as evidence")
        except Exception as e:
            logger.warning(f"[{job_id}] Failed to collect/store container logs: {e}")

        # Phase 4.5: Verify application is responding (if ports specified)
        if ports:
            logger.info(f"[{job_id}] Phase 4.5: Verifying application health")
            _update_job_status(db, job, JobStatus.RUNNING, 27, "Verifying app health")

            health_check_path = config.get("health_check_path", "/")
            health_cap = max(20, config.get("health_check_timeout", 60))
            health_check_timeout = bounded_timeout(
                health_cap,
                reserve=max(10, min(time_buffer, 15)),
                minimum=15,
            )
            config["health_check_timeout"] = health_check_timeout

            health_status = _verify_application_responding(
                deployment_name=deployment_name,
                namespace=settings.k8s_sandbox_namespace,
                ports=ports,
                health_check_path=health_check_path,
                timeout=health_check_timeout,
            )

            if not health_status["responding"]:
                # Application not responding - fail the job
                error_msg = (
                    f"Application failed to respond on any port after {health_check_timeout}s. "
                    f"Ports checked: {ports}. "
                    f"Status: {health_status['ports_status']}. "
                    f"Attempts: {health_status['attempts']}. "
                    f"\n\nPossible causes:"
                    f"\n- Application failed to start (check startup command)"
                    f"\n- Application is not listening on the specified ports"
                    f"\n- Application takes longer than {health_check_timeout}s to start"
                    f"\n\nSuggestions:"
                    f"\n- Check container logs for startup errors"
                    f"\n- Verify the 'command' in your analysis config"
                    f"\n- Increase 'health_check_timeout' if app needs more time"
                )

                logger.error(f"[{job_id}] {error_msg}")
                raise RuntimeError(error_msg)

            logger.info(
                f"[{job_id}] Application health check PASSED. "
                f"Responding on ports: {health_status['responding_ports']}"
            )

            # Store health check results as diagnostic evidence
            try:
                evidence_storage.store_health_check_results(job.id, health_status)
                logger.debug(f"[{job_id}] Stored health check results as evidence")
            except Exception as e:
                logger.warning(f"[{job_id}] Failed to store health check evidence: {e}")

        # Phase 5-7: Run security scans in parallel with Kubescape runtime analysis
        # This significantly reduces total job time by overlapping I/O-bound operations
        zap_results = None  # Initialize to track ZAP scan results
        pentest_results = None  # Initialize pentest results

        logger.info(f"[{job_id}] Phase 5-7: Starting parallel security analysis")
        _update_job_status(db, job, JobStatus.RUNNING, 30, "Security scanning")

        # Get analysis duration from config (default 5 minutes)
        analysis_duration = config.get("analysis_duration", 300)

        # Import threading for parallel execution
        import threading

        # Thread-safe database session management
        # Each thread needs its own DB session to avoid conflicts

        def run_security_scans():
            """Run ZAP and pentest scans (thread-safe)"""
            nonlocal zap_results, pentest_results

            # Run OWASP ZAP scan (if ports specified and fuzzing enabled)
            if ports and config.get("enable_fuzzing", False):
                logger.info(f"[{job_id}] Running OWASP ZAP scan in parallel")
                remaining_for_security = int(analysis_deadline - time.monotonic())
                if remaining_for_security < 90:
                    logger.info(
                        f"[{job_id}] Skipping OWASP ZAP fuzzing due to limited remaining time ({remaining_for_security}s left)"
                    )
                    zap_results = {
                        "status": "skipped",
                        "reason": "insufficient_time_budget",
                        "scanned_urls": [],
                    }
                else:
                    zap_results = _run_owasp_zap_scan(
                        deployment_name=deployment_name,
                        namespace=settings.k8s_sandbox_namespace,
                        ports=ports,
                        job_id=job.id,
                        enable_fuzzing=True,
                        time_budget=remaining_for_security,
                    )
            elif ports:
                logger.info(f"[{job_id}] OWASP ZAP fuzzing disabled; skipping scan")
                zap_results = {
                    "status": "skipped",
                    "reason": "fuzzing_disabled",
                    "scanned_urls": [],
                }

            # Log ZAP results
            if zap_results and zap_results.get("status") == "completed":
                total_alerts = zap_results["summary"]["total_alerts"]

                logger.info(
                    f"[{job_id}] ZAP scan found {total_alerts} alerts "
                    f"(High: {zap_results['summary']['high_risk']}, "
                    f"Medium: {zap_results['summary']['medium_risk']})"
                )

            # Run pentesting scan (if enabled)
            if ports and config.get("enable_pentesting", False):
                logger.info(f"[{job_id}] Running penetration testing scan in parallel")
                remaining_for_pentest = int(analysis_deadline - time.monotonic())
                if remaining_for_pentest < 60:
                    logger.info(
                        f"[{job_id}] Skipping pentesting due to limited remaining time ({remaining_for_pentest}s left)"
                    )
                else:
                    current_analysis_duration = config.get(
                        "analysis_duration", analysis_duration
                    )
                    pentest_timeout = min(
                        remaining_for_pentest - 20, current_analysis_duration
                    )
                    pentest_timeout = max(60, min(pentest_timeout, 1800))
                    logger.info(
                        f"[{job_id}] Pentest timeout set to {pentest_timeout}s "
                        f"(analysis_duration: {current_analysis_duration}s, remaining: {remaining_for_pentest}s)"
                    )

                    pentest_results = _run_pentest_scan(
                        deployment_name=deployment_name,
                        namespace=settings.k8s_sandbox_namespace,
                        ports=ports,
                        job_id=str(job.id),
                        enable_pentesting=True,
                        pentest_timeout=pentest_timeout,
                    )

                if pentest_results and pentest_results.get("status") == "completed":
                    logger.info(
                        f"[{job_id}] Pentest scan found {pentest_results['total_alerts']} alerts "
                        f"(High: {pentest_results['high_risk']}, "
                        f"Medium: {pentest_results['medium_risk']})"
                    )

        # Start security scans in background thread while we wait for Kubescape
        security_scan_thread = None
        if ports:
            security_scan_thread = threading.Thread(
                target=run_security_scans, daemon=True
            )
            security_scan_thread.start()
            logger.info(f"[{job_id}] Security scans started in parallel thread")

        # Phase 7: Wait for Kubescape runtime analysis (runs concurrently with security scans)
        logger.info(f"[{job_id}] Phase 7: Kubescape runtime analysis")
        _update_job_status(db, job, JobStatus.RUNNING, 35, "Runtime analysis")

        # DEBUG: Log the actual config received to verify it's correct
        logger.info(f"[{job_id}] DEBUG: Worker received config: {config}")
        logger.info(f"[{job_id}] DEBUG: Config analysis_duration: {analysis_duration}")
        logger.info(
            f"[{job_id}] DEBUG: Config enable_fuzzing: {config.get('enable_fuzzing', 'MISSING')}"
        )
        logger.info(f"[{job_id}] DEBUG: Config ports: {config.get('ports', 'MISSING')}")
        logger.info(
            f"[{job_id}] DEBUG: Config environment: {config.get('environment', 'MISSING')}"
        )

        logger.info(f"Runtime analysis will run for {analysis_duration} seconds")

        remaining_for_kubescape = max(10, int(analysis_deadline - time.monotonic()))
        kubescape_timeout = max(10, min(analysis_duration, remaining_for_kubescape))
        if not _wait_for_kubescape_analysis(deployment_name, kubescape_timeout):
            logger.warning(
                "Kubescape analysis timeout, will attempt to extract results anyway"
            )

        # Wait for security scans to complete (if they were started)
        if security_scan_thread:
            logger.info(f"[{job_id}] Waiting for security scans to complete")
            # Calculate remaining time for security scans
            remaining_time = max(5, int(analysis_deadline - time.monotonic()))
            security_scan_thread.join(timeout=remaining_time)
            if security_scan_thread.is_alive():
                logger.warning(
                    f"[{job_id}] Security scans still running after timeout, proceeding anyway"
                )
            else:
                logger.info(f"[{job_id}] Security scans completed")

        # Phase 5: Extract Kubescape results and Tracee profiling
        logger.info(
            f"[{job_id}] Phase 5: Extracting Kubescape results and profiling data"
        )
        _update_job_status(db, job, JobStatus.ANALYZING, 75, "Extracting results")
        kubescape_results = _extract_kubescape_results(
            deployment_name=deployment_name,
            image_digest=image_digest,
            job_id=job.id,
            enable_profiling=config.get("enable_profiling", True),
        )

        if not kubescape_results.get("has_vex"):
            logger.warning("No VEX document generated by Kubescape")

        if not kubescape_results.get("has_filtered_sbom"):
            logger.warning("No filtered SBOM generated by Kubescape")

        # Phase 6: Process VEX document (brand it with VEXxy metadata)
        logger.info(f"[{job_id}] Phase 6: Processing VEX document")
        _update_job_status(db, job, JobStatus.ANALYZING, 85, "Processing VEX")
        vex_document = _process_kubescape_vex(
            vex_document=kubescape_results.get("vex_document"), job=job
        )

        # Store the enhanced VEX document with VEXxy branding
        vex_id = None
        if vex_document:
            _, vex_id = evidence_storage.store_vex_document(job.id, vex_document)
            statements = vex_document.get("statements") or []
            logger.info(
                f"Stored enhanced VEX document (ID: {vex_id}): {len(statements)} statements"
            )
        else:
            logger.warning("No VEX document to store after processing")

        # Phase 7: Generate summary
        logger.info(f"[{job_id}] Phase 7: Generating analysis summary")
        _update_job_status(db, job, JobStatus.ANALYZING, 95, "Generating summary")
        summary = _generate_analysis_summary(
            vex_document=vex_document,
            filtered_sbom=kubescape_results.get("filtered_sbom"),
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
        files_accessed = list(
            set(
                tracee_profile.get("files_accessed", [])
                + sbom_data.get("component_files", [])
            )
        )

        # Merge libraries from Tracee and SBOM
        loaded_libraries = list(
            set(
                tracee_profile.get("loaded_libraries", [])
                + sbom_data.get("loaded_components", [])
            )
        )

        job.execution_profile = {
            "sandbox_id": job.sandbox_id or "unknown",
            "duration_seconds": tracee_profile.get(
                "duration_seconds", duration_seconds
            ),
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
                "kubescape_vex": len(vex_document.get("statements") or []) > 0,
            },
            "vex_statements": len(vex_document.get("statements") or []),
            "filtered_components": sbom_data.get("component_count", 0),
            "profiling_enabled": config.get("enable_profiling", True),
            "profiling_success": kubescape_results.get("has_profiling", False),
            "summary": summary,  # Store the summary here for reference
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

        # Store combined security findings from OWASP ZAP and pentesting scans
        if zap_results or pentest_results:
            # Format ZAP results for merging
            zap_formatted = None
            if zap_results:
                zap_formatted = {
                    "status": zap_results.get("status", "unknown"),
                    "scan_duration_seconds": zap_results.get("scan_duration_seconds"),
                    "target_urls": zap_results.get("scanned_urls", []),
                    "total_alerts": zap_results.get("summary", {}).get(
                        "total_alerts", 0
                    ),
                    "high_risk": zap_results.get("summary", {}).get("high_risk", 0),
                    "medium_risk": zap_results.get("summary", {}).get("medium_risk", 0),
                    "low_risk": zap_results.get("summary", {}).get("low_risk", 0),
                    "informational": zap_results.get("summary", {}).get(
                        "informational", 0
                    ),
                    "alerts": zap_results.get("alerts", []),
                    "scan_timestamp": datetime.utcnow().isoformat(),
                    "error_message": (
                        zap_results.get("error")
                        if zap_results.get("status") == "failed"
                        else None
                    ),
                }

            # Merge ZAP and pentest results
            job.security_findings = merge_security_findings(
                zap_formatted, pentest_results
            )

            # Add scan warnings if any were detected
            if hasattr(job, "_scan_warnings") and job._scan_warnings:
                if "warnings" not in job.security_findings:
                    job.security_findings["warnings"] = []
                job.security_findings["warnings"].extend(job._scan_warnings)
                logger.info(
                    f"[{job_id}] Added {len(job._scan_warnings)} scan warnings to security findings"
                )

            logger.info(
                f"[{job_id}] Stored combined security findings: "
                f"{job.security_findings.get('total_alerts')} total alerts "
                f"from {len(job.security_findings.get('scans', []))} scan types"
            )
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

            logger.info(
                f"[{job_id}] Calculated cost: {cost_credits} credits (base={base_cost}, duration={duration_cost})"
            )

            # Record billing event
            billing_service = BillingService(db)
            billing_service.record_analysis_cost(job.id, cost_credits)

            logger.info(f"[{job_id}] Billing event recorded: {cost_credits} credits")

        except Exception as billing_error:
            logger.error(
                f"[{job_id}] Failed to record billing event: {billing_error}",
                exc_info=True,
            )
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
                job = (
                    db.query(PremiumAnalysisJob)
                    .filter(PremiumAnalysisJob.id == job_id)
                    .first()
                )
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

                kubescape_service = KubescapeService(
                    namespace=settings.k8s_sandbox_namespace
                )
                kubescape_service.delete_service(service_name)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] Service cleanup failed: {cleanup_error}")

        if deployment_name:
            try:
                logger.info(f"[{job_id}] Cleaning up deployment {deployment_name}")
                _cleanup_workload(deployment_name)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] Deployment cleanup failed: {cleanup_error}")

            # CRITICAL: Clean up Kubescape CRDs to prevent etcd exhaustion
            try:
                logger.info(
                    f"[{job_id}] Cleaning up Kubescape CRDs for {deployment_name}"
                )
                _cleanup_kubescape_crds(deployment_name)
            except Exception as cleanup_error:
                logger.error(f"[{job_id}] CRD cleanup failed: {cleanup_error}")

        # Close database session
        db.close()
