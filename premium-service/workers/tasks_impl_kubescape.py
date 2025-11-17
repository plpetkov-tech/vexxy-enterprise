"""
Kubescape-based Task Implementation

Uses Kubescape for runtime analysis instead of manual Tracee profiling.
This is the real implementation that works with actual container images.
"""
from datetime import datetime
import logging
from typing import Dict, List, Optional
import json

from models import JobStatus

logger = logging.getLogger(__name__)

# Initialize services (lazy initialization for KubescapeService)
from services import (
    KubescapeService,
    EvidenceStorage,
)

# Lazy initialization to avoid loading kube config at import time
_kubescape_service = None
evidence_storage = EvidenceStorage()


def get_kubescape_service() -> KubescapeService:
    """Get or create KubescapeService instance (lazy initialization)"""
    global _kubescape_service
    if _kubescape_service is None:
        _kubescape_service = KubescapeService()
    return _kubescape_service


def update_job_status(db, job, status: JobStatus, progress: int, phase: str):
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


def ensure_kubescape_installed() -> bool:
    """
    Check that Kubescape is installed in the cluster

    Note: Kubescape should be installed during service startup.
    This function only verifies the installation exists.

    Returns:
        True if installed, False otherwise
    """
    logger.info("Verifying Kubescape installation...")

    kubescape_service = get_kubescape_service()
    if kubescape_service.is_kubescape_installed():
        logger.info("Kubescape is installed and ready")
        return True

    logger.error("Kubescape is not installed. It should have been installed during service startup.")
    return False


def deploy_workload_for_analysis(
    job,
    image_ref: str,
    image_digest: str,
    config: dict
) -> str:
    """
    Deploy workload that Kubescape will analyze

    Args:
        job: Analysis job model
        image_ref: Container image reference
        image_digest: Image digest
        config: Job configuration

    Returns:
        deployment_name: Name of created deployment
    """
    logger.info(f"Deploying workload for Kubescape analysis: {image_ref}@{image_digest}")

    kubescape_service = get_kubescape_service()
    deployment_name = kubescape_service.deploy_workload_for_analysis(
        job_id=str(job.id),
        image_ref=image_ref,
        image_digest=image_digest,
        job_config=config
    )

    logger.info(f"Deployment created: {deployment_name}")
    return deployment_name


def wait_for_workload_ready(deployment_name: str, timeout: int = 120) -> bool:
    """
    Wait for deployment to be ready with detailed failure reporting

    Args:
        deployment_name: Name of deployment
        timeout: Timeout in seconds

    Returns:
        True if ready, False if timeout or failure
    """
    logger.info(f"Waiting for deployment {deployment_name} to be ready...")

    import time
    start_time = time.time()
    last_status = None

    kubescape_service = get_kubescape_service()
    while time.time() - start_time < timeout:
        status = kubescape_service.get_deployment_status(deployment_name)
        last_status = status

        if status['status'] == 'ready':
            logger.info(f"Deployment {deployment_name} is ready")
            return True

        # Log detailed failure info if available
        if 'failure_details' in status:
            failure_details = status['failure_details']

            # Check for container failures
            if failure_details.get('container_statuses'):
                for container in failure_details['container_statuses']:
                    if not container.get('ready'):
                        container_name = container.get('container_name', 'unknown')
                        state = container.get('state', 'unknown')
                        reason = container.get('reason', 'N/A')

                        logger.warning(
                            f"Container {container_name} not ready: state={state}, reason={reason}",
                            extra={
                                "deployment_name": deployment_name,
                                "container_status": container
                            }
                        )

        logger.debug(f"Deployment status: {status}")
        time.sleep(5)

    # Log final failure details on timeout
    logger.error(
        f"Deployment {deployment_name} not ready after {timeout}s",
        extra={
            "deployment_name": deployment_name,
            "timeout": timeout,
            "final_status": last_status
        }
    )

    # Log specific failure reasons if available
    if last_status and 'failure_details' in last_status:
        failure_summary = []
        for container in last_status['failure_details'].get('container_statuses', []):
            if not container.get('ready'):
                failure_summary.append(
                    f"{container.get('container_name')}: {container.get('reason', 'Unknown')}"
                )

        if failure_summary:
            logger.error(f"Container failures: {', '.join(failure_summary)}")

    return False


def wait_for_kubescape_analysis(
    deployment_name: str,
    analysis_duration: int = 300
) -> bool:
    """
    Wait for Kubescape to complete runtime analysis

    Args:
        deployment_name: Name of deployment being analyzed
        analysis_duration: How long to wait for analysis (seconds)

    Returns:
        True if analysis completed, False if timeout
    """
    logger.info(f"Waiting for Kubescape runtime analysis (duration: {analysis_duration}s)...")

    # Add buffer time for Kubescape to process
    timeout = analysis_duration + 120

    kubescape_service = get_kubescape_service()
    success = kubescape_service.wait_for_kubescape_analysis(
        deployment_name=deployment_name,
        timeout_seconds=timeout
    )

    if success:
        logger.info("Kubescape analysis completed successfully")
    else:
        logger.warning("Kubescape analysis timeout")

    return success


def run_owasp_zap_scan(
    deployment_name: str,
    namespace: str,
    ports: List[int],
    job_id: str,
    enable_fuzzing: bool = True
) -> Optional[Dict]:
    """
    Run OWASP ZAP security scan against the deployed workload

    Args:
        deployment_name: Name of the deployment
        namespace: Kubernetes namespace
        ports: List of ports to scan
        job_id: Job ID for evidence storage
        enable_fuzzing: Whether fuzzing is enabled in config

    Returns:
        ZAP scan results dict, or None if scan was skipped
    """
    if not enable_fuzzing:
        logger.info("OWASP ZAP scanning disabled in config")
        return None

    if not ports:
        logger.info("No ports specified for OWASP ZAP scanning")
        return None

    logger.info(f"Starting OWASP ZAP scan on {deployment_name} ports {ports}")

    try:
        from services import ZAPService
        from config.settings import settings

        # Initialize ZAP service
        # Note: When running outside K8s (docker-compose), use kubectl port-forward:
        #   kubectl port-forward -n security svc/owasp-zap 8080:8080
        zap_service = ZAPService(
            zap_host=settings.zap_host,
            zap_port=settings.zap_port,
            zap_api_key=settings.zap_api_key
        )

        # Check if ZAP is available
        if not zap_service.is_zap_available():
            logger.warning("OWASP ZAP is not available, skipping scan")
            return {
                "status": "skipped",
                "reason": "zap_not_available",
                "scanned_urls": []
            }

        # Scan the Kubernetes service
        # Service DNS name: <deployment>-svc.<namespace>.svc.cluster.local
        service_name = f"{deployment_name}-svc"

        results = zap_service.scan_kubernetes_service(
            service_name=service_name,
            namespace=namespace,
            ports=ports,
            scan_depth="medium"  # Could be made configurable
        )

        # Store results as evidence
        evidence_storage.store_fuzzing_results(job_id, results)

        logger.info(
            f"ZAP scan completed: {results['summary']['total_alerts']} alerts found "
            f"(High: {results['summary']['high_risk']}, "
            f"Medium: {results['summary']['medium_risk']}, "
            f"Low: {results['summary']['low_risk']})"
        )

        return results

    except Exception as e:
        logger.error(f"OWASP ZAP scan failed: {e}", exc_info=True)
        # Return error result instead of failing the entire job
        error_result = {
            "status": "failed",
            "error": str(e),
            "scanned_urls": [],
            "summary": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "informational": 0,
                "total_alerts": 0
            }
        }
        # Still store the error result as evidence
        try:
            evidence_storage.store_fuzzing_results(job_id, error_result)
        except:
            pass
        return error_result


def extract_tracee_profiling(
    deployment_name: str,
    job_id: str
) -> Optional[Dict]:
    """
    Extract Tracee profiling data and parse into execution profile

    Args:
        deployment_name: Name of deployment
        job_id: Job ID for evidence storage

    Returns:
        Execution profile dict, or None if profiling failed
    """
    logger.info(f"Extracting Tracee profiling data for {deployment_name}")

    try:
        kubescape_service = get_kubescape_service()
        tracee_output = kubescape_service.extract_tracee_profiling_data(deployment_name)

        if not tracee_output:
            logger.warning("No Tracee profiling data found")
            return None

        # Store raw Tracee output as evidence
        evidence_storage.store_profiling_data(job_id, {"tracee_events": tracee_output})

        # Parse Tracee output using ProfilerService
        from services import ProfilerService
        profiler_service = ProfilerService()
        execution_profile = profiler_service.parse_tracee_logs(tracee_output)

        logger.info(f"Parsed Tracee data: {execution_profile.to_dict()['summary']}")
        return execution_profile.to_dict()

    except Exception as e:
        logger.error(f"Failed to extract Tracee profiling: {e}", exc_info=True)
        return None


def extract_kubescape_results(
    deployment_name: str,
    image_digest: str,
    job_id: str,
    enable_profiling: bool = True
) -> Dict:
    """
    Extract VEX, filtered SBOM, and Tracee profiling data

    Args:
        deployment_name: Name of deployment
        image_digest: Image digest
        job_id: Job ID for evidence storage
        enable_profiling: Whether Tracee profiling was enabled

    Returns:
        Dict with vex_document, filtered_sbom, and tracee_profile
    """
    logger.info(f"Extracting analysis results for {deployment_name}")

    # Extract both VEX and filtered SBOM from Kubescape
    kubescape_service = get_kubescape_service()
    vex_document, filtered_sbom = kubescape_service.extract_kubescape_analysis(
        deployment_name=deployment_name,
        image_digest=image_digest
    )

    # Note: VEX document will be stored AFTER branding/enhancement in the main task
    # Here we just extract and return the raw Kubescape VEX
    vex_id = None
    if vex_document:
        # Handle case where statements field is null (Go nil slice marshals to JSON null)
        statements = vex_document.get('statements') or []
        logger.info(f"Extracted runtime VEX document: {len(statements)} statements")
    else:
        logger.warning("No VEX document generated by Kubescape")

    if filtered_sbom:
        evidence_storage.store_filtered_sbom(job_id, filtered_sbom)
        # Handle case where components field is null (Go nil slice marshals to JSON null)
        components = filtered_sbom.get('components') or []
        component_count = len(components)
        logger.info(f"Stored filtered SBOM: {component_count} relevant components")
    else:
        logger.warning("No filtered SBOM generated by Kubescape")

    # Extract Tracee profiling if enabled
    tracee_profile = None
    if enable_profiling:
        tracee_profile = extract_tracee_profiling(deployment_name, job_id)

    return {
        "vex_document": vex_document,
        "filtered_sbom": filtered_sbom,
        "tracee_profile": tracee_profile,
        "has_vex": vex_document is not None,
        "has_filtered_sbom": filtered_sbom is not None,
        "has_profiling": tracee_profile is not None
    }


def convert_vex_statements_to_reachability(vex_document: Dict) -> List[Dict]:
    """
    Convert Kubescape VEX statements to ReachabilityResult format

    Kubescape VEX statements are in OpenVEX format with structure:
    {
        "vulnerability": {"name": "CVE-XXXX-XXXXX"},
        "status": "affected" | "not_affected" | "under_investigation",
        "justification": "component_not_present" | "vulnerable_code_not_present" | etc.,
        "statement": "Human-readable explanation",
        "products": [{"@id": "pkg:..."}]
    }

    Args:
        vex_document: Kubescape VEX document

    Returns:
        List of ReachabilityResult dicts
    """
    if not vex_document:
        logger.warning("No VEX document to convert")
        return []

    statements = vex_document.get("statements") or []
    reachability_results = []

    for statement in statements:
        try:
            # Extract vulnerability info
            vulnerability = statement.get("vulnerability", {})
            cve_id = vulnerability.get("name", "UNKNOWN")

            # Extract status
            status = statement.get("status", "unknown")

            # Extract justification and reasoning
            justification = statement.get("justification", "")
            reasoning = statement.get("statement", "")

            # Extract affected products/components
            products = statement.get("products") or []
            vulnerable_files = []

            for product in products:
                # Products are in purl format: pkg:type/namespace/name@version
                product_id = product.get("@id", "")
                if product_id:
                    # Extract package name from purl
                    # Example: pkg:oci/nginx@sha256:abc123 -> nginx
                    if "/" in product_id:
                        package = product_id.split("/")[-1].split("@")[0]
                        vulnerable_files.append(package)

            # Calculate confidence score based on justification and status
            confidence_score = _calculate_confidence_score(status, justification)

            # Build reason combining justification and statement
            reason_parts = []
            if justification:
                reason_parts.append(f"Justification: {justification}")
            if reasoning:
                reason_parts.append(reasoning)
            reason = " | ".join(reason_parts) if reason_parts else "No details provided"

            # Extract action information if present
            action = statement.get("action_statement", "")
            if action:
                reason += f" | Action: {action}"

            reachability_result = {
                "cve_id": cve_id,
                "status": status,
                "justification": justification or None,
                "confidence_score": confidence_score,
                "reason": reason,
                "vulnerable_files": vulnerable_files,
                "executed_files": []  # Will be populated from Tracee data in Phase 2
            }

            reachability_results.append(reachability_result)

        except Exception as e:
            logger.error(f"Failed to convert VEX statement: {e}", exc_info=True)
            continue

    logger.info(f"Converted {len(reachability_results)} VEX statements to reachability results")
    return reachability_results


def _calculate_confidence_score(status: str, justification: str) -> float:
    """
    Calculate confidence score based on VEX status and justification

    Kubescape provides high-confidence runtime analysis, so base scores are high.

    Args:
        status: VEX status (affected/not_affected/under_investigation)
        justification: VEX justification code

    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Base confidence for Kubescape runtime analysis
    base_confidence = {
        "not_affected": 0.95,  # Very high confidence when Kubescape says not affected
        "affected": 0.90,      # High confidence for confirmed affected
        "under_investigation": 0.60,  # Medium confidence for unclear cases
        "unknown": 0.50        # Low confidence for unknown
    }

    confidence = base_confidence.get(status, 0.50)

    # Adjust based on justification quality
    high_confidence_justifications = [
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "component_not_present"
    ]

    if justification in high_confidence_justifications:
        confidence = min(0.98, confidence + 0.05)  # Boost confidence slightly

    return round(confidence, 2)


def process_kubescape_vex(vex_document: Dict, job) -> Dict:
    """
    Process Kubescape VEX document into our format

    Args:
        vex_document: Kubescape VEX document
        job: Analysis job

    Returns:
        Processed VEX document with metadata
    """
    if not vex_document:
        logger.warning("No VEX document to process")
        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://vexxy.dev/vex/premium/{job.id}",
            "author": "VEXxy Premium Analysis Service",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version": 1,
            "statements": []
        }

    # Kubescape VEX is already in OpenVEX format
    # Rebrand it with VEXxy metadata
    enhanced_vex = vex_document.copy()

    # Override Kubescape branding with VEXxy branding
    enhanced_vex["author"] = "VEXxy Premium Analysis Service"
    enhanced_vex["role"] = "Automated VEX Document Generator"
    enhanced_vex["tooling"] = "vexxy-premium-service"

    # Keep or set the document ID
    if "@id" not in enhanced_vex:
        enhanced_vex["@id"] = f"https://vexxy.dev/vex/premium/{job.id}"

    # Add generation metadata
    enhanced_vex["vexxy_metadata"] = {
        "job_id": str(job.id),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "analysis_method": "kubescape_runtime",
        "analysis_engine": "kubescape",  # Credit the underlying engine
        "confidence_level": "high"  # Kubescape provides high-confidence reachability
    }

    # Handle case where statements field is null (Go nil slice marshals to JSON null)
    statements = enhanced_vex.get("statements") or []
    logger.info(f"Processed VEX document with {len(statements)} statements")

    return enhanced_vex


def extract_sbom_component_data(filtered_sbom: Dict) -> Dict:
    """
    Extract runtime component data from filtered SBOM

    The filtered SBOM from Kubescape contains only components that were
    actually used/loaded at runtime.

    Args:
        filtered_sbom: Filtered SBOM from Kubescape

    Returns:
        Dict with extracted component info (files, libraries)
    """
    if not filtered_sbom:
        logger.warning("No filtered SBOM to process")
        return {
            "loaded_components": [],
            "component_files": [],
            "component_count": 0
        }

    components = filtered_sbom.get("components") or []
    loaded_components = []
    component_files = []

    for component in components:
        try:
            # Extract component name and version
            name = component.get("name", "")
            version = component.get("version", "")
            purl = component.get("purl", "")

            # Extract file paths from component properties
            properties = component.get("properties") or []
            for prop in properties:
                if prop.get("name") == "syft:location:path":
                    path = prop.get("value", "")
                    if path:
                        component_files.append(path)

            # Add to loaded components list
            if name:
                component_info = f"{name}"
                if version:
                    component_info += f"@{version}"
                loaded_components.append(component_info)

        except Exception as e:
            logger.warning(f"Failed to process SBOM component: {e}")
            continue

    logger.info(
        f"Extracted {len(loaded_components)} loaded components, "
        f"{len(component_files)} component file paths from filtered SBOM"
    )

    return {
        "loaded_components": loaded_components,
        "component_files": component_files,
        "component_count": len(loaded_components)
    }


def generate_analysis_summary(vex_document: Dict, filtered_sbom: Dict) -> Dict:
    """
    Generate analysis summary from Kubescape results

    Args:
        vex_document: VEX document
        filtered_sbom: Filtered SBOM

    Returns:
        Summary dict
    """
    # Handle case where statements/components fields are null (Go nil slice marshals to JSON null)
    statements = (vex_document.get("statements") or []) if vex_document else []
    components = (filtered_sbom.get("components") or []) if filtered_sbom else []

    # Count VEX statuses
    not_affected = sum(1 for s in statements if s.get("status") == "not_affected")
    affected = sum(1 for s in statements if s.get("status") == "affected")
    under_investigation = sum(1 for s in statements if s.get("status") == "under_investigation")

    return {
        "total_cves_analyzed": len(statements),
        "not_affected": not_affected,
        "affected": affected,
        "under_investigation": under_investigation,
        "total_components_in_image": len(components),  # This is filtered (relevant) count
        "analysis_method": "hybrid_kubescape_tracee_sbom",
        "confidence": "high"
    }


def cleanup_workload(deployment_name: str):
    """
    Cleanup analysis workload

    Args:
        deployment_name: Name of deployment to delete
    """
    logger.info(f"Cleaning up workload {deployment_name}")

    try:
        kubescape_service = get_kubescape_service()
        kubescape_service.delete_workload(deployment_name)
        logger.info(f"Workload {deployment_name} cleaned up")
    except Exception as e:
        logger.error(f"Failed to cleanup workload {deployment_name}: {e}")
