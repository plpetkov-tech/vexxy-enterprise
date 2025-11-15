"""
Kubescape-based Task Implementation

Uses Kubescape for runtime analysis instead of manual Tracee profiling.
This is the real implementation that works with actual container images.
"""
from datetime import datetime
import logging
from typing import Dict
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
    Wait for deployment to be ready

    Args:
        deployment_name: Name of deployment
        timeout: Timeout in seconds

    Returns:
        True if ready, False if timeout
    """
    logger.info(f"Waiting for deployment {deployment_name} to be ready...")

    import time
    start_time = time.time()

    kubescape_service = get_kubescape_service()
    while time.time() - start_time < timeout:
        status = kubescape_service.get_deployment_status(deployment_name)

        if status['status'] == 'ready':
            logger.info(f"Deployment {deployment_name} is ready")
            return True

        logger.debug(f"Deployment status: {status}")
        time.sleep(5)

    logger.warning(f"Deployment {deployment_name} not ready after {timeout}s")
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


def extract_kubescape_results(
    deployment_name: str,
    image_digest: str,
    job_id: str
) -> Dict:
    """
    Extract VEX and filtered SBOM from Kubescape

    Args:
        deployment_name: Name of deployment
        image_digest: Image digest
        job_id: Job ID for evidence storage

    Returns:
        Dict with vex_document and filtered_sbom
    """
    logger.info(f"Extracting Kubescape analysis results for {deployment_name}")

    # Extract both VEX and filtered SBOM
    kubescape_service = get_kubescape_service()
    vex_document, filtered_sbom = kubescape_service.extract_kubescape_analysis(
        deployment_name=deployment_name,
        image_digest=image_digest
    )

    # Store as evidence
    if vex_document:
        evidence_storage.store_vex_document(job_id, vex_document)
        logger.info(f"Stored runtime VEX document: {len(vex_document.get('statements', []))} statements")
    else:
        logger.warning("No VEX document generated by Kubescape")

    if filtered_sbom:
        evidence_storage.store_filtered_sbom(job_id, filtered_sbom)
        component_count = len(filtered_sbom.get('components', []))
        logger.info(f"Stored filtered SBOM: {component_count} relevant components")
    else:
        logger.warning("No filtered SBOM generated by Kubescape")

    return {
        "vex_document": vex_document,
        "filtered_sbom": filtered_sbom,
        "has_vex": vex_document is not None,
        "has_filtered_sbom": filtered_sbom is not None
    }


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
    # Just enhance it with our metadata
    enhanced_vex = vex_document.copy()

    # Add VEXxy metadata
    if "@id" not in enhanced_vex:
        enhanced_vex["@id"] = f"https://vexxy.dev/vex/premium/{job.id}"

    if "author" not in enhanced_vex:
        enhanced_vex["author"] = "VEXxy Premium Analysis Service (powered by Kubescape)"

    # Add generation metadata
    enhanced_vex["vexxy_metadata"] = {
        "job_id": str(job.id),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "analysis_method": "kubescape_runtime",
        "tool_version": "kubescape",
        "confidence_level": "high"  # Kubescape provides high-confidence reachability
    }

    statements = enhanced_vex.get("statements", [])
    logger.info(f"Processed VEX document with {len(statements)} statements")

    return enhanced_vex


def generate_analysis_summary(vex_document: Dict, filtered_sbom: Dict) -> Dict:
    """
    Generate analysis summary from Kubescape results

    Args:
        vex_document: VEX document
        filtered_sbom: Filtered SBOM

    Returns:
        Summary dict
    """
    statements = vex_document.get("statements", []) if vex_document else []
    components = filtered_sbom.get("components", []) if filtered_sbom else []

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
        "analysis_method": "kubescape_runtime_reachability",
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
