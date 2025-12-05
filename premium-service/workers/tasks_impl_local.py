# Local-only implementation for premium analysis tasks
# Bypasses Kubernetes entirely for local development

import logging
from datetime import datetime
from typing import Dict, Any

from models import SessionLocal, PremiumAnalysisJob

logger = logging.getLogger(__name__)


def update_job_status(
    job_id: str, status: str, message: str | None = None, error_details: Dict[str, Any] | None = None
):
    """Update job status in database"""
    with SessionLocal() as session:
        try:
            job = (
                session.query(PremiumAnalysisJob)
                .filter(PremiumAnalysisJob.premium_job_id == job_id)
                .first()
            )
            if job:
                job.status = status
                if error_details:
                    job.error_message = str(error_details)
                session.commit()
                logger.info(f"Updated job {job_id} status to {status}")
        except Exception as e:
            logger.error(f"Failed to update job {job_id} status: {e}")
            session.rollback()


def ensure_kubescape_installed():
    """Local mode - always return True"""
    return True


def deploy_workload_for_analysis(image_ref: str, job_id: str) -> Dict[str, Any]:
    """Local mode - simulate workload deployment"""
    logger.info(f"Local mode: Simulating workload deployment for {image_ref}")
    return {
        "deployment_name": f"analysis-{job_id[:8]}",
        "namespace": "local",
        "status": "ready",
    }


def wait_for_workload_ready(deployment_name: str, namespace: str, job_id: str = "00000000") -> Dict[str, Any]:
    """Local mode - simulate workload ready"""
    logger.info(f"Local mode: Simulating workload ready for {deployment_name}")
    return {"status": "ready", "pod_name": f"analysis-{job_id[:8]}-pod"}


def run_owasp_zap_scan(image_ref: str, target_host: str, job_id: str) -> Dict[str, Any]:
    """Local mode - simulate ZAP scan"""
    logger.info(f"Local mode: Simulating ZAP scan for {image_ref}")
    # Simulate some basic findings
    return {
        "scan_results": {"high": 2, "medium": 5, "low": 10, "informational": 15},
        "zap_report": "Local mode simulated scan",
    }


def wait_for_kubescape_analysis(job_id: str) -> Dict[str, Any]:
    """Local mode - simulate analysis completion"""
    logger.info(f"Local mode: Simulating analysis completion for {job_id}")
    return {
        "status": "complete",
        "results": {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1234",
                    "severity": "high",
                    "description": "Simulated vulnerability",
                },
                {
                    "id": "CVE-2023-5678",
                    "severity": "medium",
                    "description": "Simulated vulnerability",
                },
            ]
        },
    }


def extract_kubescape_results(job_id: str) -> Dict[str, Any]:
    """Local mode - simulate result extraction"""
    logger.info(f"Local mode: Simulating result extraction for {job_id}")
    return {
        "exit_code": 0,
        "stdout": "Local mode simulated analysis output",
        "analysis_summary": {
            "total_vulnerabilities": 2,
            "critical": 0,
            "high": 1,
            "medium": 1,
            "low": 0,
        },
    }


def process_kubescape_vex(
    job_id: str, analysis_results: Dict[str, Any]
) -> Dict[str, Any]:
    """Local mode - simulate VEX processing"""
    logger.info(f"Local mode: Simulating VEX processing for {job_id}")
    return {
        "vex_document": {
            "id": f"vex-{job_id}",
            "author": "VEXxy Local Analysis",
            "timestamp": datetime.utcnow().isoformat(),
            "statements": [
                {
                    "vulnerability": "CVE-2023-1234",
                    "status": "not_affected",
                    "justification": "Local mode simulation",
                }
            ],
        }
    }


def convert_vex_statements_to_reachability(
    reachability_results: Dict[str, Any],
) -> Dict[str, Any]:
    """Local mode - convert VEX to reachability"""
    return {
        "reachability_analysis": {
            "total_functions": 10,
            "reachable_functions": 8,
            "unreachable_functions": 2,
        }
    }


def extract_sbom_component_data(image_ref: str) -> Dict[str, Any]:
    """Local mode - simulate SBOM extraction"""
    logger.info(f"Local mode: Simulating SBOM extraction for {image_ref}")
    return {
        "components": [
            {"name": "nginx", "version": "1.20.0", "type": "package"},
            {"name": "openssl", "version": "3.0.0", "type": "library"},
        ]
    }


def generate_analysis_summary(
    job_id: str, analysis_results: Dict[str, Any]
) -> Dict[str, Any]:
    """Local mode - generate analysis summary"""
    logger.info(f"Local mode: Generating analysis summary for {job_id}")
    return {
        "summary": {
            "job_id": job_id,
            "status": "complete",
            "timestamp": datetime.utcnow().isoformat(),
            "findings_count": 2,
            "analysis_duration_seconds": 300,
        }
    }


def cleanup_workload(deployment_name: str, namespace: str) -> Dict[str, Any]:
    """Local mode - simulate cleanup"""
    logger.info(f"Local mode: Simulating cleanup for {deployment_name}")
    return {"status": "cleaned"}
