"""
Kubescape-based Task Implementation

Uses Kubescape for runtime analysis instead of manual Tracee profiling.
This is the real implementation that works with actual container images.
"""

from datetime import datetime
import logging
import subprocess
from typing import Dict, List, Optional
from uuid import UUID

from models import JobStatus
from services import (
    KubescapeService,
    EvidenceStorage,
)

logger = logging.getLogger(__name__)

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

    logger.error(
        "Kubescape is not installed. It should have been installed during service startup."
    )
    return False


def deploy_workload_for_analysis(
    job, image_ref: str, image_digest: str, config: dict
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
    logger.info(
        f"Deploying workload for Kubescape analysis: {image_ref}@{image_digest}"
    )

    kubescape_service = get_kubescape_service()
    deployment_name = kubescape_service.deploy_workload_for_analysis(
        job_id=str(job.id),
        image_ref=image_ref,
        image_digest=image_digest,
        job_config=config,
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

        if status["status"] == "ready":
            logger.info(f"Deployment {deployment_name} is ready")
            return True

        # Log detailed failure info if available
        if "failure_details" in status:
            failure_details = status["failure_details"]

            # Check for container failures
            if failure_details.get("container_statuses"):
                for container in failure_details["container_statuses"]:
                    if not container.get("ready"):
                        container_name = container.get("container_name", "unknown")
                        state = container.get("state", "unknown")
                        reason = container.get("reason", "N/A")

                        logger.warning(
                            f"Container {container_name} not ready: state={state}, reason={reason}",
                            extra={
                                "deployment_name": deployment_name,
                                "container_status": container,
                            },
                        )

        logger.debug(f"Deployment status: {status}")
        time.sleep(2)  # Reduced from 5s to 2s for faster detection

    # Log final failure details on timeout
    logger.error(
        f"Deployment {deployment_name} not ready after {timeout}s",
        extra={
            "deployment_name": deployment_name,
            "timeout": timeout,
            "final_status": last_status,
        },
    )

    # Log specific failure reasons if available
    if last_status and "failure_details" in last_status:
        failure_summary = []
        for container in last_status["failure_details"].get("container_statuses", []):
            if not container.get("ready"):
                failure_summary.append(
                    f"{container.get('container_name')}: {container.get('reason', 'Unknown')}"
                )

        if failure_summary:
            logger.error(f"Container failures: {', '.join(failure_summary)}")

    return False


def wait_for_kubescape_analysis(
    deployment_name: str, analysis_duration: int = 300
) -> bool:
    """
    Wait for Kubescape to complete runtime analysis

    Args:
        deployment_name: Name of deployment being analyzed
        analysis_duration: How long to wait for analysis (seconds)
                          Note: This timeout is already calculated with appropriate buffer
                          by the tasks.py orchestrator, so we use it directly

    Returns:
        True if analysis completed, False if timeout
    """
    logger.info(
        f"Waiting for Kubescape runtime analysis (duration: {analysis_duration}s)..."
    )

    # Use the timeout directly - tasks.py already includes appropriate buffer
    # via the time_budget system (analysis_duration + adaptive buffer)
    timeout = analysis_duration

    kubescape_service = get_kubescape_service()
    success = kubescape_service.wait_for_kubescape_analysis(
        deployment_name=deployment_name, timeout_seconds=timeout
    )

    if success:
        logger.info("Kubescape analysis completed successfully")
    else:
        logger.warning("Kubescape analysis timeout")

    return success


def verify_application_responding(
    deployment_name: str,
    namespace: str,
    ports: List[int],
    health_check_path: str = "/",
    timeout: int = 60,
) -> Dict:
    """
    Verify that the application is actually responding on specified ports

    This is critical for security scanning - ZAP needs a responding application to scan.

    Args:
        deployment_name: Name of the deployment
        namespace: Kubernetes namespace
        ports: List of ports to check
        health_check_path: HTTP path to check (default: "/")
        timeout: Maximum time to wait for app to respond (seconds)

    Returns:
        Dict with:
        {
            "responding": bool,  # True if ANY port responds
            "ports_status": {port: {"status": str, "error": str}},
            "attempts": int,
            "first_response_time": float
        }
    """
    import requests
    import time

    logger.info(f"Verifying application is responding on ports {ports}...")

    service_name = f"{deployment_name}-svc"
    service_host = f"{service_name}.{namespace}.svc.cluster.local"

    ports_status = {}
    start_time = time.time()
    attempts = 0
    first_response_time = None

    # Try each port with exponential backoff
    max_attempts_per_port = 12  # ~60 seconds total with exponential backoff
    base_delay = 1

    for port in ports:
        port_responding = False

        for attempt in range(max_attempts_per_port):
            attempts += 1

            # Try both HTTP and HTTPS
            for protocol in ["http", "https"]:
                url = f"{protocol}://{service_host}:{port}{health_check_path}"

                try:
                    logger.debug(
                        f"Health check attempt {attempt + 1}/{max_attempts_per_port}: {url}"
                    )

                    response = requests.get(
                        url,
                        timeout=5,
                        verify=False,  # Skip SSL verification for self-signed certs
                        allow_redirects=True,
                    )

                    # Any HTTP response (even 404, 500) means app is responding
                    logger.info(
                        f"Application responding on {protocol}://{service_host}:{port} "
                        f"(status: {response.status_code})"
                    )

                    ports_status[port] = {
                        "status": "responding",
                        "protocol": protocol,
                        "status_code": response.status_code,
                        "error": None,
                    }

                    if first_response_time is None:
                        first_response_time = time.time() - start_time

                    port_responding = True
                    break  # Successfully connected

                except requests.exceptions.SSLError as e:
                    # SSL error might mean HTTPS is configured but with self-signed cert
                    # Try to continue anyway
                    logger.debug(f"SSL error on {url}: {e}")
                    if protocol == "https":
                        # Still consider it responding if we get SSL error
                        ports_status[port] = {
                            "status": "responding",
                            "protocol": "https",
                            "status_code": None,
                            "error": f"SSL cert issue: {str(e)[:100]}",
                        }
                        port_responding = True
                        break

                except requests.exceptions.ConnectionError as e:
                    logger.debug(f"Connection error on {url}: {e}")
                    continue  # Try next protocol

                except requests.exceptions.Timeout as e:
                    logger.debug(f"Timeout on {url}: {e}")
                    continue  # Try next protocol

                except Exception as e:
                    logger.debug(f"Unexpected error on {url}: {e}")
                    continue  # Try next protocol

            if port_responding:
                break  # Port is responding, move to next port

            # Check if we've exceeded timeout
            if time.time() - start_time > timeout:
                logger.warning(f"Health check timeout after {timeout}s")
                break

            # Exponential backoff
            delay = min(base_delay * (2**attempt), 10)  # Cap at 10 seconds
            time.sleep(delay)

        # Record final status for this port
        if not port_responding:
            ports_status[port] = {
                "status": "not_responding",
                "protocol": None,
                "status_code": None,
                "error": f"No response after {max_attempts_per_port} attempts",
            }

    # Determine overall status
    responding_ports = [
        p for p, status in ports_status.items() if status["status"] == "responding"
    ]

    result = {
        "responding": len(responding_ports) > 0,
        "ports_status": ports_status,
        "attempts": attempts,
        "first_response_time": first_response_time,
        "responding_ports": responding_ports,
        "non_responding_ports": [p for p in ports if p not in responding_ports],
    }

    if result["responding"]:
        logger.info(
            f"Application health check PASSED. "
            f"Responding on ports: {responding_ports}. "
            f"First response after {first_response_time:.2f}s."
        )
    else:
        logger.error(
            f"Application health check FAILED. "
            f"No response on any of the ports {ports} after {timeout}s. "
            f"Total attempts: {attempts}."
        )

    return result


def collect_container_logs(
    deployment_name: str,
    namespace: str,
    container_name: str = "target",
    tail_lines: int = 500,
) -> str:
    """
    Collect container startup logs for diagnostics

    Args:
        deployment_name: Name of the deployment
        namespace: Kubernetes namespace
        container_name: Name of the container (default: "target")
        tail_lines: Number of log lines to collect

    Returns:
        Container logs as string
    """
    try:
        result = subprocess.run(
            [
                "kubectl",
                "logs",
                f"deployment/{deployment_name}",
                "-n",
                namespace,
                "-c",
                container_name,
                f"--tail={tail_lines}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.debug(
                f"Collected {len(result.stdout)} bytes of logs from {container_name}"
            )
            return result.stdout
        else:
            error_msg = result.stderr or "Unknown error"
            logger.warning(f"Failed to collect logs from {container_name}: {error_msg}")
            return f"Failed to collect logs: {error_msg}"

    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout collecting logs from {container_name}")
        return "Log collection timed out after 30s"
    except Exception as e:
        logger.error(f"Error collecting logs from {container_name}: {e}")
        return f"Error collecting logs: {str(e)}"


def run_owasp_zap_scan(
    deployment_name: str,
    namespace: str,
    ports: List[int],
    job_id: UUID,
    enable_fuzzing: bool = True,
    time_budget: Optional[int] = None,
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
            zap_api_key=settings.zap_api_key,
        )

        # Check if ZAP is available
        if not zap_service.is_zap_available():
            logger.warning("OWASP ZAP is not available, skipping scan")
            return {
                "status": "skipped",
                "reason": "zap_not_available",
                "scanned_urls": [],
            }

        # Scan the Kubernetes service
        # Service DNS name: <deployment>-svc.<namespace>.svc.cluster.local
        service_name = f"{deployment_name}-svc"

        effective_budget = max(60, (time_budget - 30) if time_budget else 600)
        scan_depth = "medium"
        if effective_budget <= 180:
            scan_depth = "quick"
        elif effective_budget >= 900:
            scan_depth = "thorough"

        results = zap_service.scan_kubernetes_service(
            service_name=service_name,
            namespace=namespace,
            ports=ports,
            scan_depth=scan_depth,
            time_budget=effective_budget,
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
                "total_alerts": 0,
            },
        }
        # Still store the error result as evidence
        try:
            evidence_storage.store_fuzzing_results(job_id, error_result)
        except Exception:
            pass
        return error_result


def extract_tracee_profiling(deployment_name: str, job_id: UUID) -> Optional[Dict]:
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
    deployment_name: str, image_digest: str, job_id: UUID, enable_profiling: bool = True
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
        deployment_name=deployment_name, image_digest=image_digest
    )

    # Note: VEX document will be stored AFTER branding/enhancement in the main task
    # Here we just extract and return the raw Kubescape VEX
    if vex_document:
        # Handle case where statements field is null (Go nil slice marshals to JSON null)
        statements = vex_document.get("statements") or []
        logger.info(f"Extracted runtime VEX document: {len(statements)} statements")
    else:
        logger.warning("No VEX document generated by Kubescape")

    if filtered_sbom:
        evidence_storage.store_filtered_sbom(job_id, filtered_sbom)
        # Handle case where components field is null (Go nil slice marshals to JSON null)
        components = filtered_sbom.get("components") or []
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
        "has_profiling": tracee_profile is not None,
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
                # Check for subcomponents (actual vulnerable packages)
                subcomponents = product.get("subcomponents") or []
                if subcomponents:
                    # Extract from subcomponents (e.g., pkg:pypi/starlette@0.46.2)
                    for subcomponent in subcomponents:
                        subcomponent_id = subcomponent.get("@id", "")
                        if subcomponent_id and "/" in subcomponent_id:
                            # Extract package name from purl
                            # Example: pkg:pypi/starlette@0.46.2 -> starlette@0.46.2
                            package = subcomponent_id.split("/")[-1]
                            vulnerable_files.append(package)
                else:
                    # Fallback to product if no subcomponents
                    product_id = product.get("@id", "")
                    if product_id and "/" in product_id:
                        # Extract package name from purl
                        # Example: pkg:oci/nginx@sha256:abc123 -> nginx
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
                "executed_files": [],  # Will be populated from Tracee data in Phase 2
            }

            reachability_results.append(reachability_result)

        except Exception as e:
            logger.error(f"Failed to convert VEX statement: {e}", exc_info=True)
            continue

    logger.info(
        f"Converted {len(reachability_results)} VEX statements to reachability results"
    )
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
        "affected": 0.90,  # High confidence for confirmed affected
        "under_investigation": 0.60,  # Medium confidence for unclear cases
        "unknown": 0.50,  # Low confidence for unknown
    }

    confidence = base_confidence.get(status, 0.50)

    # Adjust based on justification quality
    high_confidence_justifications = [
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "component_not_present",
    ]

    if justification in high_confidence_justifications:
        confidence = min(0.98, confidence + 0.05)  # Boost confidence slightly

    return round(confidence, 2)


def process_kubescape_vex(vex_document: Dict | None, job) -> Dict:
    """
    Process Kubescape VEX document into our format

    Args:
        vex_document: Kubescape VEX document (can be None)
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
            "statements": [],
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
        "confidence_level": "high",  # Kubescape provides high-confidence reachability
    }

    # Handle case where statements field is null (Go nil slice marshals to JSON null)
    statements = enhanced_vex.get("statements") or []
    logger.info(f"Processed VEX document with {len(statements)} statements")

    return enhanced_vex


def extract_sbom_component_data(filtered_sbom: Dict | None) -> Dict:
    """
    Extract runtime component data from filtered SBOM

    The filtered SBOM from Kubescape contains only components that were
    actually used/loaded at runtime.

    Args:
        filtered_sbom: Filtered SBOM from Kubescape (can be None)

    Returns:
        Dict with extracted component info (files, libraries)
    """
    if not filtered_sbom:
        logger.warning("No filtered SBOM to process")
        return {"loaded_components": [], "component_files": [], "component_count": 0}

    components = filtered_sbom.get("components") or []
    loaded_components = []
    component_files = []

    for component in components:
        try:
            # Extract component name and version
            name = component.get("name", "")
            version = component.get("version", "")

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
        "component_count": len(loaded_components),
    }


def generate_analysis_summary(vex_document: Dict | None, filtered_sbom: Dict | None) -> Dict:
    """
    Generate analysis summary from Kubescape results

    Args:
        vex_document: VEX document (can be None)
        filtered_sbom: Filtered SBOM (can be None)

    Returns:
        Summary dict
    """
    # Handle case where statements/components fields are null (Go nil slice marshals to JSON null)
    statements = (vex_document.get("statements") or []) if vex_document else []
    components = (filtered_sbom.get("components") or []) if filtered_sbom else []

    # Count VEX statuses
    not_affected = sum(1 for s in statements if s.get("status") == "not_affected")
    affected = sum(1 for s in statements if s.get("status") == "affected")
    under_investigation = sum(
        1 for s in statements if s.get("status") == "under_investigation"
    )

    return {
        "total_cves_analyzed": len(statements),
        "not_affected": not_affected,
        "affected": affected,
        "under_investigation": under_investigation,
        "total_components_in_image": len(
            components
        ),  # This is filtered (relevant) count
        "analysis_method": "hybrid_kubescape_tracee_sbom",
        "confidence": "high",
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


def cleanup_kubescape_crds(deployment_name: str):
    """
    Delete Kubescape CRDs after extracting VEX results.

    CRITICAL: These CRDs consume etcd storage and must be cleaned up
    to prevent etcd quota exhaustion at scale. After 1000 analyses without
    cleanup, etcd can fill up causing complete cluster failure.

    Args:
        deployment_name: Name of the deployment (used as CRD name)
    """
    logger.info(f"Cleaning up Kubescape CRDs for {deployment_name}")
    kubescape_service = get_kubescape_service()

    # Delete VEX CRD
    try:
        kubescape_service.delete_custom_resource(
            group="spdx.softwarecomposition.kubescape.io",
            version="v1beta1",
            plural="openvulnerabilityexchangecontainers",
            name=deployment_name,
            namespace="vexxy-sandbox",
        )
        logger.info(f"Deleted VEX CRD for {deployment_name}")
    except Exception as e:
        logger.warning(
            f"Failed to delete VEX CRD for {deployment_name}: {e}", exc_info=True
        )

    # Delete SBOM CRD
    try:
        kubescape_service.delete_custom_resource(
            group="spdx.softwarecomposition.kubescape.io",
            version="v1beta1",
            plural="sbomsyftfiltereds",
            name=deployment_name,
            namespace="vexxy-sandbox",
        )
        logger.info(f"Deleted SBOM CRD for {deployment_name}")
    except Exception as e:
        logger.warning(
            f"Failed to delete SBOM CRD for {deployment_name}: {e}", exc_info=True
        )

    # Delete Vulnerability Manifest CRD
    try:
        kubescape_service.delete_custom_resource(
            group="spdx.softwarecomposition.kubescape.io",
            version="v1beta1",
            plural="vulnerabilitymanifests",
            name=deployment_name,
            namespace="vexxy-sandbox",
        )
        logger.info(f"Deleted VulnerabilityManifest CRD for {deployment_name}")
    except Exception as e:
        logger.warning(
            f"Failed to delete VulnerabilityManifest for {deployment_name}: {e}",
            exc_info=True,
        )


def extract_pentest_results(
    deployment_name: str, namespace: str, job_id: str
) -> Optional[Dict]:
    """
    Extract pentesting results from Kali sidecar container

    Args:
        deployment_name: Name of the deployment
        namespace: Kubernetes namespace
        job_id: Job ID for logging

    Returns:
        Pentest results dict or None if not available
    """
    logger.info(f"Extracting pentest results from {deployment_name}")

    try:
        kubescape_service = get_kubescape_service()

        # Get pod for this deployment
        pods = kubescape_service.core_v1.list_namespaced_pod(
            namespace=namespace, label_selector=f"job-id={job_id}"
        )

        if not pods.items:
            logger.warning(f"No pods found for deployment {deployment_name}")
            return None

        pod_name = pods.items[0].metadata.name

        # Check if pentest sidecar exists
        pod = pods.items[0]
        pentest_container = None
        for container_status in pod.status.container_statuses or []:
            if container_status.name == "pentest-sidecar":
                pentest_container = container_status
                break

        if not pentest_container:
            logger.info("Pentest sidecar not found (pentesting not enabled)")
            return None

        # Check container status
        if pentest_container.state.terminated:
            exit_code = pentest_container.state.terminated.exit_code
            if exit_code != 0:
                logger.warning(f"Pentest sidecar exited with code {exit_code}")

        # Extract results via kubectl exec
        from kubernetes.stream import stream

        exec_command = [
            "/bin/sh",
            "-c",
            'cat /pentest-output/report.json 2>/dev/null || echo "{}"',
        ]

        resp = stream(
            kubescape_service.core_v1.connect_get_namespaced_pod_exec,
            name=pod_name,
            namespace=namespace,
            container="pentest-sidecar",
            command=exec_command,
            stderr=True,
            stdin=False,
            stdout=True,
            tty=False,
            _preload_content=True,
        )

        if not resp or resp == "{}":
            logger.warning("Pentest results empty or not found")
            return None

        # Parse JSON
        import json

        logger.info(f"Raw pentest response (first 500 chars): {resp[:500]}")
        logger.info(f"Response type: {type(resp)}, length: {len(resp)}")
        results = json.loads(resp)

        logger.info(
            f"Pentest results extracted: {len(results.get('results', {}))} tool outputs"
        )
        return results

    except Exception as e:
        logger.error(f"Failed to extract pentest results: {e}", exc_info=True)
        return None


def parse_pentest_to_security_findings(pentest_results: Dict) -> Dict:
    """
    Transform pentesting.sh output into SecurityFindings schema

    Args:
        pentest_results: Raw pentest results from pentesting.sh script
                        Expected format: {"pentest_report": {"metadata": {...}, "findings": [...]}}

    Returns:
        Formatted security findings dict matching SecurityFindings schema
    """
    alerts = []

    # Extract from actual pentesting.sh output format
    pentest_report = pentest_results.get("pentest_report", {})
    findings = pentest_report.get("findings", [])
    metadata = pentest_report.get("metadata", {})

    logger.info(
        f"Parsing pentest results: {len(findings)} findings from {metadata.get('scanner', 'unknown')}"
    )

    # Transform findings to alerts
    for finding in findings:
        severity = finding.get("severity", "info").lower()

        # Map severity levels to risk categories expected by frontend
        risk_map = {
            "critical": "High",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Informational",
            "informational": "Informational",
        }
        risk = risk_map.get(severity, "Informational")

        # Create alert in format expected by SecurityFindings schema
        alert = {
            "alert_id": f"pentest_{finding.get('title', 'unknown').replace(' ', '_').lower()}",
            "name": finding.get("title", "Unknown Finding"),
            "risk": risk,
            "confidence": "Medium",
            "description": finding.get("description", ""),
            "solution": "Review security configuration and apply recommended fixes",
            "reference": finding.get("cve") or "Pentest Scan",
        }

        # Add optional fields if present
        if finding.get("cve"):
            alert["cveId"] = finding.get("cve")
        if finding.get("cwe"):
            alert["cweId"] = finding.get("cwe")

        alerts.append(alert)

    # Count by risk level
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in alerts:
        risk_counts[alert["risk"]] += 1

    logger.info(
        f"Pentest findings parsed: {len(alerts)} total alerts "
        f"(High: {risk_counts['High']}, Medium: {risk_counts['Medium']}, "
        f"Low: {risk_counts['Low']}, Info: {risk_counts['Informational']})"
    )

    return {
        "scan_type": "pentest",
        "status": "completed",
        "scan_duration_seconds": metadata.get("duration_seconds"),
        "target_urls": [metadata.get("target", "unknown")],
        "total_alerts": len(alerts),
        "high_risk": risk_counts["High"],
        "medium_risk": risk_counts["Medium"],
        "low_risk": risk_counts["Low"],
        "informational": risk_counts["Informational"],
        "alerts": alerts,
        "scan_timestamp": metadata.get("scan_start"),
        "scanner_version": metadata.get("scanner", "vexxy-kali-pentester"),
        "error_message": None,
    }


def check_pentest_container_status(
    deployment_name: str, namespace: str, job_id: str
) -> str:
    """
    Check pentest sidecar container status

    Args:
        deployment_name: Name of the deployment
        namespace: Kubernetes namespace
        job_id: Job ID

    Returns:
        Status string: "completed", "failed", "running", "waiting", "not_found", "unknown"
    """
    try:
        kubescape_service = get_kubescape_service()
        pods = kubescape_service.core_v1.list_namespaced_pod(
            namespace=namespace, label_selector=f"job-id={job_id}"
        )

        if not pods.items:
            return "not_found"

        pod = pods.items[0]
        for container_status in pod.status.container_statuses or []:
            if container_status.name == "pentest-sidecar":
                if container_status.state.terminated:
                    exit_code = container_status.state.terminated.exit_code
                    return "completed" if exit_code == 0 else "failed"
                elif container_status.state.running:
                    return "running"
                elif container_status.state.waiting:
                    return "waiting"

        return "not_found"
    except Exception as e:
        logger.error(f"Failed to check pentest status: {e}")
        return "unknown"


def run_pentest_scan(
    deployment_name: str,
    namespace: str,
    ports: List[int],
    job_id: str,
    enable_pentesting: bool = True,
    pentest_timeout: int = 1200,
) -> Optional[Dict]:
    """
    Run pentesting scan and return formatted results with enhanced error handling

    Args:
        deployment_name: Name of the deployment
        namespace: Kubernetes namespace
        ports: List of ports to scan
        job_id: Job ID for logging
        enable_pentesting: Whether pentesting is enabled
        pentest_timeout: Maximum wait time for pentest scan in seconds (default: 1200s / 20 min)

    Returns:
        Formatted security findings dict, or None if skipped
    """
    if not enable_pentesting or not ports:
        return None

    logger.info(f"Starting pentest scan on {deployment_name} ports {ports}")

    try:
        # Wait for pentest sidecar to complete
        import time

        max_wait = pentest_timeout  # Use configurable timeout
        start_time = time.time()
        last_logged_status = None

        while time.time() - start_time < max_wait:
            status = check_pentest_container_status(deployment_name, namespace, job_id)

            # Log status transitions for visibility
            if status != last_logged_status:
                elapsed = time.time() - start_time
                logger.info(
                    f"Pentest container status: {last_logged_status} -> {status} (elapsed: {elapsed:.1f}s)"
                )
                last_logged_status = status

                # Fetch container logs for debugging on failure or waiting states
                if status in ["waiting", "failed"]:
                    try:
                        kubescape_service = get_kubescape_service()
                        pods = kubescape_service.core_v1.list_namespaced_pod(
                            namespace=namespace, label_selector=f"job-id={job_id}"
                        )
                        if pods.items:
                            pod_name = pods.items[0].metadata.name
                            logs = kubescape_service.core_v1.read_namespaced_pod_log(
                                name=pod_name,
                                namespace=namespace,
                                container="pentest-sidecar",
                                tail_lines=50,
                            )
                            logger.error(
                                f"Pentest sidecar logs (last 50 lines):\n{logs}"
                            )
                    except Exception as log_err:
                        logger.warning(
                            f"Could not fetch pentest container logs: {log_err}"
                        )

            if status == "completed":
                logger.info("Pentest sidecar completed successfully")
                break
            elif status == "failed":
                logger.error("Pentest sidecar failed - check logs above")
                return {
                    "status": "failed",
                    "error": "Pentest container exited with error",
                }
            elif status == "not_found":
                logger.error("Pentest sidecar container not found in pod")
                return {
                    "status": "failed",
                    "error": "Pentest sidecar not found - may not be enabled or configured correctly",
                }

            time.sleep(10)  # Check every 10 seconds

        # Check if we timed out
        elapsed_total = time.time() - start_time
        if elapsed_total >= max_wait:
            logger.warning(
                f"Pentest scan timeout after {elapsed_total:.1f}s (max: {max_wait}s)"
            )
            return {
                "status": "failed",
                "error": f"Pentest scan timeout after {max_wait}s",
            }

        # Extract and parse results
        pentest_raw = extract_pentest_results(deployment_name, namespace, job_id)

        if not pentest_raw:
            logger.warning(
                "No pentest results available - results file may not have been created"
            )
            return {"status": "skipped", "reason": "no_results_found"}

        pentest_findings = parse_pentest_to_security_findings(pentest_raw)

        logger.info(
            f"Pentest scan completed: {pentest_findings['total_alerts']} alerts found"
        )
        return pentest_findings

    except Exception as e:
        logger.error(f"Pentest scan failed with exception: {e}", exc_info=True)
        return {"status": "failed", "error": str(e)}
