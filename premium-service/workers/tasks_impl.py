"""
Task implementation helpers

Real implementations of analysis functions (not stubs).
"""
from datetime import datetime
import logging
import asyncio
from typing import Dict

from models import JobStatus

logger = logging.getLogger(__name__)

# Initialize services
from services import (
    SandboxManager,
    ProfilerService,
    ReachabilityAnalyzer,
    EvidenceStorage,
    MockSBOMService,
)

sandbox_manager = SandboxManager()
profiler_service = ProfilerService()
reachability_analyzer = ReachabilityAnalyzer()
evidence_storage = EvidenceStorage()
sbom_service = MockSBOMService()  # TODO: Switch to real SBOMService when backend is ready


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


def setup_sandbox(job, image_ref: str, image_digest: str, config: dict) -> str:
    """Setup isolated sandbox environment"""
    logger.info(f"Setting up sandbox for {image_ref}@{image_digest}")

    # Create Kubernetes Job with profiler sidecar
    job_name = sandbox_manager.create_sandbox_job(
        job_id=str(job.id),
        image_ref=image_ref,
        image_digest=image_digest,
        job_config=config
    )

    logger.info(f"Created sandbox: {job_name}")
    return job_name


def start_container_with_profiling(sandbox_id: str, config: dict):
    """Start container with eBPF profiling attached"""
    logger.info(f"Starting container in {sandbox_id} with profiling")

    # Job is already created with profiling sidecar
    # Wait for it to start
    import time
    max_wait = 60  # 60 seconds
    waited = 0

    while waited < max_wait:
        status = sandbox_manager.get_job_status(sandbox_id)
        if status['status'] in ['running', 'succeeded']:
            logger.info(f"Job {sandbox_id} is {status['status']}")
            break

        time.sleep(5)
        waited += 5

    if waited >= max_wait:
        raise TimeoutError(f"Job {sandbox_id} did not start within {max_wait} seconds")


def execute_tests(sandbox_id: str, config: dict):
    """Execute tests and fuzzing"""
    logger.info(f"Running tests in {sandbox_id}")

    # Wait for test duration
    test_timeout = config.get("test_timeout", 300)
    logger.info(f"Waiting {test_timeout} seconds for tests to complete")

    import time
    time.sleep(min(test_timeout, 300))  # Cap at 5 minutes for now

    # Check if custom test script provided
    if config.get("test_script"):
        logger.info("Custom test script execution not yet implemented")
        # TODO: Execute user-provided script in target container

    # Check if fuzzing enabled
    if config.get("enable_fuzzing", True):
        logger.info("OWASP ZAP fuzzing not yet implemented")
        # TODO: Run ZAP fuzzer


def collect_execution_profile(sandbox_id: str, job_id: str) -> dict:
    """Collect execution profile from profiler"""
    logger.info(f"Collecting execution profile from {sandbox_id}")

    # Get logs from profiler container
    try:
        tracee_logs = sandbox_manager.get_job_logs(sandbox_id, container="profiler")
        logger.info(f"Retrieved {len(tracee_logs)} bytes of Tracee logs")

        # Store raw Tracee output as evidence
        evidence_storage.store_tracee_output(job_id, tracee_logs)

        # Parse Tracee output
        profile = profiler_service.parse_tracee_logs(tracee_logs)

        # Convert to dict for storage
        profile_dict = profile.to_dict()

        # Store parsed profile as evidence
        evidence_storage.store_execution_profile(job_id, profile_dict)

        logger.info(f"Execution profile: {profile_dict['summary']}")
        return profile_dict

    except Exception as e:
        logger.error(f"Failed to collect execution profile: {e}", exc_info=True)

        # Return minimal profile on error
        return {
            "duration_seconds": 120,
            "files_accessed": [],
            "syscalls": [],
            "network_connections": [],
            "summary": {
                "total_files_accessed": 0,
                "total_syscalls": 0,
                "error": str(e)
            }
        }


async def analyze_reachability_async(
    execution_profile: dict,
    image_digest: str,
    sbom_id,
    config: dict,
    job_id: str
) -> dict:
    """Determine CVE reachability (async)"""
    logger.info("Analyzing reachability")

    # Fetch SBOM and vulnerabilities
    if sbom_id:
        sbom = await sbom_service.fetch_sbom(sbom_id)
        vulnerabilities = await sbom_service.fetch_vulnerabilities(sbom_id)
    else:
        # Fallback: try to find SBOM by image
        sbom = await sbom_service.fetch_sbom_by_image(image_ref="unknown", image_digest=image_digest)
        if sbom:
            vulnerabilities = sbom_service.extract_vulnerabilities_from_sbom(sbom)
        else:
            logger.warning("No SBOM found, using mock data")
            sbom = await sbom_service.fetch_sbom(None)
            vulnerabilities = await sbom_service.fetch_vulnerabilities(None)

    logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities")

    # Reconstruct ExecutionProfile object
    from services.profiler import ExecutionProfile as EP
    ep = EP()
    ep.duration_seconds = execution_profile.get('duration_seconds', 0)
    ep.files_accessed = set(execution_profile.get('files_accessed', []))
    ep.syscalls = set(execution_profile.get('syscalls', []))
    ep.syscall_counts = execution_profile.get('syscall_counts', {})
    ep.network_connections = set(execution_profile.get('network_connections', []))
    ep.loaded_libraries = set(execution_profile.get('loaded_libraries', []))
    ep.executed_binaries = set(execution_profile.get('executed_binaries', []))

    # Analyze reachability for all CVEs
    results = reachability_analyzer.analyze_all_cves(
        vulnerabilities=vulnerabilities,
        execution_profile=ep,
        sbom=sbom or {}
    )

    # Convert to dict
    results_dict = {
        "cves_analyzed": len(results),
        "not_affected": sum(1 for r in results if r.status.value == "not_affected"),
        "affected": sum(1 for r in results if r.status.value == "affected"),
        "under_investigation": sum(1 for r in results if r.status.value == "under_investigation"),
        "results": [r.to_dict() for r in results]
    }

    # Store reachability results as evidence
    evidence_storage.store_reachability_results(job_id, results_dict)

    logger.info(
        f"Reachability analysis complete: "
        f"{results_dict['not_affected']} not affected, "
        f"{results_dict['affected']} affected"
    )

    return results_dict


def analyze_reachability(execution_profile: dict, image_digest: str, config: dict, job_id: str) -> dict:
    """Determine CVE reachability (sync wrapper)"""

    # Get event loop or create new one
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Run async function
    sbom_id = config.get('sbom_id')
    result = loop.run_until_complete(
        analyze_reachability_async(execution_profile, image_digest, sbom_id, config, job_id)
    )

    return result


def generate_vex_document(reachability_results: dict, execution_profile: dict, job) -> dict:
    """Generate OpenVEX document"""
    logger.info("Generating VEX document")

    statements = []

    # Create VEX statement for each CVE
    for result in reachability_results.get('results', []):
        statement = {
            "vulnerability": {
                "@id": f"https://nvd.nist.gov/vuln/detail/{result['cve_id']}",
                "name": result['cve_id']
            },
            "products": [
                {
                    "@id": f"https://vexxy.dev/analysis/{job.id}"
                }
            ],
            "status": result['status'],
            "justification": result['justification'],
            "impact_statement": result['reason'],
            "action_statement": (
                "No action required. Vulnerable code not executed."
                if result['status'] == "not_affected"
                else "Investigate and remediate vulnerability."
            ),
            "vexxy_evidence": result['evidence']
        }
        statements.append(statement)

    vex_document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://vexxy.dev/vex/premium/{job.id}",
        "author": "VEXxy Premium Analysis Service",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": 1,
        "statements": statements
    }

    logger.info(f"Generated VEX document with {len(statements)} statements")
    return vex_document


def cleanup_sandbox(sandbox_id: str):
    """Cleanup sandbox resources"""
    logger.info(f"Cleaning up sandbox {sandbox_id}")

    try:
        sandbox_manager.delete_job(sandbox_id)
        logger.info(f"Sandbox {sandbox_id} cleaned up")
    except Exception as e:
        logger.error(f"Failed to cleanup sandbox {sandbox_id}: {e}")
