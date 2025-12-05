"""
Kubernetes Sandbox Manager

Manages isolated sandbox execution of container images for security analysis.
"""

from kubernetes import client, config  # type: ignore[import-untyped]
from kubernetes.client.rest import ApiException  # type: ignore[import-untyped]
import logging
from typing import Dict, List
from datetime import datetime

from config.settings import settings

logger = logging.getLogger(__name__)


class SandboxManager:
    """
    Manage sandbox execution in Kubernetes

    Creates isolated Jobs for running untrusted container images
    with profiling, fuzzing, and security analysis.
    """

    def __init__(self, namespace: str | None = None):
        """
        Initialize Kubernetes client

        Args:
            namespace: Kubernetes namespace for sandbox jobs
        """
        self.namespace = namespace or settings.k8s_sandbox_namespace

        # Load kubeconfig
        try:
            if settings.k8s_in_cluster:
                config.load_incluster_config()  # When running in cluster
                logger.info("Loaded in-cluster Kubernetes configuration")
            else:
                config.load_kube_config()  # Local development
                logger.info("Loaded local kubeconfig")
        except Exception as e:
            logger.error(f"Failed to load Kubernetes config: {e}")
            raise

        self.batch_v1 = client.BatchV1Api()
        self.core_v1 = client.CoreV1Api()

        # Ensure namespace exists
        self._ensure_namespace()

    def _ensure_namespace(self):
        """Create namespace if it doesn't exist"""
        try:
            self.core_v1.read_namespace(self.namespace)
            logger.info(f"Namespace {self.namespace} exists")
        except ApiException as e:
            if e.status == 404:
                # Create namespace
                namespace = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=self.namespace)
                )
                self.core_v1.create_namespace(namespace)
                logger.info(f"Created namespace {self.namespace}")
            else:
                logger.error(f"Failed to check namespace: {e}")

    def create_sandbox_job(
        self, job_id: str, image_ref: str, image_digest: str, job_config: Dict
    ) -> str:
        """
        Create Kubernetes Job for sandbox execution

        Args:
            job_id: Unique job identifier
            image_ref: Container image reference
            image_digest: Image digest (sha256:...)
            job_config: Analysis configuration

        Returns:
            job_name: Name of created Kubernetes Job
        """
        job_name = f"vex-analysis-{job_id[:8]}"

        # Prepare environment variables
        env_vars = []
        for key, value in job_config.get("environment", {}).items():
            env_vars.append(client.V1EnvVar(name=key, value=value))

        # Prepare command
        command = job_config.get("command", ["/bin/sh", "-c", "sleep 300"])

        # Main container (target image)
        target_container = client.V1Container(
            name="target",
            image=f"{image_ref}@{image_digest}",
            command=command,
            env=env_vars,
            resources=client.V1ResourceRequirements(
                limits={
                    "cpu": settings.sandbox_cpu_limit,
                    "memory": settings.sandbox_memory_limit,
                },
                requests={
                    "cpu": settings.sandbox_cpu_request,
                    "memory": settings.sandbox_memory_request,
                },
            ),
            security_context=client.V1SecurityContext(
                run_as_non_root=False,  # May need root for some images
                allow_privilege_escalation=False,
                read_only_root_filesystem=False,
            ),
        )

        # Logger sidecar (captures output)
        logger_container = client.V1Container(
            name="logger",
            image="busybox:latest",
            command=[
                "/bin/sh",
                "-c",
                "while true; do echo '[LOG]' $(date); ps aux | head -10; sleep 10; done",
            ],
            resources=client.V1ResourceRequirements(
                limits={"cpu": "100m", "memory": "128Mi"},
                requests={"cpu": "50m", "memory": "64Mi"},
            ),
        )

        # Tracee profiler sidecar (eBPF profiling)
        # Only add if profiling is enabled
        containers = [target_container, logger_container]

        if job_config.get("enable_profiling", True):
            profiler_container = client.V1Container(
                name="profiler",
                image="aquasec/tracee:latest",
                command=[
                    "tracee",
                    "--output",
                    "json",
                    "--output",
                    "option:parse-arguments",
                    "--trace",
                    "comm=target",  # Trace target container
                    "--trace",
                    "follow",  # Follow child processes
                ],
                security_context=client.V1SecurityContext(
                    privileged=True,  # Required for eBPF
                    capabilities=client.V1Capabilities(
                        add=["SYS_ADMIN", "SYS_RESOURCE", "SYS_PTRACE"]
                    ),
                ),
                resources=client.V1ResourceRequirements(
                    limits={"cpu": "500m", "memory": "512Mi"},
                    requests={"cpu": "200m", "memory": "256Mi"},
                ),
                volume_mounts=[
                    client.V1VolumeMount(
                        name="shared-logs", mount_path="/tracee-output"
                    )
                ],
            )
            containers.append(profiler_container)

        # Job specification
        job = client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(
                name=job_name,
                namespace=self.namespace,
                labels={
                    "app": "vexxy-premium",
                    "component": "sandbox",
                    "job-id": job_id,
                },
                annotations={
                    "vexxy.dev/image-ref": image_ref,
                    "vexxy.dev/image-digest": image_digest,
                    "vexxy.dev/created-at": datetime.utcnow().isoformat(),
                },
            ),
            spec=client.V1JobSpec(
                ttl_seconds_after_finished=settings.k8s_job_ttl_seconds,
                backoff_limit=0,  # No retries
                active_deadline_seconds=job_config.get("test_timeout", 900),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={
                            "app": "vexxy-premium",
                            "component": "sandbox",
                            "job-id": job_id,
                        }
                    ),
                    spec=client.V1PodSpec(
                        restart_policy="Never",
                        security_context=client.V1PodSecurityContext(
                            seccomp_profile=client.V1SeccompProfile(
                                type="RuntimeDefault"
                            )
                        ),
                        containers=containers,  # Use dynamically built container list
                        volumes=[
                            client.V1Volume(
                                name="shared-logs",
                                empty_dir=client.V1EmptyDirVolumeSource(),
                            )
                        ],
                    ),
                ),
            ),
        )

        try:
            self.batch_v1.create_namespaced_job(namespace=self.namespace, body=job)
            logger.info(f"Created sandbox job {job_name} in namespace {self.namespace}")
            return job_name

        except ApiException as e:
            logger.error(f"Failed to create sandbox job: {e}")
            raise RuntimeError(f"Failed to create sandbox job: {e}")

    def get_job_status(self, job_name: str) -> Dict:
        """
        Get status of sandbox job

        Args:
            job_name: Name of Kubernetes Job

        Returns:
            dict with job status information
        """
        try:
            job = self.batch_v1.read_namespaced_job(
                name=job_name, namespace=self.namespace
            )

            status = "unknown"
            if job.status.succeeded:
                status = "succeeded"
            elif job.status.failed:
                status = "failed"
            elif job.status.active:
                status = "running"
            else:
                status = "pending"

            return {
                "job_name": job_name,
                "status": status,
                "active": job.status.active or 0,
                "succeeded": job.status.succeeded or 0,
                "failed": job.status.failed or 0,
                "start_time": (
                    job.status.start_time.isoformat() if job.status.start_time else None
                ),
                "completion_time": (
                    job.status.completion_time.isoformat()
                    if job.status.completion_time
                    else None
                ),
            }

        except ApiException as e:
            if e.status == 404:
                return {"job_name": job_name, "status": "not_found"}
            logger.error(f"Failed to get job status: {e}")
            raise RuntimeError(f"Failed to get job status: {e}")

    def get_job_logs(self, job_name: str, container: str = "target") -> str:
        """
        Get logs from sandbox job

        Args:
            job_name: Name of Kubernetes Job
            container: Container name to get logs from

        Returns:
            Container logs as string
        """
        try:
            # Find pod for this job
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace, label_selector=f"job-name={job_name}"
            )

            if not pods.items:
                logger.warning(f"No pods found for job {job_name}")
                return "No pods found for this job"

            pod_name = pods.items[0].metadata.name

            # Get logs
            logs = self.core_v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=self.namespace,
                container=container,
                tail_lines=1000,  # Last 1000 lines
            )

            return logs

        except ApiException as e:
            logger.error(f"Failed to get job logs: {e}")
            return f"Error retrieving logs: {e}"

    def delete_job(self, job_name: str):
        """
        Delete sandbox job and associated pods

        Args:
            job_name: Name of Kubernetes Job
        """
        try:
            # Delete job (will cascade delete pods)
            self.batch_v1.delete_namespaced_job(
                name=job_name,
                namespace=self.namespace,
                propagation_policy="Foreground",  # Wait for pods to be deleted
            )
            logger.info(f"Deleted sandbox job {job_name}")

        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Job {job_name} not found (already deleted?)")
            else:
                logger.error(f"Failed to delete job {job_name}: {e}")
                raise RuntimeError(f"Failed to delete job: {e}")

    def list_jobs(self, label_selector: str | None = None) -> List[Dict]:
        """
        List sandbox jobs

        Args:
            label_selector: Kubernetes label selector

        Returns:
            List of job information dictionaries
        """
        try:
            jobs = self.batch_v1.list_namespaced_job(
                namespace=self.namespace,
                label_selector=label_selector or "app=vexxy-premium",
            )

            result = []
            for job in jobs.items:
                result.append(
                    {
                        "name": job.metadata.name,
                        "job_id": job.metadata.labels.get("job-id"),
                        "created_at": job.metadata.creation_timestamp.isoformat(),
                        "active": job.status.active or 0,
                        "succeeded": job.status.succeeded or 0,
                        "failed": job.status.failed or 0,
                    }
                )

            return result

        except ApiException as e:
            logger.error(f"Failed to list jobs: {e}")
            return []
