"""
Kubescape Integration Service

Manages Kubescape deployment and extracts runtime VEX documents and filtered SBOMs.
Kubescape provides reachability analysis and generates VEX statements based on runtime behavior.
"""
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.dynamic import DynamicClient
import logging
import time
import json
from typing import Optional, Dict, List, Tuple
from datetime import datetime

from config.settings import settings
from exceptions import (
    KubernetesError,
    KubescapeError,
    TimeoutError as VexxyTimeoutError,
    InternalServiceError
)
from utils import retry_with_backoff, RetryConfig
from utils.kubernetes_config import is_config_loaded, load_kubernetes_config

logger = logging.getLogger(__name__)


class KubescapeService:
    """
    Service for deploying Kubescape and extracting runtime analysis results

    Kubescape generates:
    - Runtime VEX documents (OpenVulnerabilityExchangeContainer CRDs)
    - Filtered SBOMs showing only relevant/reachable components (SBOMSyftFiltered CRDs)
    """

    def __init__(self, namespace: str = None):
        """
        Initialize Kubescape service

        Args:
            namespace: Kubernetes namespace for analysis workloads

        Raises:
            KubernetesError: If Kubernetes configuration fails
        """
        self.namespace = namespace or settings.k8s_sandbox_namespace

        # Load kubeconfig only if not already loaded
        try:
            if not is_config_loaded():
                load_kubernetes_config(in_cluster=settings.k8s_in_cluster)
            else:
                logger.debug("Kubernetes config already loaded, reusing existing configuration")
        except Exception as e:
            logger.error(f"Failed to load Kubernetes config: {e}", exc_info=True)
            raise KubernetesError(
                operation="load_config",
                error=str(e),
                details={"in_cluster": settings.k8s_in_cluster}
            )

        try:
            self.apps_v1 = client.AppsV1Api()
            self.core_v1 = client.CoreV1Api()
            self.batch_v1 = client.BatchV1Api()
            self.custom_objects_api = client.CustomObjectsApi()

            # Dynamic client for custom resources (Kubescape CRDs)
            self.dynamic_client = DynamicClient(client.ApiClient())

            # Ensure the sandbox namespace exists
            self._ensure_namespace_exists()
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes API clients: {e}", exc_info=True)
            raise KubernetesError(
                operation="initialize_clients",
                error=str(e)
            )

    def _ensure_namespace_exists(self):
        """
        Ensure the sandbox namespace exists, create it if it doesn't

        Raises:
            KubernetesError: If namespace creation fails (except for already exists)
        """
        try:
            # Try to read the namespace
            self.core_v1.read_namespace(self.namespace)
            logger.info(f"Namespace {self.namespace} already exists")
        except ApiException as e:
            if e.status == 404:
                # Namespace doesn't exist, create it
                logger.info(f"Creating namespace {self.namespace}")
                try:
                    namespace_body = client.V1Namespace(
                        metadata=client.V1ObjectMeta(
                            name=self.namespace,
                            labels={
                                "app": "vexxy",
                                "vexxy.dev/premium": "true",
                                "vexxy.dev/component": "sandbox"
                            }
                        )
                    )
                    self.core_v1.create_namespace(body=namespace_body)
                    logger.info(f"Successfully created namespace {self.namespace}")
                except ApiException as create_error:
                    if create_error.status == 409:
                        # Namespace was created by another process (race condition)
                        logger.info(f"Namespace {self.namespace} already exists (created concurrently)")
                    else:
                        logger.error(f"Failed to create namespace {self.namespace}: {create_error}")
                        raise KubernetesError(
                            operation="create_namespace",
                            error=str(create_error),
                            details={"namespace": self.namespace, "status_code": create_error.status}
                        )
            else:
                # Other error checking namespace
                logger.error(f"Failed to check namespace {self.namespace}: {e}")
                raise KubernetesError(
                    operation="check_namespace",
                    error=str(e),
                    details={"namespace": self.namespace, "status_code": e.status}
                )
        except Exception as e:
            logger.error(f"Unexpected error ensuring namespace exists: {e}", exc_info=True)
            raise InternalServiceError(
                message=f"Failed to ensure namespace {self.namespace} exists: {str(e)}",
                service="kubernetes"
            )

    @retry_with_backoff(
        exceptions=(ApiException,),
        config=RetryConfig(max_attempts=3, initial_delay=1.0)
    )
    def is_kubescape_installed(self) -> bool:
        """
        Check if Kubescape is installed in the cluster

        This method checks for:
        1. Kubescape namespace existence
        2. Kubescape operator deployment
        3. Required CRDs (with leniency for startup delays)

        Returns:
            True if Kubescape is installed (even if CRDs are still initializing), False otherwise

        Raises:
            KubernetesError: If API call fails
        """
        try:
            # Check for Kubescape namespace
            try:
                self.core_v1.read_namespace("kubescape")
                logger.info("Kubescape namespace found")
            except ApiException as e:
                if e.status == 404:
                    logger.info("Kubescape namespace not found")
                    return False
                raise

            # Check for Kubescape operator deployment (more reliable than CRDs)
            try:
                deployment = self.apps_v1.read_namespaced_deployment(
                    name="kubescape",
                    namespace="kubescape"
                )
                logger.info("Kubescape operator deployment found")

                # If deployment exists, consider Kubescape installed
                # even if CRDs are not fully registered yet
                deployment_ready = (
                    deployment.status.ready_replicas and
                    deployment.status.ready_replicas > 0
                )

                if deployment_ready:
                    logger.info("Kubescape operator is running and ready")
                else:
                    logger.info("Kubescape operator deployment exists but may still be starting")

            except ApiException as e:
                if e.status == 404:
                    logger.info("Kubescape operator deployment not found")
                    # No deployment means not installed
                    return False
                raise

            # Check for Kubescape CRDs (optional check - warn if missing but don't fail)
            # Note: This requires permissions to list CRDs at cluster scope
            try:
                api_client = client.ApiClient()
                api_instance = client.ApiextensionsV1Api(api_client)

                required_crds = [
                    "openvulnerabilityexchangecontainers.spdx.softwarecomposition.kubescape.io",
                    "sbomsyftfiltereds.spdx.softwarecomposition.kubescape.io"
                ]

                crds = api_instance.list_custom_resource_definition()
                crd_names = [crd.metadata.name for crd in crds.items]

                missing_crds = [crd for crd in required_crds if crd not in crd_names]

                if missing_crds:
                    logger.warning(
                        f"Kubescape CRDs not yet registered (may still be initializing): {missing_crds}. "
                        f"This is normal during startup."
                    )
                    # Don't return False here - deployment exists, so Kubescape is installed
                    # CRDs will be registered shortly
                else:
                    logger.info("All required Kubescape CRDs found")
            except ApiException as crd_error:
                # If we don't have permissions to list CRDs (403), that's OK
                # The deployment check is sufficient
                if crd_error.status == 403:
                    logger.info(
                        "Skipping CRD check (no permissions to list CRDs at cluster scope). "
                        "Kubescape deployment exists, so considering it installed."
                    )
                else:
                    # Log other API errors but don't fail
                    logger.warning(f"Could not check CRDs: {crd_error.status} - {crd_error.reason}")

            # If we got here, namespace and deployment exist
            return True

        except ApiException as e:
            if e.status == 404:
                logger.warning("Kubescape not found in cluster")
                return False
            logger.error(f"Error checking Kubescape installation: {e}", exc_info=True)
            raise KubernetesError(
                operation="check_kubescape_installation",
                error=str(e),
                details={"status_code": e.status}
            )
        except Exception as e:
            logger.error(f"Unexpected error checking Kubescape installation: {e}", exc_info=True)
            raise InternalServiceError(
                message=f"Failed to check Kubescape installation: {str(e)}",
                service="kubescape"
            )

    def install_kubescape(self) -> bool:
        """
        Install Kubescape using Helm

        Returns:
            True if successful, False otherwise
        """
        import subprocess

        logger.info("Installing Kubescape via Helm...")

        try:
            # Check if Helm is installed
            try:
                helm_version = subprocess.run(
                    ["helm", "version", "--short"],
                    check=True,
                    capture_output=True,
                    text=True
                )
                logger.info(f"Helm version: {helm_version.stdout.strip()}")
            except FileNotFoundError:
                logger.error("Helm is not installed in the container")
                return False
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to get Helm version: {e.stderr}")
                return False

            # Add Kubescape Helm repo (idempotent - force update if exists)
            logger.info("Adding Kubescape Helm repository...")
            result = subprocess.run(
                ["helm", "repo", "add", "kubescape", "https://kubescape.github.io/helm-charts", "--force-update"],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Helm repo add output: {result.stdout}")

            logger.info("Updating Helm repositories...")
            result = subprocess.run(
                ["helm", "repo", "update"],
                check=True,
                capture_output=True,
                text=True
            )
            logger.info(f"Helm repo update output: {result.stdout}")

            # Install Kubescape with VEX and filtered SBOM enabled
            helm_values = """
capabilities:
  vexGeneration: enable
  vulnerabilityScan: enable
  relevancy: enable
  runtimeObservability: enable
  networkEventsStreaming: disable

nodeAgent:
  enabled: true
  config:
    applicationActivityTime: 5m
    learningPeriod: 5m
    maxLearningPeriod: 5m
    updatePeriod: 1m

kubevuln:
  enabled: true
  config:
    storeFilteredSbom: true

storage:
  enabled: true

grypeOfflineDB:
  enabled: true
"""

            # Write values to temp file
            import tempfile
            import os
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(helm_values)
                values_file = f.name

            try:
                # Install or upgrade Kubescape (idempotent)
                logger.info("Installing/upgrading Kubescape operator (this may take a few minutes)...")
                result = subprocess.run(
                    [
                        "helm", "upgrade", "--install", "kubescape", "kubescape/kubescape-operator",
                        "-n", "kubescape",
                        "--create-namespace",
                        "-f", values_file,
                        "--wait",
                        "--timeout", "5m"
                    ],
                    check=True,
                    capture_output=True,
                    text=True
                )

                logger.info(f"Kubescape installed/upgraded successfully: {result.stdout}")

                # Wait for Kubescape pods to be ready
                logger.info("Waiting for Kubescape pods to be ready...")
                time.sleep(30)

                logger.info("Kubescape installation complete")
                return True

            finally:
                # Cleanup temp file
                try:
                    os.unlink(values_file)
                except Exception as cleanup_error:
                    logger.warning(f"Failed to cleanup temp values file: {cleanup_error}")

        except subprocess.CalledProcessError as e:
            logger.error(
                f"Failed to install Kubescape via Helm",
                extra={
                    "command": " ".join(e.cmd),
                    "return_code": e.returncode,
                    "stdout": e.stdout,
                    "stderr": e.stderr
                }
            )
            logger.error(f"STDOUT: {e.stdout}")
            logger.error(f"STDERR: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing Kubescape: {e}", exc_info=True)
            return False

    def _create_tracee_sidecar(self, job_id: str) -> client.V1Container:
        """
        Create Tracee sidecar container for eBPF profiling

        Args:
            job_id: Job identifier

        Returns:
            V1Container configured for Tracee profiling
        """
        return client.V1Container(
            name="tracee-profiler",
            image="aquasec/tracee:0.20.0",  # Pin to stable version
            image_pull_policy="IfNotPresent",  # Use local image if available
            command=[
                "/tracee/tracee",
                "--scope", "comm=target",  # Only trace the target container process
                "--scope", "follow",  # Include child processes
                "--events", "open,openat,openat2,read,write,execve,connect,socket,clone,fork",
                "--output", "json:/tracee-output/events.json",
                "--output", "option:parse-arguments",
                "--log", "info"
            ],
            volume_mounts=[
                client.V1VolumeMount(
                    name="tracee-output",
                    mount_path="/tracee-output"
                ),
                # Required for Tracee to access host OS info
                client.V1VolumeMount(
                    name="os-release",
                    mount_path="/etc/os-release-host",
                    read_only=True
                )
            ],
            resources=client.V1ResourceRequirements(
                limits={
                    "cpu": "500m",
                    "memory": "512Mi"
                },
                requests={
                    "cpu": "100m",
                    "memory": "128Mi"
                }
            ),
            security_context=client.V1SecurityContext(
                privileged=True,  # Required for eBPF
                capabilities=client.V1Capabilities(
                    add=["SYS_ADMIN", "SYS_RESOURCE", "SYS_PTRACE"]
                )
            ),
            env=[
                client.V1EnvVar(
                    name="LIBBPFGO_OSRELEASE_FILE",
                    value="/etc/os-release-host"
                )
            ]
        )

    def deploy_workload_for_analysis(
        self,
        job_id: str,
        image_ref: str,
        image_digest: str,
        job_config: Dict
    ) -> str:
        """
        Deploy a workload that Kubescape will monitor and analyze

        Creates a Deployment (not Job) so Kubescape can perform runtime analysis.
        Optionally includes Tracee sidecar for detailed runtime profiling.

        Args:
            job_id: Unique job identifier
            image_ref: Container image reference
            image_digest: Image digest
            job_config: Analysis configuration (includes enable_profiling flag)

        Returns:
            deployment_name: Name of created Deployment
        """
        deployment_name = f"vex-analysis-{job_id[:8]}"

        # Environment variables
        env_vars = []
        for key, value in job_config.get("environment", {}).items():
            env_vars.append(client.V1EnvVar(name=key, value=value))

        # Command (default: keep container running)
        command = job_config.get("command", ["/bin/sh", "-c", "sleep 600"])

        # Container ports (if specified)
        container_ports = []
        for port in job_config.get("ports", []):
            container_ports.append(
                client.V1ContainerPort(
                    container_port=port,
                    protocol="TCP"
                )
            )

        # Container spec
        # Note: Use image_ref without digest for local kind clusters to avoid pull issues
        # Kubescape will still track by digest via annotations
        container = client.V1Container(
            name="target",
            image=image_ref,  # Use ref without digest for kind compatibility
            image_pull_policy="IfNotPresent",  # Prefer local images (kind cluster)
            command=command,
            env=env_vars,
            ports=container_ports if container_ports else None,
            resources=client.V1ResourceRequirements(
                limits={
                    "cpu": settings.sandbox_cpu_limit,
                    "memory": settings.sandbox_memory_limit
                },
                requests={
                    "cpu": settings.sandbox_cpu_request,
                    "memory": settings.sandbox_memory_request
                }
            ),
            security_context=client.V1SecurityContext(
                run_as_non_root=False,
                allow_privilege_escalation=False,
                read_only_root_filesystem=False
            )
        )

        # Build containers list
        containers = [container]

        # Add Tracee sidecar for runtime profiling if enabled
        if job_config.get("enable_profiling", True):
            tracee_container = self._create_tracee_sidecar(job_id)
            containers.append(tracee_container)
            logger.info(f"Tracee profiling enabled for deployment {deployment_name}")

        # Deployment spec
        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(
                name=deployment_name,
                namespace=self.namespace,
                labels={
                    "app": "vexxy-premium",
                    "component": "analysis",
                    "job-id": job_id,
                    "vexxy.dev/analysis": "true"  # Label for Kubescape to track
                },
                annotations={
                    "vexxy.dev/image-ref": image_ref,
                    "vexxy.dev/image-digest": image_digest,
                    "vexxy.dev/created-at": datetime.utcnow().isoformat()
                }
            ),
            spec=client.V1DeploymentSpec(
                replicas=1,
                selector=client.V1LabelSelector(
                    match_labels={
                        "app": "vexxy-premium",
                        "job-id": job_id
                    }
                ),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={
                            "app": "vexxy-premium",
                            "component": "analysis",
                            "job-id": job_id
                        }
                    ),
                    spec=client.V1PodSpec(
                        containers=containers,
                        restart_policy="Always",
                        # Share process namespace if Tracee is enabled
                        share_process_namespace=True if job_config.get("enable_profiling", True) else None,
                        # Volumes for Tracee output and host OS info
                        volumes=[
                            client.V1Volume(
                                name="tracee-output",
                                empty_dir={}
                            ),
                            client.V1Volume(
                                name="os-release",
                                host_path=client.V1HostPathVolumeSource(
                                    path="/etc/os-release",
                                    type="File"
                                )
                            )
                        ] if job_config.get("enable_profiling", True) else None
                    )
                )
            )
        )

        try:
            self.apps_v1.create_namespaced_deployment(
                namespace=self.namespace,
                body=deployment
            )
            logger.info(
                f"Created deployment {deployment_name} for Kubescape analysis",
                extra={
                    "deployment_name": deployment_name,
                    "job_id": job_id,
                    "image_ref": image_ref,
                    "namespace": self.namespace
                }
            )
            return deployment_name

        except ApiException as e:
            logger.error(
                f"Failed to create deployment: {e}",
                extra={
                    "deployment_name": deployment_name,
                    "job_id": job_id,
                    "namespace": self.namespace,
                    "status_code": e.status
                },
                exc_info=True
            )
            raise KubernetesError(
                operation="create_deployment",
                error=str(e),
                details={
                    "deployment_name": deployment_name,
                    "namespace": self.namespace,
                    "status_code": e.status
                }
            )
        except Exception as e:
            logger.error(f"Unexpected error creating deployment: {e}", exc_info=True)
            raise InternalServiceError(
                message=f"Failed to create deployment: {str(e)}",
                service="kubernetes",
                details={"deployment_name": deployment_name}
            )

    def wait_for_kubescape_analysis(
        self,
        deployment_name: str,
        timeout_seconds: int = 600
    ) -> bool:
        """
        Wait for Kubescape to generate VEX and filtered SBOM

        Args:
            deployment_name: Name of the deployment being analyzed
            timeout_seconds: Maximum time to wait

        Returns:
            True if analysis completed, False if timeout
        """
        logger.info(f"Waiting for Kubescape to analyze {deployment_name} (timeout: {timeout_seconds}s)")

        start_time = time.time()

        # Pattern matching for CRD names (Kubescape converts names)
        # Format: ghcr-io-owner-repo-sha256-abc123...
        pattern = deployment_name.replace("-", "").replace("_", "")

        while time.time() - start_time < timeout_seconds:
            try:
                # Check for VEX document
                vex_exists = self._check_vex_exists(pattern)

                # Check for filtered SBOM
                sbom_exists = self._check_filtered_sbom_exists(pattern)

                if vex_exists and sbom_exists:
                    elapsed = time.time() - start_time
                    logger.info(f"Kubescape analysis complete after {elapsed:.1f}s")
                    return True

                if vex_exists:
                    logger.debug(f"VEX document found, waiting for filtered SBOM...")
                elif sbom_exists:
                    logger.debug(f"Filtered SBOM found, waiting for VEX document...")
                else:
                    logger.debug(f"Waiting for Kubescape analysis...")

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                logger.error(f"Error checking Kubescape analysis status: {e}")
                time.sleep(10)

        logger.warning(f"Kubescape analysis timeout after {timeout_seconds}s")
        return False

    def _check_vex_exists(self, pattern: str) -> bool:
        """Check if VEX CRD exists"""
        try:
            result = self.custom_objects_api.list_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="openvulnerabilityexchangecontainers"
            )

            # Check if any VEX matches our pattern
            for item in result.get('items', []):
                name = item['metadata']['name']
                if pattern in name or self._name_matches_deployment(name, pattern):
                    return True

            return False

        except Exception as e:
            logger.debug(f"Error checking VEX: {e}")
            return False

    def _check_filtered_sbom_exists(self, pattern: str) -> bool:
        """Check if filtered SBOM CRD exists"""
        try:
            result = self.custom_objects_api.list_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="sbomsyftfiltereds"
            )

            # Check if any SBOM matches our pattern
            for item in result.get('items', []):
                name = item['metadata']['name']
                if pattern in name or self._name_matches_deployment(name, pattern):
                    return True

            return False

        except Exception as e:
            logger.debug(f"Error checking filtered SBOM: {e}")
            return False

    def _name_matches_deployment(self, crd_name: str, deployment_name: str) -> bool:
        """
        Check if CRD name matches deployment

        Kubescape generates CRD names from image refs, not deployment names.
        We need to match based on image digest or other metadata.
        """
        # Simple heuristic: check if deployment name parts are in CRD name
        deployment_parts = deployment_name.lower().replace("-", "").split()
        crd_lower = crd_name.lower()

        return any(part in crd_lower for part in deployment_parts if len(part) > 3)

    def extract_runtime_vex(self, deployment_name: str, image_digest: str) -> Optional[Dict]:
        """
        Extract runtime VEX document from Kubescape CRD

        Args:
            deployment_name: Name of deployment
            image_digest: Image digest to match

        Returns:
            VEX document as dict, or None if not found
        """
        logger.info(f"Extracting runtime VEX for {deployment_name}")

        try:
            # First, list VEX documents to find the name
            # Note: list returns truncated data for large arrays, so we need to get the full object
            result = self.custom_objects_api.list_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="openvulnerabilityexchangecontainers"
            )

            # Find VEX matching our deployment
            # VEX CRD names follow pattern: replicaset-{deployment_name}-{hash}-{container}-{hash}
            # Example: replicaset-vex-analysis-e8e35769-5bcc849bcb-target-2bdc-4cf6
            digest_short = image_digest.replace("sha256:", "")[:12]

            vex_crd_name = None
            for item in result.get('items', []):
                name = item['metadata']['name']

                # Match by deployment name (more precise than first 8 chars)
                # or by image digest for image-based matching
                if deployment_name in name or digest_short in name:
                    vex_crd_name = name
                    logger.info(f"Found runtime VEX CRD: {name}")
                    break

            if not vex_crd_name:
                logger.warning(f"No runtime VEX found for {deployment_name}")
                return None

            # Now fetch the full VEX document (list truncates large arrays)
            vex_crd = self.custom_objects_api.get_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="openvulnerabilityexchangecontainers",
                name=vex_crd_name
            )

            vex_spec = vex_crd.get('spec', {})
            statement_count = len(vex_spec.get('statements', []) or [])
            logger.info(f"VEX spec contains {statement_count} statements")

            # Kubescape VEX format is already OpenVEX-compatible
            return vex_spec

        except ApiException as e:
            logger.error(f"Failed to extract runtime VEX: {e}")
            return None

    def extract_filtered_sbom(self, deployment_name: str, image_digest: str) -> Optional[Dict]:
        """
        Extract filtered SBOM from Kubescape CRD

        Filtered SBOMs contain only components that are actually used at runtime.

        Args:
            deployment_name: Name of deployment
            image_digest: Image digest to match

        Returns:
            Filtered SBOM document as dict, or None if not found
        """
        logger.info(f"Extracting filtered SBOM for {deployment_name}")

        try:
            # First, list filtered SBOMs to find the name
            # Note: list may return truncated data for large arrays
            result = self.custom_objects_api.list_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="sbomsyftfiltereds"
            )

            # Find SBOM matching our deployment
            # Filtered SBOM CRD names may follow similar pattern to VEX
            digest_short = image_digest.replace("sha256:", "")[:12]

            sbom_crd_name = None
            for item in result.get('items', []):
                name = item['metadata']['name']

                # Match by deployment name (more precise than first 8 chars)
                # or by image digest for image-based matching
                if deployment_name in name or digest_short in name:
                    sbom_crd_name = name
                    logger.info(f"Found filtered SBOM CRD: {name}")
                    break

            if not sbom_crd_name:
                logger.warning(f"No filtered SBOM found for {deployment_name}")
                return None

            # Now fetch the full SBOM document
            sbom_crd = self.custom_objects_api.get_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="sbomsyftfiltereds",
                name=sbom_crd_name
            )

            sbom_spec = sbom_crd.get('spec', {})
            component_count = len(sbom_spec.get('components', []) or [])
            logger.info(f"Filtered SBOM contains {component_count} components")

            return sbom_spec

        except ApiException as e:
            logger.error(f"Failed to extract filtered SBOM: {e}")
            return None

    def extract_tracee_profiling_data(self, deployment_name: str) -> Optional[str]:
        """
        Extract Tracee profiling data from the sidecar container

        Args:
            deployment_name: Name of the deployment

        Returns:
            Tracee JSON output as string, or None if not found/error
        """
        logger.info(f"Extracting Tracee profiling data from {deployment_name}")

        try:
            # Get the pod for this deployment
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app=vexxy-premium,component=analysis"
            )

            # Find pod matching deployment
            target_pod = None
            for pod in pods.items:
                if deployment_name in pod.metadata.name:
                    target_pod = pod
                    break

            if not target_pod:
                logger.warning(f"No pod found for deployment {deployment_name}")
                return None

            pod_name = target_pod.metadata.name
            logger.info(f"Found pod {pod_name} for Tracee data extraction")

            # Read Tracee output file from the profiler container
            # Execute cat command to read the JSON file
            from kubernetes.stream import stream

            exec_command = [
                '/bin/sh',
                '-c',
                'cat /tracee-output/events.json 2>/dev/null || echo "{}"'
            ]

            try:
                resp = stream(
                    self.core_v1.connect_get_namespaced_pod_exec,
                    name=pod_name,
                    namespace=self.namespace,
                    container='tracee-profiler',
                    command=exec_command,
                    stderr=True,
                    stdin=False,
                    stdout=True,
                    tty=False,
                    _preload_content=True
                )

                if resp:
                    logger.info(f"Successfully retrieved Tracee data ({len(resp)} bytes)")
                    return resp
                else:
                    logger.warning("Tracee output file is empty")
                    return None

            except ApiException as e:
                if e.status == 404:
                    logger.warning(f"Tracee profiler container not found in pod {pod_name}")
                else:
                    logger.error(f"Failed to exec into Tracee container: {e}")
                return None

        except Exception as e:
            logger.error(f"Failed to extract Tracee profiling data: {e}", exc_info=True)
            return None

    def extract_kubescape_analysis(
        self,
        deployment_name: str,
        image_digest: str
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Extract both VEX and filtered SBOM from Kubescape

        Args:
            deployment_name: Name of deployment
            image_digest: Image digest

        Returns:
            Tuple of (vex_document, filtered_sbom)
        """
        vex = self.extract_runtime_vex(deployment_name, image_digest)
        sbom = self.extract_filtered_sbom(deployment_name, image_digest)

        return vex, sbom

    def delete_workload(self, deployment_name: str):
        """
        Delete analysis workload and cleanup

        Args:
            deployment_name: Name of deployment to delete

        Raises:
            KubernetesError: If deletion fails (except for 404)
        """
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace,
                propagation_policy="Foreground"
            )
            logger.info(
                f"Deleted deployment {deployment_name}",
                extra={
                    "deployment_name": deployment_name,
                    "namespace": self.namespace
                }
            )

        except ApiException as e:
            if e.status == 404:
                logger.warning(
                    f"Deployment {deployment_name} not found (already deleted?)",
                    extra={"deployment_name": deployment_name, "namespace": self.namespace}
                )
            else:
                logger.error(
                    f"Failed to delete deployment: {e}",
                    extra={
                        "deployment_name": deployment_name,
                        "namespace": self.namespace,
                        "status_code": e.status
                    },
                    exc_info=True
                )
                raise KubernetesError(
                    operation="delete_deployment",
                    error=str(e),
                    details={
                        "deployment_name": deployment_name,
                        "namespace": self.namespace,
                        "status_code": e.status
                    }
                )
        except Exception as e:
            logger.error(
                f"Unexpected error deleting deployment: {e}",
                extra={"deployment_name": deployment_name},
                exc_info=True
            )
            raise InternalServiceError(
                message=f"Failed to delete deployment: {str(e)}",
                service="kubernetes",
                details={"deployment_name": deployment_name}
            )

    def _get_pod_failure_details(self, deployment_name: str) -> Dict:
        """
        Get detailed failure information from pods in a deployment

        Args:
            deployment_name: Name of deployment

        Returns:
            dict with pod failure details
        """
        try:
            # Get pods for this deployment using label selector
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"app=vexxy-premium,component=analysis"
            )

            failure_info = {
                "pod_count": len(pods.items),
                "container_statuses": [],
                "pod_conditions": []
            }

            for pod in pods.items:
                # Check if this pod belongs to our deployment
                if not pod.metadata.name.startswith(deployment_name.rsplit('-', 1)[0]):
                    continue

                # Get container statuses
                if pod.status.container_statuses:
                    for container_status in pod.status.container_statuses:
                        status_detail = {
                            "container_name": container_status.name,
                            "ready": container_status.ready,
                            "restart_count": container_status.restart_count
                        }

                        # Check for waiting state
                        if container_status.state.waiting:
                            status_detail["state"] = "waiting"
                            status_detail["reason"] = container_status.state.waiting.reason
                            status_detail["message"] = container_status.state.waiting.message

                        # Check for terminated state
                        elif container_status.state.terminated:
                            status_detail["state"] = "terminated"
                            status_detail["reason"] = container_status.state.terminated.reason
                            status_detail["exit_code"] = container_status.state.terminated.exit_code
                            status_detail["message"] = container_status.state.terminated.message

                        # Running state
                        elif container_status.state.running:
                            status_detail["state"] = "running"

                        failure_info["container_statuses"].append(status_detail)

                # Get pod conditions
                if pod.status.conditions:
                    for condition in pod.status.conditions:
                        if condition.status == "False":
                            failure_info["pod_conditions"].append({
                                "type": condition.type,
                                "status": condition.status,
                                "reason": condition.reason,
                                "message": condition.message
                            })

            return failure_info

        except Exception as e:
            logger.warning(f"Failed to get pod failure details: {e}")
            return {"error": str(e)}

    @retry_with_backoff(
        exceptions=(ApiException,),
        config=RetryConfig(max_attempts=3, initial_delay=1.0)
    )
    def get_deployment_status(self, deployment_name: str) -> Dict:
        """
        Get status of analysis deployment with detailed failure information

        Args:
            deployment_name: Name of deployment

        Returns:
            dict with deployment status and failure details if not ready

        Raises:
            KubernetesError: If status check fails (except for 404)
        """
        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace
            )

            is_ready = deployment.status.ready_replicas and deployment.status.ready_replicas > 0

            status_info = {
                "deployment_name": deployment_name,
                "replicas": deployment.status.replicas or 0,
                "ready_replicas": deployment.status.ready_replicas or 0,
                "available_replicas": deployment.status.available_replicas or 0,
                "status": "ready" if is_ready else "not_ready"
            }

            # Get detailed failure information regardless of ready state
            failure_details = self._get_pod_failure_details(deployment_name)

            # Check if the target container is ready even if sidecars are failing
            # This allows graceful degradation when optional sidecars (like Tracee) fail
            if not is_ready and failure_details.get("container_statuses"):
                target_container_ready = False
                for container in failure_details["container_statuses"]:
                    if container.get("container_name") == "target" and container.get("ready"):
                        target_container_ready = True
                        break

                # If target container is ready, mark deployment as ready (degraded mode)
                if target_container_ready:
                    logger.warning(
                        f"Deployment {deployment_name} running in degraded mode (target ready, sidecars failing)",
                        extra={"deployment_name": deployment_name, "failure_details": failure_details}
                    )
                    status_info["status"] = "ready"
                    status_info["degraded"] = True
                    status_info["sidecar_failures"] = [
                        c for c in failure_details["container_statuses"]
                        if not c.get("ready") and c.get("container_name") != "target"
                    ]

            # If not ready, include detailed failure information
            if status_info["status"] != "ready":
                status_info["failure_details"] = failure_details

            logger.debug(
                f"Deployment {deployment_name} status: {status_info['status']}",
                extra={
                    "deployment_name": deployment_name,
                    "status": status_info
                }
            )

            return status_info

        except ApiException as e:
            if e.status == 404:
                logger.warning(
                    f"Deployment {deployment_name} not found",
                    extra={"deployment_name": deployment_name}
                )
                return {"deployment_name": deployment_name, "status": "not_found"}

            logger.error(
                f"Failed to get deployment status: {e}",
                extra={
                    "deployment_name": deployment_name,
                    "status_code": e.status
                },
                exc_info=True
            )
            raise KubernetesError(
                operation="get_deployment_status",
                error=str(e),
                details={
                    "deployment_name": deployment_name,
                    "status_code": e.status
                }
            )
        except Exception as e:
            logger.error(
                f"Unexpected error getting deployment status: {e}",
                extra={"deployment_name": deployment_name},
                exc_info=True
            )
            raise InternalServiceError(
                message=f"Failed to get deployment status: {str(e)}",
                service="kubernetes",
                details={"deployment_name": deployment_name}
            )

    def create_service_for_deployment(
        self,
        deployment_name: str,
        job_id: str,
        ports: List[int]
    ) -> Optional[str]:
        """
        Create a Kubernetes Service to expose deployment ports

        Args:
            deployment_name: Name of the deployment
            job_id: Job ID for labels
            ports: List of ports to expose

        Returns:
            Service name if created, None if no ports

        Raises:
            KubernetesError: If service creation fails
        """
        if not ports:
            logger.info("No ports specified, skipping service creation")
            return None

        service_name = f"{deployment_name}-svc"

        # Create port specifications
        service_ports = []
        for idx, port in enumerate(ports):
            service_ports.append(
                client.V1ServicePort(
                    name=f"port-{port}",
                    protocol="TCP",
                    port=port,
                    target_port=port
                )
            )

        # Service spec
        service = client.V1Service(
            api_version="v1",
            kind="Service",
            metadata=client.V1ObjectMeta(
                name=service_name,
                namespace=self.namespace,
                labels={
                    "app": "vexxy-premium",
                    "component": "analysis",
                    "job-id": job_id
                }
            ),
            spec=client.V1ServiceSpec(
                selector={
                    "app": "vexxy-premium",
                    "job-id": job_id
                },
                ports=service_ports,
                type="ClusterIP"
            )
        )

        try:
            self.core_v1.create_namespaced_service(
                namespace=self.namespace,
                body=service
            )
            logger.info(
                f"Created service {service_name} exposing ports {ports}",
                extra={
                    "service_name": service_name,
                    "deployment_name": deployment_name,
                    "ports": ports,
                    "namespace": self.namespace
                }
            )
            return service_name

        except ApiException as e:
            logger.error(
                f"Failed to create service: {e}",
                extra={
                    "service_name": service_name,
                    "namespace": self.namespace,
                    "status_code": e.status
                },
                exc_info=True
            )
            raise KubernetesError(
                operation="create_service",
                error=str(e),
                details={
                    "service_name": service_name,
                    "namespace": self.namespace,
                    "status_code": e.status
                }
            )
        except Exception as e:
            logger.error(f"Unexpected error creating service: {e}", exc_info=True)
            raise InternalServiceError(
                message=f"Failed to create service: {str(e)}",
                service="kubernetes",
                details={"service_name": service_name}
            )

    def delete_service(self, service_name: str):
        """
        Delete a Kubernetes Service

        Args:
            service_name: Name of service to delete

        Raises:
            KubernetesError: If deletion fails (except for 404)
        """
        if not service_name:
            return

        try:
            self.core_v1.delete_namespaced_service(
                name=service_name,
                namespace=self.namespace
            )
            logger.info(
                f"Deleted service {service_name}",
                extra={
                    "service_name": service_name,
                    "namespace": self.namespace
                }
            )

        except ApiException as e:
            if e.status == 404:
                logger.warning(
                    f"Service {service_name} not found (already deleted?)",
                    extra={"service_name": service_name, "namespace": self.namespace}
                )
            else:
                logger.error(
                    f"Failed to delete service: {e}",
                    extra={
                        "service_name": service_name,
                        "namespace": self.namespace,
                        "status_code": e.status
                    },
                    exc_info=True
                )
                raise KubernetesError(
                    operation="delete_service",
                    error=str(e),
                    details={
                        "service_name": service_name,
                        "namespace": self.namespace,
                        "status_code": e.status
                    }
                )
        except Exception as e:
            logger.error(
                f"Unexpected error deleting service: {e}",
                extra={"service_name": service_name},
                exc_info=True
            )
            raise InternalServiceError(
                message=f"Failed to delete service: {str(e)}",
                service="kubernetes",
                details={"service_name": service_name}
            )
