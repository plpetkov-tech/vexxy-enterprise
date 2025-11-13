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
        """
        self.namespace = namespace or settings.k8s_sandbox_namespace

        # Load kubeconfig
        try:
            if settings.k8s_in_cluster:
                config.load_incluster_config()
                logger.info("Loaded in-cluster Kubernetes configuration")
            else:
                config.load_kube_config()
                logger.info("Loaded local kubeconfig")
        except Exception as e:
            logger.error(f"Failed to load Kubernetes config: {e}")
            raise

        self.apps_v1 = client.AppsV1Api()
        self.core_v1 = client.CoreV1Api()
        self.batch_v1 = client.BatchV1Api()

        # Dynamic client for custom resources (Kubescape CRDs)
        self.dynamic_client = DynamicClient(client.ApiClient())

    def is_kubescape_installed(self) -> bool:
        """
        Check if Kubescape is installed in the cluster

        Returns:
            True if Kubescape is installed, False otherwise
        """
        try:
            # Check for Kubescape namespace
            self.core_v1.read_namespace("kubescape")
            logger.info("Kubescape namespace found")

            # Check for Kubescape CRDs
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
                logger.warning(f"Kubescape CRDs missing: {missing_crds}")
                return False

            logger.info("All required Kubescape CRDs found")
            return True

        except ApiException as e:
            if e.status == 404:
                logger.warning("Kubescape not found in cluster")
                return False
            logger.error(f"Error checking Kubescape installation: {e}")
            return False

    def install_kubescape(self) -> bool:
        """
        Install Kubescape using Helm

        Returns:
            True if successful, False otherwise
        """
        import subprocess

        logger.info("Installing Kubescape via Helm...")

        try:
            # Add Kubescape Helm repo
            subprocess.run(
                ["helm", "repo", "add", "kubescape", "https://kubescape.github.io/helm-charts"],
                check=True,
                capture_output=True
            )

            subprocess.run(
                ["helm", "repo", "update"],
                check=True,
                capture_output=True
            )

            # Install Kubescape with VEX and filtered SBOM enabled
            helm_values = """
capabilities:
  relevancy: enable
  vulnerabilityScan: enable

nodeAgent:
  enabled: true

kubevuln:
  enabled: true

storage:
  enabled: true

grypeOfflineDB:
  enabled: true
"""

            # Write values to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(helm_values)
                values_file = f.name

            # Install Kubescape
            result = subprocess.run(
                [
                    "helm", "install", "kubescape", "kubescape/kubescape-operator",
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

            logger.info(f"Kubescape installed successfully: {result.stdout}")

            # Wait for Kubescape pods to be ready
            time.sleep(30)

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Kubescape: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Error installing Kubescape: {e}", exc_info=True)
            return False

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

        Args:
            job_id: Unique job identifier
            image_ref: Container image reference
            image_digest: Image digest
            job_config: Analysis configuration

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

        # Container spec
        container = client.V1Container(
            name="target",
            image=f"{image_ref}@{image_digest}",
            command=command,
            env=env_vars,
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
                        containers=[container],
                        restart_policy="Always"
                    )
                )
            )
        )

        try:
            self.apps_v1.create_namespaced_deployment(
                namespace=self.namespace,
                body=deployment
            )
            logger.info(f"Created deployment {deployment_name} for Kubescape analysis")
            return deployment_name

        except ApiException as e:
            logger.error(f"Failed to create deployment: {e}")
            raise RuntimeError(f"Failed to create deployment: {e}")

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
            result = self.core_v1.list_namespaced_custom_object(
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
            result = self.core_v1.list_namespaced_custom_object(
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
            # Get all VEX documents in kubescape namespace
            result = self.core_v1.list_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="openvulnerabilityexchangecontainers"
            )

            # Find VEX matching our deployment
            digest_short = image_digest.replace("sha256:", "")[:12]

            for item in result.get('items', []):
                name = item['metadata']['name']

                # Check if VEX matches our image by digest
                if digest_short in name or deployment_name[:8] in name:
                    vex_spec = item.get('spec', {})
                    logger.info(f"Found runtime VEX: {name}")

                    # Kubescape VEX format is already OpenVEX-compatible
                    return vex_spec

            logger.warning(f"No runtime VEX found for {deployment_name}")
            return None

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
            # Get all filtered SBOMs in kubescape namespace
            result = self.core_v1.list_namespaced_custom_object(
                group="spdx.softwarecomposition.kubescape.io",
                version="v1beta1",
                namespace="kubescape",
                plural="sbomsyftfiltereds"
            )

            # Find SBOM matching our deployment
            digest_short = image_digest.replace("sha256:", "")[:12]

            for item in result.get('items', []):
                name = item['metadata']['name']

                # Check if SBOM matches our image
                if digest_short in name or deployment_name[:8] in name:
                    sbom_spec = item.get('spec', {})
                    logger.info(f"Found filtered SBOM: {name}")

                    return sbom_spec

            logger.warning(f"No filtered SBOM found for {deployment_name}")
            return None

        except ApiException as e:
            logger.error(f"Failed to extract filtered SBOM: {e}")
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
        """
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace,
                propagation_policy="Foreground"
            )
            logger.info(f"Deleted deployment {deployment_name}")

        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Deployment {deployment_name} not found (already deleted?)")
            else:
                logger.error(f"Failed to delete deployment: {e}")
                raise RuntimeError(f"Failed to delete deployment: {e}")

    def get_deployment_status(self, deployment_name: str) -> Dict:
        """
        Get status of analysis deployment

        Args:
            deployment_name: Name of deployment

        Returns:
            dict with deployment status
        """
        try:
            deployment = self.apps_v1.read_namespaced_deployment(
                name=deployment_name,
                namespace=self.namespace
            )

            return {
                "deployment_name": deployment_name,
                "replicas": deployment.status.replicas or 0,
                "ready_replicas": deployment.status.ready_replicas or 0,
                "available_replicas": deployment.status.available_replicas or 0,
                "status": "ready" if deployment.status.ready_replicas else "not_ready"
            }

        except ApiException as e:
            if e.status == 404:
                return {"deployment_name": deployment_name, "status": "not_found"}
            logger.error(f"Failed to get deployment status: {e}")
            raise RuntimeError(f"Failed to get deployment status: {e}")
