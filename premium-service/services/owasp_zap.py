"""
OWASP ZAP Integration Service

Provides security scanning capabilities using OWASP ZAP (Zed Attack Proxy).
Scans exposed ports for common web vulnerabilities.
"""
import logging
import time
import json
import subprocess
from typing import Dict, List, Optional
from zapv2 import ZAPv2
import requests
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from utils.kubernetes_config import is_config_loaded, load_kubernetes_config

logger = logging.getLogger(__name__)


class ZAPService:
    """
    Service for running OWASP ZAP security scans against container workloads

    Performs:
    - Active scanning for vulnerabilities
    - Spider/crawling to discover endpoints
    - Passive scanning during exploration
    """

    def __init__(self, zap_host: str = "localhost", zap_port: int = 8080, zap_api_key: str = None):
        """
        Initialize ZAP service

        Args:
            zap_host: ZAP proxy host
            zap_port: ZAP proxy port
            zap_api_key: ZAP API key (if authentication enabled)
        """
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_api_key = zap_api_key or "vexxy-zap-key"

        # Initialize ZAP API client
        self.zap = ZAPv2(
            apikey=self.zap_api_key,
            proxies={
                'http': f'http://{zap_host}:{zap_port}',
                'https': f'http://{zap_host}:{zap_port}'
            }
        )

        logger.info(f"ZAP service initialized at {zap_host}:{zap_port}")

    def is_zap_available(self) -> bool:
        """
        Check if ZAP is running and accessible

        Returns:
            True if ZAP is available, False otherwise
        """
        try:
            # Try to get ZAP version
            version = self.zap.core.version
            logger.info(f"ZAP is available, version: {version}")
            return True
        except Exception as e:
            logger.warning(f"ZAP is not available: {e}")
            return False

    def scan_target(
        self,
        target_host: str,
        target_ports: List[int],
        scan_depth: str = "medium",
        timeout: int = 600
    ) -> Dict:
        """
        Perform a comprehensive security scan on target

        Args:
            target_host: Target hostname/IP
            target_ports: List of ports to scan
            scan_depth: Scan depth (quick, medium, thorough)
            timeout: Maximum time for scan in seconds

        Returns:
            Scan results dictionary
        """
        logger.info(f"Starting ZAP scan of {target_host} on ports {target_ports}")

        if not target_ports:
            logger.warning("No ports specified for ZAP scan")
            return {
                "status": "skipped",
                "reason": "no_ports_specified",
                "scanned_urls": []
            }

        results = {
            "target_host": target_host,
            "target_ports": target_ports,
            "scan_depth": scan_depth,
            "scanned_urls": [],
            "alerts": [],
            "summary": {
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "informational": 0,
                "total_alerts": 0
            },
            "scan_duration_seconds": 0,
            "status": "in_progress"
        }

        start_time = time.time()

        try:
            # Check if ZAP is available
            if not self.is_zap_available():
                results["status"] = "failed"
                results["error"] = "ZAP is not available"
                return results

            # Create new session
            self.zap.core.new_session()
            logger.info("Created new ZAP session")

            # Scan each port
            for port in target_ports:
                try:
                    # Determine protocol (assume HTTP for common web ports, HTTPS for 443/8443)
                    protocol = "https" if port in [443, 8443] else "http"
                    target_url = f"{protocol}://{target_host}:{port}"

                    logger.info(f"Scanning {target_url}")
                    results["scanned_urls"].append(target_url)

                    # Access the URL to add to ZAP's sites
                    try:
                        self.zap.urlopen(target_url)
                        logger.info(f"Accessed {target_url}")
                    except Exception as e:
                        logger.warning(f"Could not access {target_url}: {e}")
                        continue

                    # Spider the target (discover pages)
                    if scan_depth in ["medium", "thorough"]:
                        logger.info(f"Spidering {target_url}")
                        scan_id = self.zap.spider.scan(target_url)

                        # Wait for spider to complete (with timeout)
                        spider_timeout = 120 if scan_depth == "medium" else 300
                        spider_start = time.time()

                        while int(self.zap.spider.status(scan_id)) < 100:
                            if time.time() - spider_start > spider_timeout:
                                logger.warning(f"Spider timeout for {target_url}")
                                break
                            time.sleep(2)

                        logger.info(f"Spider completed for {target_url}")

                    # Active scan
                    logger.info(f"Starting active scan on {target_url}")
                    scan_id = self.zap.ascan.scan(target_url)

                    # Wait for active scan to complete (with timeout)
                    scan_timeout = 180 if scan_depth == "quick" else 300 if scan_depth == "medium" else 600
                    scan_start = time.time()

                    while int(self.zap.ascan.status(scan_id)) < 100:
                        if time.time() - scan_start > scan_timeout:
                            logger.warning(f"Active scan timeout for {target_url}")
                            self.zap.ascan.stop(scan_id)
                            break

                        progress = int(self.zap.ascan.status(scan_id))
                        logger.debug(f"Active scan progress: {progress}%")
                        time.sleep(5)

                    logger.info(f"Active scan completed for {target_url}")

                except Exception as port_error:
                    logger.error(f"Error scanning port {port}: {port_error}", exc_info=True)
                    continue

            # Get all alerts
            alerts = self.zap.core.alerts()
            logger.info(f"Retrieved {len(alerts)} alerts from ZAP")

            # Process alerts
            for alert in alerts:
                processed_alert = {
                    "alert": alert.get("alert", "Unknown"),
                    "risk": alert.get("risk", "Informational"),
                    "confidence": alert.get("confidence", "Medium"),
                    "url": alert.get("url", ""),
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "cwe_id": alert.get("cweid", ""),
                    "wasc_id": alert.get("wascid", "")
                }
                results["alerts"].append(processed_alert)

                # Update summary
                risk = alert.get("risk", "Informational")
                if risk == "High":
                    results["summary"]["high_risk"] += 1
                elif risk == "Medium":
                    results["summary"]["medium_risk"] += 1
                elif risk == "Low":
                    results["summary"]["low_risk"] += 1
                else:
                    results["summary"]["informational"] += 1

            results["summary"]["total_alerts"] = len(alerts)
            results["status"] = "completed"

        except Exception as e:
            logger.error(f"ZAP scan failed: {e}", exc_info=True)
            results["status"] = "failed"
            results["error"] = str(e)

        finally:
            results["scan_duration_seconds"] = int(time.time() - start_time)

        logger.info(
            f"ZAP scan completed: {results['summary']['total_alerts']} alerts "
            f"(High: {results['summary']['high_risk']}, "
            f"Medium: {results['summary']['medium_risk']}, "
            f"Low: {results['summary']['low_risk']})"
        )

        return results

    def scan_kubernetes_service(
        self,
        service_name: str,
        namespace: str,
        ports: List[int],
        scan_depth: str = "medium"
    ) -> Dict:
        """
        Scan a Kubernetes service

        Args:
            service_name: Name of the Kubernetes service
            namespace: Kubernetes namespace
            ports: List of ports to scan
            scan_depth: Scan depth (quick, medium, thorough)

        Returns:
            Scan results dictionary
        """
        # In Kubernetes, services are accessible via DNS: <service>.<namespace>.svc.cluster.local
        target_host = f"{service_name}.{namespace}.svc.cluster.local"

        logger.info(f"Scanning Kubernetes service {service_name} in namespace {namespace}")

        return self.scan_target(
            target_host=target_host,
            target_ports=ports,
            scan_depth=scan_depth
        )

    @staticmethod
    def is_zap_installed(namespace: str = "security") -> bool:
        """
        Check if OWASP ZAP is installed in the cluster

        Args:
            namespace: Kubernetes namespace to check (default: security)

        Returns:
            True if ZAP is installed, False otherwise

        Note:
            Assumes Kubernetes configuration has already been loaded.
            Call load_kubernetes_config() before using this method.
        """
        try:
            # Ensure config is loaded (will be a no-op if already loaded)
            if not is_config_loaded():
                from config.settings import settings
                load_kubernetes_config(in_cluster=settings.k8s_in_cluster)

            apps_v1 = client.AppsV1Api()

            # Check for ZAP deployment
            try:
                deployment = apps_v1.read_namespaced_deployment(
                    name="owasp-zap",
                    namespace=namespace
                )
                logger.info(f"OWASP ZAP deployment found in namespace {namespace}")
                return True
            except ApiException as e:
                if e.status == 404:
                    logger.info(f"OWASP ZAP deployment not found in namespace {namespace}")
                    return False
                raise

        except Exception as e:
            logger.error(f"Error checking ZAP installation: {e}", exc_info=True)
            return False

    @staticmethod
    def install_zap(namespace: str = "security") -> bool:
        """
        Install OWASP ZAP in the Kubernetes cluster

        Args:
            namespace: Kubernetes namespace (default: security)

        Returns:
            True if successful, False otherwise

        Note:
            Assumes Kubernetes configuration has already been loaded.
            Call load_kubernetes_config() before using this method.
        """
        logger.info(f"Installing OWASP ZAP in namespace {namespace}...")

        try:
            # Ensure config is loaded (will be a no-op if already loaded)
            if not is_config_loaded():
                from config.settings import settings
                load_kubernetes_config(in_cluster=settings.k8s_in_cluster)

            core_v1 = client.CoreV1Api()
            apps_v1 = client.AppsV1Api()

            # Create namespace if it doesn't exist
            try:
                core_v1.read_namespace(namespace)
                logger.info(f"Namespace {namespace} already exists")
            except ApiException as e:
                if e.status == 404:
                    logger.info(f"Creating namespace {namespace}")
                    namespace_body = client.V1Namespace(
                        metadata=client.V1ObjectMeta(
                            name=namespace,
                            labels={
                                "app": "vexxy",
                                "vexxy.dev/component": "security"
                            }
                        )
                    )
                    core_v1.create_namespace(body=namespace_body)

            # Create ZAP deployment
            logger.info("Creating OWASP ZAP deployment...")

            # Container configuration
            container = client.V1Container(
                name="zap",
                image="ghcr.io/zaproxy/zaproxy:stable",
                command=["zap.sh"],
                args=[
                    "-daemon",
                    "-host", "0.0.0.0",
                    "-port", "8080",
                    "-config", "api.disablekey=true",  # No API key for now
                    "-config", "api.addrs.addr.name=.*",
                    "-config", "api.addrs.addr.regex=true"
                ],
                ports=[
                    client.V1ContainerPort(container_port=8080, protocol="TCP")
                ],
                resources=client.V1ResourceRequirements(
                    limits={"cpu": "2", "memory": "2Gi"},
                    requests={"cpu": "500m", "memory": "512Mi"}
                ),
                liveness_probe=client.V1Probe(
                    http_get=client.V1HTTPGetAction(
                        path="/",
                        port=8080
                    ),
                    initial_delay_seconds=30,
                    period_seconds=10
                ),
                readiness_probe=client.V1Probe(
                    http_get=client.V1HTTPGetAction(
                        path="/",
                        port=8080
                    ),
                    initial_delay_seconds=10,
                    period_seconds=5
                )
            )

            # Deployment spec
            deployment = client.V1Deployment(
                api_version="apps/v1",
                kind="Deployment",
                metadata=client.V1ObjectMeta(
                    name="owasp-zap",
                    namespace=namespace,
                    labels={
                        "app": "owasp-zap",
                        "vexxy.dev/component": "security-scanner"
                    }
                ),
                spec=client.V1DeploymentSpec(
                    replicas=1,
                    selector=client.V1LabelSelector(
                        match_labels={"app": "owasp-zap"}
                    ),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(
                            labels={"app": "owasp-zap"}
                        ),
                        spec=client.V1PodSpec(
                            containers=[container]
                        )
                    )
                )
            )

            apps_v1.create_namespaced_deployment(
                namespace=namespace,
                body=deployment
            )
            logger.info("OWASP ZAP deployment created successfully")

            # Create Service to expose ZAP
            logger.info("Creating OWASP ZAP service...")

            service = client.V1Service(
                api_version="v1",
                kind="Service",
                metadata=client.V1ObjectMeta(
                    name="owasp-zap",
                    namespace=namespace,
                    labels={
                        "app": "owasp-zap",
                        "vexxy.dev/component": "security-scanner"
                    }
                ),
                spec=client.V1ServiceSpec(
                    selector={"app": "owasp-zap"},
                    ports=[
                        client.V1ServicePort(
                            name="zap-api",
                            protocol="TCP",
                            port=8080,
                            target_port=8080
                        )
                    ],
                    type="ClusterIP"
                )
            )

            core_v1.create_namespaced_service(
                namespace=namespace,
                body=service
            )
            logger.info("OWASP ZAP service created successfully")

            # Wait for deployment to be ready
            logger.info("Waiting for OWASP ZAP to be ready...")
            max_wait = 120  # 2 minutes
            waited = 0

            while waited < max_wait:
                try:
                    deployment_status = apps_v1.read_namespaced_deployment_status(
                        name="owasp-zap",
                        namespace=namespace
                    )

                    if deployment_status.status.ready_replicas and deployment_status.status.ready_replicas > 0:
                        logger.info("OWASP ZAP is ready")
                        return True

                except ApiException:
                    pass

                time.sleep(5)
                waited += 5

            logger.warning("OWASP ZAP deployment created but not ready yet (may still be starting)")
            return True  # Consider it successful even if not ready yet

        except ApiException as e:
            if e.status == 409:
                logger.info("OWASP ZAP already exists (conflict)")
                return True
            logger.error(f"Kubernetes API error installing ZAP: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Failed to install OWASP ZAP: {e}", exc_info=True)
            return False
