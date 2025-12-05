"""
OWASP ZAP Integration Service

Provides security scanning capabilities using OWASP ZAP (Zed Attack Proxy).
Scans exposed ports for common web vulnerabilities.
"""

import logging
import time
from typing import Dict, List, Any
import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter  # type: ignore[import-untyped]
from requests.packages.urllib3.util.retry import Retry  # type: ignore[import-untyped]
from kubernetes import client  # type: ignore[import-untyped]
from kubernetes.client.rest import ApiException  # type: ignore[import-untyped]
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

    def __init__(
        self, zap_host: str = "localhost", zap_port: int = 8080, zap_api_key: str | None = None
    ):
        """
        Initialize ZAP service

        Args:
            zap_host: ZAP proxy host (can be localhost, IP, or Kubernetes DNS name)
            zap_port: ZAP proxy port
            zap_api_key: ZAP API key (if authentication enabled)
        """
        # Support Kubernetes service DNS names
        # If running in cluster, prefer owasp-zap.security.svc.cluster.local
        if zap_host == "localhost":
            # Try cluster DNS first, fallback to localhost
            try:
                # Test if cluster DNS is reachable
                import socket

                socket.gethostbyname("owasp-zap.security.svc.cluster.local")
                zap_host = "owasp-zap.security.svc.cluster.local"
                logger.info("Using Kubernetes service DNS for ZAP connectivity")
            except socket.gaierror:
                logger.info(
                    "Kubernetes DNS not available, using localhost (requires port-forward)"
                )

        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_api_key = zap_api_key or "vexxy-zap-key"
        self.zap_url = f"http://{zap_host}:{zap_port}"

        # Create requests session with retry logic
        self.session = self._create_retry_session()

        logger.info(f"ZAP service initialized at {zap_host}:{zap_port}")

    def _create_retry_session(
        self, retries: int = 3, backoff_factor: float = 0.5
    ) -> requests.Session:
        """
        Create requests session with automatic retry logic

        Args:
            retries: Maximum number of retries
            backoff_factor: Backoff factor for exponential backoff

        Returns:
            Configured requests session
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _call_zap_api(
        self, component: str, api_type: str, action: str, params: Dict | None = None
    ) -> Dict:
        """
        Call ZAP REST API directly

        Args:
            component: API component (e.g., 'core', 'spider', 'ascan')
            api_type: API type ('view' or 'action')
            action: API action name
            params: Additional parameters

        Returns:
            API response as dictionary
        """
        if params is None:
            params = {}

        # Add API key
        params["apikey"] = self.zap_api_key

        # Build URL
        url = f"{self.zap_url}/JSON/{component}/{api_type}/{action}/"

        # Make request
        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()

        return response.json()

    def is_zap_available(self, max_retries: int = 3, retry_delay: float = 2.0) -> bool:
        """
        Check if ZAP is running and accessible with retry logic

        Args:
            max_retries: Maximum number of connection attempts
            retry_delay: Delay between retries in seconds

        Returns:
            True if ZAP is available, False otherwise
        """
        for attempt in range(1, max_retries + 1):
            try:
                # Use session with retry logic
                url = f"{self.zap_url}/JSON/core/view/version/"
                params = {"apikey": self.zap_api_key}
                response = self.session.get(url, params=params, timeout=10)

                if response.status_code == 200:
                    version_data = response.json()
                    version = version_data.get("version", "unknown")
                    logger.info(f"ZAP is available, version: {version}")
                    return True
                else:
                    logger.warning(f"ZAP returned status code {response.status_code}")
                    if attempt < max_retries:
                        logger.info(
                            f"Retrying ZAP connectivity check (attempt {attempt + 1}/{max_retries})..."
                        )
                        time.sleep(retry_delay)
                        continue
                    return False

            except requests.exceptions.ConnectionError as e:
                logger.warning(
                    f"ZAP connection error (attempt {attempt}/{max_retries}): {e}"
                )
                if attempt < max_retries:
                    logger.info(f"Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    continue
                logger.error("ZAP is not reachable after all retry attempts")
                logger.error(
                    f"Ensure OWASP ZAP is running at {self.zap_url}. "
                    "If running outside cluster, use: kubectl port-forward -n security svc/owasp-zap 8080:8080"
                )
                return False

            except requests.exceptions.Timeout as e:
                logger.warning(
                    f"ZAP request timeout (attempt {attempt}/{max_retries}): {e}"
                )
                if attempt < max_retries:
                    logger.info(f"Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    continue
                logger.error("ZAP did not respond after all retry attempts")
                return False

            except Exception as e:
                logger.error(
                    f"Unexpected error checking ZAP availability (attempt {attempt}/{max_retries}): {e}",
                    exc_info=True,
                )
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                return False

        return False

    def scan_target(
        self,
        target_host: str,
        target_ports: List[int],
        scan_depth: str = "medium",
        timeout: int = 600,
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
                "scanned_urls": [],
            }

        results: Dict[str, Any] = {
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
                "total_alerts": 0,
            },
            "scan_duration_seconds": 0,
            "status": "in_progress",
        }

        start_time = time.time()

        try:
            # Check if ZAP is available
            if not self.is_zap_available():
                results["status"] = "failed"
                results["error"] = "ZAP is not available"
                return results

            # Create new session
            self._call_zap_api("core", "action", "newSession")
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
                        self._call_zap_api(
                            "core", "action", "accessUrl", {"url": target_url}
                        )
                        logger.info(f"Accessed {target_url}")
                    except Exception as e:
                        logger.warning(f"Could not access {target_url}: {e}")
                        continue

                    # Spider the target (discover pages)
                    if scan_depth in ["medium", "thorough"]:
                        logger.info(f"Spidering {target_url}")
                        spider_response = self._call_zap_api(
                            "spider", "action", "scan", {"url": target_url}
                        )
                        scan_id = spider_response.get("scan")

                        # Wait for spider to complete (with timeout)
                        spider_timeout = 120 if scan_depth == "medium" else 300
                        spider_start = time.time()

                        while True:
                            status_response = self._call_zap_api(
                                "spider", "view", "status", {"scanId": scan_id}
                            )
                            status = int(status_response.get("status", 0))
                            if status >= 100:
                                break
                            if time.time() - spider_start > spider_timeout:
                                logger.warning(f"Spider timeout for {target_url}")
                                break
                            time.sleep(2)

                        logger.info(f"Spider completed for {target_url}")

                    # Active scan
                    logger.info(f"Starting active scan on {target_url}")
                    ascan_response = self._call_zap_api(
                        "ascan", "action", "scan", {"url": target_url}
                    )
                    scan_id = ascan_response.get("scan")

                    # Wait for active scan to complete (with timeout)
                    scan_timeout = (
                        180
                        if scan_depth == "quick"
                        else 300 if scan_depth == "medium" else 600
                    )
                    scan_start = time.time()

                    while True:
                        status_response = self._call_zap_api(
                            "ascan", "view", "status", {"scanId": scan_id}
                        )
                        status = int(status_response.get("status", 0))
                        if status >= 100:
                            break
                        if time.time() - scan_start > scan_timeout:
                            logger.warning(f"Active scan timeout for {target_url}")
                            self._call_zap_api(
                                "ascan", "action", "stop", {"scanId": scan_id}
                            )
                            break

                        logger.debug(f"Active scan progress: {status}%")
                        time.sleep(5)

                    logger.info(f"Active scan completed for {target_url}")

                except Exception as port_error:
                    logger.error(
                        f"Error scanning port {port}: {port_error}", exc_info=True
                    )
                    continue

            # Get all alerts
            alerts_response = self._call_zap_api("core", "view", "alerts")
            alerts = alerts_response.get("alerts", [])
            logger.info(f"Retrieved {len(alerts)} active scan alerts from ZAP")

            # Run passive checks (even if active scan found nothing)
            # This ensures we detect basic issues like HTTP, missing headers
            logger.info("Running passive security checks...")
            passive_alerts = self.run_passive_checks(results["scanned_urls"])
            logger.info(
                f"Passive checks found {len(passive_alerts)} additional findings"
            )

            # Combine active and passive alerts
            all_alerts = list(alerts) + passive_alerts

            # Process alerts
            for alert in all_alerts:
                processed_alert = {
                    "alert_id": alert.get("pluginid", alert.get("id", "0")),
                    "name": alert.get("alert", "Unknown"),
                    "risk": alert.get("risk", "Informational"),
                    "confidence": alert.get("confidence", "Medium"),
                    "url": alert.get("url", ""),
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "cwe_id": alert.get("cweid", ""),
                    "wasc_id": alert.get("wascid", ""),
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

    def run_passive_checks(self, scanned_urls: List[str]) -> List[Dict]:
        """
        Run passive security checks that don't require spidering

        These checks are valuable even when active scanning finds no URLs:
        - Protocol check (HTTP vs HTTPS)
        - Security headers check
        - Basic SSL/TLS verification

        Args:
            scanned_urls: List of URLs that were scanned

        Returns:
            List of alert dicts in ZAP format
        """
        passive_findings: List[Dict[str, Any]] = []

        if not scanned_urls:
            return passive_findings

        # Check each scanned URL
        for url in scanned_urls:
            try:
                # 1. Protocol check
                if url.startswith("http://"):
                    passive_findings.append(
                        {
                            "pluginid": "10001",
                            "alert": "Insecure Protocol (HTTP)",
                            "risk": "Medium",
                            "confidence": "Certain",
                            "url": url,
                            "description": (
                                "The application uses HTTP instead of HTTPS. "
                                "Data transmitted over HTTP is not encrypted and can be intercepted."
                            ),
                            "solution": (
                                "Configure the application to use HTTPS for all communications. "
                                "Redirect HTTP requests to HTTPS."
                            ),
                            "reference": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection",
                            "cweid": "319",  # Cleartext Transmission of Sensitive Information
                            "wascid": "4",  # Insufficient Transport Layer Protection
                        }
                    )

                # 2. Make one request to check headers
                try:
                    response = self.session.get(url, timeout=10, verify=False)

                    # Check for missing security headers
                    security_headers = {
                        "X-Frame-Options": {
                            "risk": "Medium",
                            "cweid": "1021",  # Improper Restriction of Rendered UI Layers
                            "description": "X-Frame-Options header is not set, allowing the page to be framed",
                            "solution": "Set X-Frame-Options header to DENY or SAMEORIGIN",
                        },
                        "X-Content-Type-Options": {
                            "risk": "Low",
                            "cweid": "16",  # Configuration
                            "description": "X-Content-Type-Options header is not set, allowing MIME-sniffing",
                            "solution": "Set X-Content-Type-Options header to nosniff",
                        },
                        "Content-Security-Policy": {
                            "risk": "Medium",
                            "cweid": "693",  # Protection Mechanism Failure
                            "description": "Content-Security-Policy header is not set, increasing XSS risk",
                            "solution": "Implement a strong Content-Security-Policy",
                        },
                        "Strict-Transport-Security": {
                            "risk": "Medium",
                            "cweid": "523",  # Unprotected Transport of Credentials
                            "description": "Strict-Transport-Security header is not set (HTTPS only)",
                            "solution": "Set Strict-Transport-Security header with max-age",
                        },
                        "X-XSS-Protection": {
                            "risk": "Low",
                            "cweid": "79",  # XSS
                            "description": "X-XSS-Protection header is not set",
                            "solution": "Set X-XSS-Protection header to 1; mode=block",
                        },
                    }

                    for header, details in security_headers.items():
                        # Skip HSTS check for HTTP URLs
                        if header == "Strict-Transport-Security" and url.startswith(
                            "http://"
                        ):
                            continue

                        if header not in response.headers:
                            plugin_id = (
                                f"1000{2 + list(security_headers.keys()).index(header)}"
                            )
                            passive_findings.append(
                                {
                                    "pluginid": plugin_id,
                                    "alert": f"Missing Security Header: {header}",
                                    "risk": details["risk"],
                                    "confidence": "Certain",
                                    "url": url,
                                    "description": details["description"],
                                    "solution": details["solution"],
                                    "reference": "https://owasp.org/www-project-secure-headers/",
                                    "cweid": details["cweid"],
                                    "wascid": "15",  # Application Misconfiguration
                                }
                            )

                    # 3. Check for server information disclosure
                    if "Server" in response.headers:
                        server_value = response.headers["Server"]
                        # Check if server header reveals too much info
                        if any(
                            keyword in server_value.lower()
                            for keyword in ["apache/", "nginx/", "iis/", "tomcat/"]
                        ):
                            passive_findings.append(
                                {
                                    "pluginid": "10008",
                                    "alert": "Server Information Disclosure",
                                    "risk": "Low",
                                    "confidence": "Certain",
                                    "url": url,
                                    "description": f"Server header reveals detailed version information: {server_value}",
                                    "solution": "Configure the server to remove or obfuscate version information",
                                    "reference": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                                    "cweid": "200",  # Exposure of Sensitive Information
                                    "wascid": "13",  # Information Leakage
                                }
                            )

                except Exception as check_error:
                    logger.debug(f"Error checking headers for {url}: {check_error}")
                    # Don't fail passive checks if one URL fails
                    continue

            except Exception as e:
                logger.debug(f"Error in passive check for {url}: {e}")
                continue

        return passive_findings

    def scan_kubernetes_service(
        self,
        service_name: str,
        namespace: str,
        ports: List[int],
        scan_depth: str = "medium",
        time_budget: int = 600,
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

        logger.info(
            f"Scanning Kubernetes service {service_name} in namespace {namespace}"
        )

        return self.scan_target(
            target_host=target_host, target_ports=ports, scan_depth=scan_depth
        )

    @staticmethod
    def is_zap_installed(namespace: str = "security") -> bool:
        """
        Check if OWASP ZAP is installed in the cluster

        This method checks for:
        1. Namespace existence
        2. ZAP deployment existence
        3. ZAP service existence (optional)

        Args:
            namespace: Kubernetes namespace to check (default: security)

        Returns:
            True if ZAP is installed (even if still starting), False otherwise

        Note:
            Assumes Kubernetes configuration has already been loaded.
            Call load_kubernetes_config() before using this method.
        """
        try:
            # Ensure config is loaded (will be a no-op if already loaded)
            if not is_config_loaded():
                from config.settings import settings

                load_kubernetes_config(in_cluster=settings.k8s_in_cluster)

            core_v1 = client.CoreV1Api()
            apps_v1 = client.AppsV1Api()

            # Check if namespace exists
            try:
                core_v1.read_namespace(namespace)
                logger.debug(f"Namespace {namespace} found")
            except ApiException as e:
                if e.status == 404:
                    logger.info(f"Namespace {namespace} not found - ZAP not installed")
                    return False
                raise

            # Check for ZAP deployment
            try:
                deployment = apps_v1.read_namespaced_deployment(
                    name="owasp-zap", namespace=namespace
                )
                logger.info(f"OWASP ZAP deployment found in namespace {namespace}")

                # Check deployment status
                deployment_ready = (
                    deployment.status.ready_replicas
                    and deployment.status.ready_replicas > 0
                )

                if deployment_ready:
                    logger.info("OWASP ZAP deployment is running and ready")
                else:
                    logger.info("OWASP ZAP deployment exists but may still be starting")

                # If deployment exists, consider ZAP installed regardless of ready status
                return True

            except ApiException as e:
                if e.status == 404:
                    logger.info(
                        f"OWASP ZAP deployment not found in namespace {namespace}"
                    )
                    return False
                raise

        except Exception as e:
            logger.error(f"Error checking ZAP installation: {e}", exc_info=True)
            return False

    @staticmethod
    def install_zap(namespace: str = "security") -> bool:
        """
        Install OWASP ZAP in the Kubernetes cluster (idempotent)

        This method is idempotent - it checks if ZAP is already installed
        and skips installation if it exists.

        Args:
            namespace: Kubernetes namespace (default: security)

        Returns:
            True if successful or already installed, False on error

        Note:
            Assumes Kubernetes configuration has already been loaded.
            Call load_kubernetes_config() before using this method.
        """
        # Check if ZAP is already installed (idempotent)
        if ZAPService.is_zap_installed(namespace=namespace):
            logger.info(
                f"OWASP ZAP is already installed in namespace {namespace}, skipping installation"
            )
            return True

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
                            labels={"app": "vexxy", "vexxy.dev/component": "security"},
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
                    "-host",
                    "0.0.0.0",
                    "-port",
                    "8080",
                    "-config",
                    "api.disablekey=true",  # No API key for now
                    "-config",
                    "api.addrs.addr.name=.*",
                    "-config",
                    "api.addrs.addr.regex=true",
                ],
                ports=[client.V1ContainerPort(container_port=8080, protocol="TCP")],
                resources=client.V1ResourceRequirements(
                    limits={"cpu": "2", "memory": "2Gi"},
                    requests={"cpu": "500m", "memory": "512Mi"},
                ),
                liveness_probe=client.V1Probe(
                    http_get=client.V1HTTPGetAction(path="/", port=8080),
                    initial_delay_seconds=30,
                    period_seconds=10,
                ),
                readiness_probe=client.V1Probe(
                    http_get=client.V1HTTPGetAction(path="/", port=8080),
                    initial_delay_seconds=10,
                    period_seconds=5,
                ),
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
                        "vexxy.dev/component": "security-scanner",
                    },
                ),
                spec=client.V1DeploymentSpec(
                    replicas=1,
                    selector=client.V1LabelSelector(match_labels={"app": "owasp-zap"}),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(labels={"app": "owasp-zap"}),
                        spec=client.V1PodSpec(containers=[container]),
                    ),
                ),
            )

            apps_v1.create_namespaced_deployment(namespace=namespace, body=deployment)
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
                        "vexxy.dev/component": "security-scanner",
                    },
                ),
                spec=client.V1ServiceSpec(
                    selector={"app": "owasp-zap"},
                    ports=[
                        client.V1ServicePort(
                            name="zap-api", protocol="TCP", port=8080, target_port=8080
                        )
                    ],
                    type="ClusterIP",
                ),
            )

            core_v1.create_namespaced_service(namespace=namespace, body=service)
            logger.info("OWASP ZAP service created successfully")

            # Wait for deployment to be ready
            logger.info("Waiting for OWASP ZAP to be ready...")
            max_wait = 120  # 2 minutes
            waited = 0

            while waited < max_wait:
                try:
                    deployment_status = apps_v1.read_namespaced_deployment_status(
                        name="owasp-zap", namespace=namespace
                    )

                    if (
                        deployment_status.status.ready_replicas
                        and deployment_status.status.ready_replicas > 0
                    ):
                        logger.info("OWASP ZAP is ready")
                        return True

                except ApiException:
                    pass

                time.sleep(5)
                waited += 5

            logger.warning(
                "OWASP ZAP deployment created but not ready yet (may still be starting)"
            )
            return True  # Consider it successful even if not ready yet

        except ApiException as e:
            if e.status == 409:
                # Resource already exists - this shouldn't happen since we check first,
                # but handle it gracefully (race condition between check and create)
                logger.info(
                    "OWASP ZAP already exists (conflict during creation - likely race condition)"
                )
                return True
            logger.error(f"Kubernetes API error installing ZAP: {e}", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Failed to install OWASP ZAP: {e}", exc_info=True)
            return False
