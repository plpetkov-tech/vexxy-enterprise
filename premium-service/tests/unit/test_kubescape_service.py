"""
Unit tests for Kubescape Service.

Tests the core functionality of Kubescape integration without requiring a real cluster.
"""
import pytest
from unittest.mock import Mock, patch
from kubernetes.client.rest import ApiException

# Import fixtures
from tests.fixtures.k8s_mocks import (
    create_mock_deployment,
    create_mock_crd,
    setup_deployment_success,
    setup_crd_extraction,
)
from tests.fixtures.kubescape_fixtures import (
    get_sample_vex_crd,
    get_sample_filtered_sbom_crd,
)

from services.kubescape import KubescapeService
from exceptions import KubernetesError


@pytest.fixture
def kubescape_service(mock_k8s_config, mock_k8s_clients):
    """
    Create a KubescapeService instance with mocked K8s clients.

    The mock_k8s_config fixture mocks the kubernetes.config module,
    and mock_k8s_clients provides all mocked API clients.
    """
    with patch("services.kubescape.is_config_loaded", return_value=False), \
         patch("services.kubescape.load_kubernetes_config"):
        service = KubescapeService(namespace="test-namespace")
        return service


# =============================================================================
# Test: Initialization
# =============================================================================


@pytest.mark.unit
def test_kubescape_service_init(mock_k8s_config, mock_k8s_clients):
    """Test KubescapeService initialization."""
    with patch("services.kubescape.is_config_loaded", return_value=False), \
         patch("services.kubescape.load_kubernetes_config") as mock_load:
        service = KubescapeService(namespace="test-ns")

        assert service.namespace == "test-ns"
        assert service.apps_v1 is not None
        assert service.core_v1 is not None
        assert service.custom_objects_api is not None
        mock_load.assert_called_once()


@pytest.mark.unit
def test_kubescape_service_init_default_namespace(mock_k8s_config, mock_k8s_clients, mock_settings):
    """Test KubescapeService uses default namespace from settings."""
    mock_settings.k8s_sandbox_namespace = "vexxy-sandbox"

    with patch("services.kubescape.is_config_loaded", return_value=False), \
         patch("services.kubescape.load_kubernetes_config"):
        service = KubescapeService()
        assert service.namespace == "vexxy-sandbox"


@pytest.mark.unit
def test_kubescape_service_init_config_already_loaded(mock_k8s_config, mock_k8s_clients):
    """Test KubescapeService skips config loading if already loaded."""
    with patch("services.kubescape.is_config_loaded", return_value=True), \
         patch("services.kubescape.load_kubernetes_config") as mock_load:
        service = KubescapeService()
        mock_load.assert_not_called()


@pytest.mark.unit
def test_kubescape_service_init_config_load_failure(mock_k8s_config):
    """Test KubescapeService raises KubernetesError on config load failure."""
    with patch("services.kubescape.is_config_loaded", return_value=False), \
         patch("services.kubescape.load_kubernetes_config", side_effect=Exception("Config error")):
        with pytest.raises(KubernetesError) as exc_info:
            KubescapeService()

        # Check the error message contains the operation and error text
        assert "load_config" in exc_info.value.message
        assert "Config error" in exc_info.value.message
        assert exc_info.value.error_code == "EXTERNAL_SERVICE_ERROR"


# =============================================================================
# Test: extract_runtime_vex
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_extract_runtime_vex_success(kubescape_service, mock_k8s_clients, sample_vex_crd):
    """Test successful VEX extraction from Kubescape CRD."""
    deployment_name = "test-deployment"
    namespace = "test-namespace"

    # Setup mock: list returns matching CRD
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.return_value = {
        "items": [sample_vex_crd]
    }

    # Setup mock: get returns full CRD
    mock_k8s_clients["custom_objects"].get_namespaced_custom_object.return_value = sample_vex_crd

    # Call the method
    result = kubescape_service.extract_runtime_vex(deployment_name, namespace)

    # Assertions
    assert result is not None
    assert "statements" in result
    assert len(result["statements"]) > 0
    assert result["metadata"]["author"] == "Kubescape"

    # Verify API was called correctly
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.assert_called_once_with(
        group="spdx.softwarecomposition.kubescape.io",
        version="v1beta1",
        namespace=namespace,
        plural="openvulnerabilityexchangecontainers",
    )


@pytest.mark.unit
@pytest.mark.kubescape
def test_extract_runtime_vex_not_found(kubescape_service, mock_k8s_clients):
    """Test VEX extraction when no CRDs are found."""
    deployment_name = "test-deployment"
    namespace = "test-namespace"

    # Setup mock: list returns empty items
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.return_value = {
        "items": []
    }

    # Call the method
    result = kubescape_service.extract_runtime_vex(deployment_name, namespace)

    # Assertions
    assert result is None


@pytest.mark.unit
@pytest.mark.kubescape
def test_extract_runtime_vex_api_exception(kubescape_service, mock_k8s_clients):
    """Test VEX extraction handles API exceptions."""
    deployment_name = "test-deployment"
    namespace = "test-namespace"

    # Setup mock: list raises ApiException
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    # Call the method - should raise KubernetesError
    with pytest.raises(KubernetesError) as exc_info:
        kubescape_service.extract_runtime_vex(deployment_name, namespace)

    assert exc_info.value.operation == "extract_runtime_vex"


@pytest.mark.unit
@pytest.mark.kubescape
def test_extract_runtime_vex_multiple_crds(kubescape_service, mock_k8s_clients):
    """Test VEX extraction when multiple CRDs match - returns first one."""
    deployment_name = "test-deployment"
    namespace = "test-namespace"

    vex_crd_1 = get_sample_vex_crd(deployment_name, namespace, num_vulnerabilities=2)
    vex_crd_2 = get_sample_vex_crd(deployment_name, namespace, num_vulnerabilities=3)

    # Setup mock: list returns multiple CRDs
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.return_value = {
        "items": [vex_crd_1, vex_crd_2]
    }

    # Setup mock: get returns first CRD
    mock_k8s_clients["custom_objects"].get_namespaced_custom_object.return_value = vex_crd_1

    # Call the method
    result = kubescape_service.extract_runtime_vex(deployment_name, namespace)

    # Assertions - should get the first CRD
    assert result is not None
    assert len(result["statements"]) == 2


# =============================================================================
# Test: extract_filtered_sbom
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_extract_filtered_sbom_success(kubescape_service, mock_k8s_clients, sample_filtered_sbom_crd):
    """Test successful filtered SBOM extraction."""
    deployment_name = "test-deployment"
    namespace = "test-namespace"

    # Setup mock: list returns matching CRD
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.return_value = {
        "items": [sample_filtered_sbom_crd]
    }

    # Setup mock: get returns full CRD
    mock_k8s_clients["custom_objects"].get_namespaced_custom_object.return_value = sample_filtered_sbom_crd

    # Call the method
    result = kubescape_service.extract_filtered_sbom(deployment_name, namespace)

    # Assertions
    assert result is not None
    assert "packages" in result
    assert len(result["packages"]) > 0
    assert result["spdxVersion"] == "SPDX-2.3"

    # Verify API was called correctly
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.assert_called_once_with(
        group="spdx.softwarecomposition.kubescape.io",
        version="v1beta1",
        namespace=namespace,
        plural="sbomsyftfiltereds",
    )


@pytest.mark.unit
@pytest.mark.kubescape
def test_extract_filtered_sbom_not_found(kubescape_service, mock_k8s_clients):
    """Test SBOM extraction when no CRDs are found."""
    deployment_name = "test-deployment"
    namespace = "test-namespace"

    # Setup mock: list returns empty items
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.return_value = {
        "items": []
    }

    # Call the method
    result = kubescape_service.extract_filtered_sbom(deployment_name, namespace)

    # Assertions
    assert result is None


# =============================================================================
# Test: deploy_workload_for_analysis
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_deploy_workload_basic(kubescape_service, mock_k8s_clients):
    """Test basic workload deployment without sidecars."""
    job_id = "job-123"
    image = "nginx:1.21"
    command = ["nginx", "-g", "daemon off;"]
    analysis_duration = 60

    # Setup mock
    mock_deployment = create_mock_deployment("vexxy-analysis-job-123", "test-namespace")
    mock_k8s_clients["apps_v1"].create_namespaced_deployment.return_value = mock_deployment

    # Call the method
    result = kubescape_service.deploy_workload_for_analysis(
        job_id=job_id,
        image=image,
        command=command,
        analysis_duration=analysis_duration,
        enable_profiling=False,
        enable_pentesting=False,
        ports=None,
    )

    # Assertions
    assert result == "vexxy-analysis-job-123"
    mock_k8s_clients["apps_v1"].create_namespaced_deployment.assert_called_once()

    # Verify deployment spec
    call_args = mock_k8s_clients["apps_v1"].create_namespaced_deployment.call_args
    deployment_body = call_args[1]["body"]

    assert deployment_body.metadata.name == "vexxy-analysis-job-123"
    assert deployment_body.metadata.namespace == "test-namespace"
    assert "vexxy.dev/analysis" in deployment_body.metadata.labels
    assert deployment_body.spec.replicas == 1


@pytest.mark.unit
@pytest.mark.kubescape
@pytest.mark.pentest
def test_deploy_workload_with_pentesting_sidecar(kubescape_service, mock_k8s_clients):
    """Test workload deployment with pentesting sidecar enabled."""
    job_id = "job-123"
    image = "nginx:1.21"
    command = ["nginx", "-g", "daemon off;"]
    analysis_duration = 60
    ports = [8080, 8443]

    # Setup mocks
    mock_deployment = create_mock_deployment("vexxy-analysis-job-123", "test-namespace")
    mock_k8s_clients["apps_v1"].create_namespaced_deployment.return_value = mock_deployment
    mock_k8s_clients["core_v1"].create_namespaced_service.return_value = Mock()

    # Call the method
    result = kubescape_service.deploy_workload_for_analysis(
        job_id=job_id,
        image=image,
        command=command,
        analysis_duration=analysis_duration,
        enable_profiling=False,
        enable_pentesting=True,
        ports=ports,
    )

    # Assertions
    assert result == "vexxy-analysis-job-123"

    # Verify service was created for pentesting
    mock_k8s_clients["core_v1"].create_namespaced_service.assert_called_once()

    # Verify deployment has pentest sidecar
    call_args = mock_k8s_clients["apps_v1"].create_namespaced_deployment.call_args
    deployment_body = call_args[1]["body"]

    # The deployment should have 2 containers: main + pentest sidecar
    containers = deployment_body.spec.template.spec.containers
    assert len(containers) == 2
    assert containers[1].name == "kali-pentester"


@pytest.mark.unit
@pytest.mark.kubescape
def test_deploy_workload_without_pentesting_no_sidecar(kubescape_service, mock_k8s_clients):
    """Test workload deployment without pentesting - no sidecar created."""
    job_id = "job-123"
    image = "nginx:1.21"
    command = ["nginx", "-g", "daemon off;"]
    analysis_duration = 60

    # Setup mock
    mock_deployment = create_mock_deployment("vexxy-analysis-job-123", "test-namespace")
    mock_k8s_clients["apps_v1"].create_namespaced_deployment.return_value = mock_deployment

    # Call the method
    result = kubescape_service.deploy_workload_for_analysis(
        job_id=job_id,
        image=image,
        command=command,
        analysis_duration=analysis_duration,
        enable_profiling=False,
        enable_pentesting=False,
        ports=None,
    )

    # Assertions
    assert result == "vexxy-analysis-job-123"

    # Verify service was NOT created (no pentesting)
    mock_k8s_clients["core_v1"].create_namespaced_service.assert_not_called()

    # Verify deployment has only 1 container (main)
    call_args = mock_k8s_clients["apps_v1"].create_namespaced_deployment.call_args
    deployment_body = call_args[1]["body"]
    containers = deployment_body.spec.template.spec.containers
    assert len(containers) == 1


@pytest.mark.unit
@pytest.mark.kubescape
def test_deploy_workload_api_exception(kubescape_service, mock_k8s_clients):
    """Test workload deployment handles API exceptions."""
    job_id = "job-123"
    image = "nginx:1.21"
    command = ["nginx", "-g", "daemon off;"]
    analysis_duration = 60

    # Setup mock: create raises ApiException
    mock_k8s_clients["apps_v1"].create_namespaced_deployment.side_effect = ApiException(
        status=403, reason="Forbidden"
    )

    # Call the method - should raise KubernetesError
    with pytest.raises(KubernetesError) as exc_info:
        kubescape_service.deploy_workload_for_analysis(
            job_id=job_id,
            image=image,
            command=command,
            analysis_duration=analysis_duration,
            enable_profiling=False,
            enable_pentesting=False,
            ports=None,
        )

    assert exc_info.value.operation == "deploy_workload"
    assert "403" in str(exc_info.value.details)


# =============================================================================
# Test: delete_workload
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_delete_workload_success(kubescape_service, mock_k8s_clients):
    """Test successful workload deletion."""
    deployment_name = "test-deployment"

    # Setup mock
    mock_k8s_clients["apps_v1"].delete_namespaced_deployment.return_value = Mock()

    # Call the method
    kubescape_service.delete_workload(deployment_name)

    # Assertions
    mock_k8s_clients["apps_v1"].delete_namespaced_deployment.assert_called_once_with(
        name=deployment_name,
        namespace="test-namespace",
        propagation_policy="Foreground",
    )


@pytest.mark.unit
@pytest.mark.kubescape
def test_delete_workload_not_found(kubescape_service, mock_k8s_clients):
    """Test workload deletion when deployment doesn't exist - should not raise error."""
    deployment_name = "nonexistent-deployment"

    # Setup mock: delete raises 404
    mock_k8s_clients["apps_v1"].delete_namespaced_deployment.side_effect = ApiException(
        status=404, reason="Not Found"
    )

    # Call the method - should NOT raise error (graceful handling)
    kubescape_service.delete_workload(deployment_name)

    # No exception should be raised


@pytest.mark.unit
@pytest.mark.kubescape
def test_delete_workload_other_api_exception(kubescape_service, mock_k8s_clients):
    """Test workload deletion with non-404 API exception - should raise KubernetesError."""
    deployment_name = "test-deployment"

    # Setup mock: delete raises 500
    mock_k8s_clients["apps_v1"].delete_namespaced_deployment.side_effect = ApiException(
        status=500, reason="Internal Server Error"
    )

    # Call the method - should raise KubernetesError
    with pytest.raises(KubernetesError) as exc_info:
        kubescape_service.delete_workload(deployment_name)

    assert exc_info.value.operation == "delete_workload"


# =============================================================================
# Test: wait_for_kubescape_analysis
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
@pytest.mark.slow
def test_wait_for_kubescape_analysis_success(kubescape_service, mock_k8s_clients, sample_vex_crd, sample_filtered_sbom_crd):
    """Test waiting for Kubescape analysis completes successfully."""
    deployment_name = "test-deployment"
    timeout = 60

    # Setup mocks: CRDs appear after first check
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.side_effect = [
        # First call (VEX): empty
        {"items": []},
        # Second call (SBOM): empty
        {"items": []},
        # Third call (VEX): found
        {"items": [sample_vex_crd]},
        # Fourth call (SBOM): found
        {"items": [sample_filtered_sbom_crd]},
    ]

    # Call the method
    with patch("time.sleep"):  # Mock sleep to speed up test
        result = kubescape_service.wait_for_kubescape_analysis(deployment_name, timeout)

    # Assertions
    assert result is True


@pytest.mark.unit
@pytest.mark.kubescape
@pytest.mark.slow
def test_wait_for_kubescape_analysis_timeout(kubescape_service, mock_k8s_clients):
    """Test waiting for Kubescape analysis times out."""
    deployment_name = "test-deployment"
    timeout = 5  # Short timeout

    # Setup mocks: CRDs never appear
    mock_k8s_clients["custom_objects"].list_namespaced_custom_object.return_value = {
        "items": []
    }

    # Call the method
    with patch("time.sleep"), \
         patch("time.time", side_effect=[0, 3, 6]):  # Simulate time passing
        result = kubescape_service.wait_for_kubescape_analysis(deployment_name, timeout)

    # Assertions
    assert result is False


# =============================================================================
# Test: _create_pentest_sidecar
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
@pytest.mark.pentest
def test_create_pentest_sidecar(kubescape_service):
    """Test pentesting sidecar container creation."""
    job_id = "job-123"
    deployment_name = "test-deployment"
    primary_port = 8080
    max_runtime = 300

    # Call the method
    sidecar = kubescape_service._create_pentest_sidecar(
        job_id=job_id,
        deployment_name=deployment_name,
        primary_port=primary_port,
        max_runtime=max_runtime,
    )

    # Assertions
    assert sidecar.name == "kali-pentester"
    assert sidecar.image == "vexxy-kali-pentester"
    assert sidecar.image_pull_policy == "IfNotPresent"

    # Verify args
    assert len(sidecar.args) == 3
    assert f"{deployment_name}-svc.test-namespace.svc.cluster.local" in sidecar.args
    assert str(primary_port) in sidecar.args
    assert str(max_runtime) in sidecar.args

    # Verify security context
    assert sidecar.security_context.run_as_non_root is False
    assert sidecar.security_context.allow_privilege_escalation is False
    assert sidecar.security_context.read_only_root_filesystem is False

    # Verify capabilities
    assert "NET_RAW" in sidecar.security_context.capabilities.add

    # Verify resources
    assert sidecar.resources.requests["cpu"] == "200m"
    assert sidecar.resources.requests["memory"] == "256Mi"
    assert sidecar.resources.limits["cpu"] == "500m"
    assert sidecar.resources.limits["memory"] == "512Mi"

    # Verify volume mounts
    assert len(sidecar.volume_mounts) == 1
    assert sidecar.volume_mounts[0].name == "pentest-output"
    assert sidecar.volume_mounts[0].mount_path == "/pentest-output"


# =============================================================================
# Test: Namespace management
# =============================================================================


@pytest.mark.unit
def test_ensure_namespace_exists_already_exists(mock_k8s_config, mock_k8s_clients):
    """Test namespace creation when namespace already exists."""
    mock_k8s_clients["core_v1"].read_namespace.return_value = Mock()

    with patch("services.kubescape.is_config_loaded", return_value=False), \
         patch("services.kubescape.load_kubernetes_config"):
        service = KubescapeService(namespace="existing-namespace")

        # Namespace read should have been called
        mock_k8s_clients["core_v1"].read_namespace.assert_called_once_with("existing-namespace")

        # Namespace create should NOT have been called
        mock_k8s_clients["core_v1"].create_namespace.assert_not_called()


@pytest.mark.unit
def test_ensure_namespace_creates_if_not_exists(mock_k8s_config, mock_k8s_clients):
    """Test namespace creation when namespace doesn't exist."""
    # Setup mock: read raises 404, then create succeeds
    mock_k8s_clients["core_v1"].read_namespace.side_effect = ApiException(
        status=404, reason="Not Found"
    )
    mock_k8s_clients["core_v1"].create_namespace.return_value = Mock()

    with patch("services.kubescape.is_config_loaded", return_value=False), \
         patch("services.kubescape.load_kubernetes_config"):
        service = KubescapeService(namespace="new-namespace")

        # Namespace read should have been called
        mock_k8s_clients["core_v1"].read_namespace.assert_called_once_with("new-namespace")

        # Namespace create should have been called
        mock_k8s_clients["core_v1"].create_namespace.assert_called_once()
