"""
Mock helpers for Kubernetes client objects.

These mocks provide reusable fixtures for testing K8s integrations without
requiring a real cluster.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, Mock

import pytest
from kubernetes.client import (
    V1ContainerStatus,
    V1Deployment,
    V1DeploymentCondition,
    V1DeploymentSpec,
    V1DeploymentStatus,
    V1LabelSelector,
    V1ObjectMeta,
    V1Pod,
    V1PodCondition,
    V1PodSpec,
    V1PodStatus,
    V1Service,
    V1ServicePort,
    V1ServiceSpec,
)


# =============================================================================
# Mock Data Builders
# =============================================================================


def create_mock_deployment(
    name: str,
    namespace: str = "default",
    replicas: int = 1,
    available_replicas: int = 1,
    ready: bool = True,
    labels: Optional[Dict[str, str]] = None,
    annotations: Optional[Dict[str, str]] = None,
) -> V1Deployment:
    """Create a mock K8s Deployment object."""
    if labels is None:
        labels = {"app": name}
    if annotations is None:
        annotations = {}

    conditions = []
    if ready:
        conditions.append(
            V1DeploymentCondition(
                type="Available",
                status="True",
                reason="MinimumReplicasAvailable",
                message="Deployment has minimum availability",
                last_transition_time=datetime.utcnow(),
            )
        )

    return V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
            annotations=annotations,
            uid=f"uid-{name}",
            resource_version="1",
        ),
        spec=V1DeploymentSpec(
            replicas=replicas,
            selector=V1LabelSelector(match_labels=labels),
            template=Mock(),  # Simplified for testing
        ),
        status=V1DeploymentStatus(
            replicas=replicas,
            available_replicas=available_replicas if ready else 0,
            ready_replicas=available_replicas if ready else 0,
            conditions=conditions,
        ),
    )


def create_mock_pod(
    name: str,
    namespace: str = "default",
    phase: str = "Running",
    ready: bool = True,
    container_statuses: Optional[List] = None,
    labels: Optional[Dict[str, str]] = None,
) -> V1Pod:
    """Create a mock K8s Pod object."""
    if labels is None:
        labels = {"app": name}

    if container_statuses is None:
        container_statuses = [
            V1ContainerStatus(
                name="main",
                ready=ready,
                restart_count=0,
                image="nginx:latest",
                image_id="docker-pullable://nginx@sha256:abc123",
                state=Mock(running=Mock(started_at=datetime.utcnow())),
            )
        ]

    conditions = []
    if ready:
        conditions.append(
            V1PodCondition(
                type="Ready",
                status="True",
                last_transition_time=datetime.utcnow(),
            )
        )

    return V1Pod(
        api_version="v1",
        kind="Pod",
        metadata=V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
            uid=f"uid-{name}",
        ),
        spec=V1PodSpec(containers=[Mock()]),  # Simplified
        status=V1PodStatus(
            phase=phase,
            conditions=conditions,
            container_statuses=container_statuses,
        ),
    )


def create_mock_service(
    name: str,
    namespace: str = "default",
    service_type: str = "ClusterIP",
    ports: Optional[List[int]] = None,
    labels: Optional[Dict[str, str]] = None,
) -> V1Service:
    """Create a mock K8s Service object."""
    if labels is None:
        labels = {"app": name}
    if ports is None:
        ports = [8080]

    port_specs = [
        V1ServicePort(
            name=f"port-{port}",
            port=port,
            target_port=port,
            protocol="TCP",
        )
        for port in ports
    ]

    return V1Service(
        api_version="v1",
        kind="Service",
        metadata=V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels=labels,
        ),
        spec=V1ServiceSpec(
            type=service_type,
            selector=labels,
            ports=port_specs,
        ),
    )


def create_mock_crd(
    group: str,
    version: str,
    plural: str,
    name: str,
    namespace: str,
    spec: Dict[str, Any],
    status: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a mock Custom Resource Definition object."""
    crd = {
        "apiVersion": f"{group}/{version}",
        "kind": plural.capitalize(),
        "metadata": {
            "name": name,
            "namespace": namespace,
            "uid": f"uid-{name}",
            "resourceVersion": "1",
        },
        "spec": spec,
    }
    if status:
        crd["status"] = status
    return crd


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_apps_v1_api(mocker):
    """Mock kubernetes.client.AppsV1Api."""
    mock_api = MagicMock()

    # Mock deployment operations
    mock_api.create_namespaced_deployment = Mock()
    mock_api.read_namespaced_deployment = Mock()
    mock_api.read_namespaced_deployment_status = Mock()
    mock_api.delete_namespaced_deployment = Mock()
    mock_api.list_namespaced_deployment = Mock()
    mock_api.patch_namespaced_deployment = Mock()

    # Patch the API class
    mocker.patch("kubernetes.client.AppsV1Api", return_value=mock_api)
    return mock_api


@pytest.fixture
def mock_core_v1_api(mocker):
    """Mock kubernetes.client.CoreV1Api."""
    mock_api = MagicMock()

    # Mock pod operations
    mock_api.list_namespaced_pod = Mock()
    mock_api.read_namespaced_pod = Mock()
    mock_api.read_namespaced_pod_log = Mock(return_value="Mock pod logs")
    mock_api.delete_namespaced_pod = Mock()

    # Mock service operations
    mock_api.create_namespaced_service = Mock()
    mock_api.read_namespaced_service = Mock()
    mock_api.delete_namespaced_service = Mock()

    # Mock namespace operations
    mock_api.create_namespace = Mock()
    mock_api.read_namespace = Mock()
    mock_api.delete_namespace = Mock()
    mock_api.list_namespace = Mock()

    # Mock configmap operations
    mock_api.read_namespaced_config_map = Mock()

    # Mock secret operations
    mock_api.read_namespaced_secret = Mock()

    # Patch the API class
    mocker.patch("kubernetes.client.CoreV1Api", return_value=mock_api)
    return mock_api


@pytest.fixture
def mock_custom_objects_api(mocker):
    """Mock kubernetes.client.CustomObjectsApi."""
    mock_api = MagicMock()

    # Mock CRD operations
    mock_api.get_namespaced_custom_object = Mock()
    mock_api.list_namespaced_custom_object = Mock()
    mock_api.list_cluster_custom_object = Mock()
    mock_api.create_namespaced_custom_object = Mock()
    mock_api.delete_namespaced_custom_object = Mock()
    mock_api.patch_namespaced_custom_object = Mock()

    # Patch the API class
    mocker.patch("kubernetes.client.CustomObjectsApi", return_value=mock_api)
    return mock_api


@pytest.fixture
def mock_batch_v1_api(mocker):
    """Mock kubernetes.client.BatchV1Api."""
    mock_api = MagicMock()

    # Mock job operations
    mock_api.create_namespaced_job = Mock()
    mock_api.read_namespaced_job = Mock()
    mock_api.read_namespaced_job_status = Mock()
    mock_api.delete_namespaced_job = Mock()
    mock_api.list_namespaced_job = Mock()

    # Patch the API class
    mocker.patch("kubernetes.client.BatchV1Api", return_value=mock_api)
    return mock_api


@pytest.fixture
def mock_dynamic_client(mocker):
    """Mock kubernetes.dynamic.DynamicClient."""
    mock_client = MagicMock()
    mock_client.resources = Mock()

    # Patch the DynamicClient class
    mocker.patch("kubernetes.dynamic.DynamicClient", return_value=mock_client)
    return mock_client


@pytest.fixture
def mock_k8s_clients(
    mock_apps_v1_api,
    mock_core_v1_api,
    mock_custom_objects_api,
    mock_batch_v1_api,
    mock_dynamic_client,
):
    """
    Composite fixture that provides all K8s API mocks.

    Returns a dict with all mocked clients for easy access.
    """
    return {
        "apps_v1": mock_apps_v1_api,
        "core_v1": mock_core_v1_api,
        "custom_objects": mock_custom_objects_api,
        "batch_v1": mock_batch_v1_api,
        "dynamic": mock_dynamic_client,
    }


# =============================================================================
# Helper Functions
# =============================================================================


def setup_deployment_success(mock_apps_v1_api, name: str, namespace: str):
    """
    Setup mocks for a successful deployment creation and monitoring.

    Args:
        mock_apps_v1_api: Mocked AppsV1Api
        name: Deployment name
        namespace: Deployment namespace
    """
    deployment = create_mock_deployment(name, namespace, ready=True)

    # Mock create operation
    mock_apps_v1_api.create_namespaced_deployment.return_value = deployment

    # Mock read operations (for status monitoring)
    mock_apps_v1_api.read_namespaced_deployment.return_value = deployment
    mock_apps_v1_api.read_namespaced_deployment_status.return_value = deployment

    return deployment


def setup_pod_success(mock_core_v1_api, name: str, namespace: str):
    """
    Setup mocks for successful pod operations.

    Args:
        mock_core_v1_api: Mocked CoreV1Api
        name: Pod name
        namespace: Pod namespace
    """
    pod = create_mock_pod(name, namespace, phase="Running", ready=True)

    # Mock pod list (for deployment monitoring)
    mock_core_v1_api.list_namespaced_pod.return_value = Mock(items=[pod])

    # Mock pod read
    mock_core_v1_api.read_namespaced_pod.return_value = pod

    return pod


def setup_crd_extraction(
    mock_custom_objects_api,
    group: str,
    version: str,
    plural: str,
    name: str,
    namespace: str,
    crd_data: Dict[str, Any],
):
    """
    Setup mocks for CRD extraction operations.

    Args:
        mock_custom_objects_api: Mocked CustomObjectsApi
        group: CRD group (e.g., 'spdx.softwarecomposition.kubescape.io')
        version: CRD version (e.g., 'v1beta1')
        plural: CRD plural name (e.g., 'openvulnerabilityexchangecontainers')
        name: CRD instance name
        namespace: CRD namespace
        crd_data: The CRD data to return
    """
    # Mock get operation
    mock_custom_objects_api.get_namespaced_custom_object.return_value = crd_data

    # Mock list operation (for polling)
    mock_custom_objects_api.list_namespaced_custom_object.return_value = {
        "items": [crd_data]
    }

    return crd_data
