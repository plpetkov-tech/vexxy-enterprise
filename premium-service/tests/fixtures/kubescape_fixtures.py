"""
Fixtures for Kubescape integration testing.

Provides sample CRD data (VEX, SBOM) for unit tests.
"""
from datetime import datetime, timezone
from typing import Any, Dict

import pytest


# =============================================================================
# Sample Kubescape VEX CRD Data
# =============================================================================


def get_sample_vex_crd(
    deployment_name: str = "test-deployment",
    namespace: str = "default",
    image: str = "nginx:1.21",
    num_vulnerabilities: int = 3,
) -> Dict[str, Any]:
    """
    Get a sample OpenVulnerabilityExchangeContainer CRD.

    This mimics the structure returned by Kubescape's runtime analysis.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    vulnerabilities = []
    for i in range(num_vulnerabilities):
        cve_id = f"CVE-2024-{1000 + i}"
        vulnerabilities.append({
            "id": cve_id,
            "modified": timestamp,
            "published": timestamp,
            "affects": [{
                "version": {
                    "version": "1.21",
                    "versionType": "semver"
                },
                "vendor": {"product": {"name": "nginx"}},
            }],
            "analysis": {
                "state": "not_affected" if i == 0 else "affected",
                "justification": "vulnerable_code_not_in_execute_path" if i == 0 else None,
                "detail": "Runtime analysis shows this vulnerability is not reachable" if i == 0 else None,
            },
            "ratings": [{
                "severity": "high" if i < 1 else "medium",
                "score": 8.5 if i < 1 else 5.5,
                "vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:{'H' if i < 1 else 'N'}",
            }],
        })

    return {
        "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
        "kind": "OpenVulnerabilityExchangeContainer",
        "metadata": {
            "name": f"replicaset-{deployment_name}-abc123-main-xyz789",
            "namespace": namespace,
            "labels": {
                "kubescape.io/workload-kind": "Deployment",
                "kubescape.io/workload-name": deployment_name,
                "kubescape.io/image-id": image.replace(":", "-"),
            },
            "creationTimestamp": timestamp,
        },
        "spec": {
            "metadata": {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": f"https://vexxy.io/vex/{deployment_name}",
                "author": "Kubescape",
                "timestamp": timestamp,
                "version": "1",
            },
            "statements": vulnerabilities,
        },
    }


def get_sample_vex_with_mixed_status() -> Dict[str, Any]:
    """Get a VEX CRD with mixed vulnerability statuses (affected, not_affected, under_investigation)."""
    timestamp = datetime.now(timezone.utc).isoformat()

    return {
        "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
        "kind": "OpenVulnerabilityExchangeContainer",
        "metadata": {
            "name": "replicaset-nginx-abc123-main-xyz789",
            "namespace": "default",
        },
        "spec": {
            "metadata": {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": "https://vexxy.io/vex/nginx",
                "author": "Kubescape",
                "timestamp": timestamp,
                "version": "1",
            },
            "statements": [
                {
                    "id": "CVE-2024-1000",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "vulnerable_code_not_in_execute_path",
                        "detail": "Code path not reachable at runtime",
                    },
                    "ratings": [{"severity": "high", "score": 8.5}],
                },
                {
                    "id": "CVE-2024-1001",
                    "analysis": {
                        "state": "affected",
                        "detail": "Vulnerability confirmed in runtime execution",
                    },
                    "ratings": [{"severity": "critical", "score": 9.8}],
                },
                {
                    "id": "CVE-2024-1002",
                    "analysis": {
                        "state": "under_investigation",
                        "detail": "Analysis in progress",
                    },
                    "ratings": [{"severity": "medium", "score": 5.5}],
                },
            ],
        },
    }


# =============================================================================
# Sample Kubescape Filtered SBOM CRD Data
# =============================================================================


def get_sample_filtered_sbom_crd(
    deployment_name: str = "test-deployment",
    namespace: str = "default",
    num_packages: int = 5,
) -> Dict[str, Any]:
    """
    Get a sample SBOMSyftFiltered CRD.

    This contains only runtime-reachable components identified by Kubescape.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    packages = []
    for i in range(num_packages):
        packages.append({
            "SPDXID": f"SPDXRef-Package-nginx-{i}",
            "name": f"nginx-module-{i}",
            "versionInfo": f"1.21.{i}",
            "supplier": "Organization: nginx",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:generic/nginx-module-{i}@1.21.{i}",
            }],
        })

    return {
        "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
        "kind": "SBOMSyftFiltered",
        "metadata": {
            "name": f"replicaset-{deployment_name}-abc123-main-xyz789",
            "namespace": namespace,
            "labels": {
                "kubescape.io/workload-kind": "Deployment",
                "kubescape.io/workload-name": deployment_name,
            },
            "creationTimestamp": timestamp,
        },
        "spec": {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"sbom-{deployment_name}",
            "documentNamespace": f"https://vexxy.io/sbom/{deployment_name}",
            "creationInfo": {
                "created": timestamp,
                "creators": ["Tool: kubescape"],
                "licenseListVersion": "3.20",
            },
            "packages": packages,
        },
    }


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def sample_vex_crd():
    """Fixture providing a sample VEX CRD."""
    return get_sample_vex_crd()


@pytest.fixture
def sample_vex_with_mixed_status():
    """Fixture providing a VEX CRD with mixed vulnerability statuses."""
    return get_sample_vex_with_mixed_status()


@pytest.fixture
def sample_filtered_sbom_crd():
    """Fixture providing a sample filtered SBOM CRD."""
    return get_sample_filtered_sbom_crd()


@pytest.fixture
def kubescape_crd_list_response(sample_vex_crd, sample_filtered_sbom_crd):
    """
    Fixture simulating a list_namespaced_custom_object response.

    Returns a dict with 'items' key containing CRDs, as returned by K8s API.
    """
    return {
        "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
        "kind": "OpenVulnerabilityExchangeContainerList",
        "metadata": {
            "resourceVersion": "1",
        },
        "items": [sample_vex_crd],
    }


@pytest.fixture
def empty_crd_list_response():
    """Fixture simulating an empty CRD list response (no results yet)."""
    return {
        "apiVersion": "spdx.softwarecomposition.kubescape.io/v1beta1",
        "kind": "OpenVulnerabilityExchangeContainerList",
        "metadata": {
            "resourceVersion": "1",
        },
        "items": [],
    }


# =============================================================================
# Sample Processed VEX Data
# =============================================================================


@pytest.fixture
def sample_processed_vex():
    """
    Fixture providing processed VEX data (after CRD parsing).

    This represents the format stored in the database.
    """
    return {
        "statements": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1000",
                    "severity": "high",
                    "score": 8.5,
                },
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "detail": "Runtime analysis shows this vulnerability is not reachable",
            },
            {
                "vulnerability": {
                    "id": "CVE-2024-1001",
                    "severity": "critical",
                    "score": 9.8,
                },
                "status": "affected",
                "detail": "Vulnerability confirmed in runtime execution",
            },
        ],
        "metadata": {
            "author": "Kubescape",
            "version": "1",
        },
    }


@pytest.fixture
def sample_reachability_results():
    """
    Fixture providing reachability analysis results.

    This is the format used internally by VEXxy premium service.
    """
    return {
        "CVE-2024-1000": {
            "reachable": False,
            "justification": "vulnerable_code_not_in_execute_path",
            "confidence": "high",
            "method": "runtime_analysis",
        },
        "CVE-2024-1001": {
            "reachable": True,
            "justification": None,
            "confidence": "high",
            "method": "runtime_analysis",
        },
        "CVE-2024-1002": {
            "reachable": None,  # Unknown/under investigation
            "justification": None,
            "confidence": "low",
            "method": "runtime_analysis",
        },
    }


@pytest.fixture
def sample_sbom_components():
    """
    Fixture providing extracted SBOM component data.

    This is the format stored after SBOM processing.
    """
    return [
        {
            "name": "nginx-module-0",
            "version": "1.21.0",
            "purl": "pkg:generic/nginx-module-0@1.21.0",
            "type": "library",
            "reachable": True,
        },
        {
            "name": "nginx-module-1",
            "version": "1.21.1",
            "purl": "pkg:generic/nginx-module-1@1.21.1",
            "type": "library",
            "reachable": True,
        },
    ]
