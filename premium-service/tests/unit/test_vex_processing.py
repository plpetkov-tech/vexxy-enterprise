"""
Unit tests for VEX processing functions.

Tests the conversion of Kubescape VEX documents to internal reachability format.
"""
import pytest
from unittest.mock import Mock

from workers.tasks_impl_kubescape import (
    convert_vex_statements_to_reachability,
    process_kubescape_vex,
    _calculate_confidence_score,
)
from tests.fixtures.kubescape_fixtures import (
    get_sample_vex_crd,
    get_sample_vex_with_mixed_status,
)


# =============================================================================
# Test: convert_vex_statements_to_reachability
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_basic(sample_processed_vex):
    """Test basic VEX statement conversion to reachability format."""
    # Use the processed VEX format (not CRD format)
    vex_document = sample_processed_vex

    # Call the function
    results = convert_vex_statements_to_reachability(vex_document)

    # Assertions
    assert len(results) == 2
    assert all("cve_id" in r for r in results)
    assert all("status" in r for r in results)
    assert all("confidence_score" in r for r in results)


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_with_not_affected():
    """Test VEX conversion with 'not_affected' status."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-1000"},
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "statement": "Runtime analysis shows this code path is not executed",
                "products": [],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 1
    result = results[0]

    assert result["cve_id"] == "CVE-2024-1000"
    assert result["status"] == "not_affected"
    assert result["justification"] == "vulnerable_code_not_in_execute_path"
    assert result["confidence_score"] >= 0.95  # High confidence for not_affected


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_with_affected():
    """Test VEX conversion with 'affected' status."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-2000"},
                "status": "affected",
                "justification": "",
                "statement": "Vulnerability confirmed in runtime execution",
                "products": [],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 1
    result = results[0]

    assert result["cve_id"] == "CVE-2024-2000"
    assert result["status"] == "affected"
    assert result["confidence_score"] >= 0.90  # High confidence for affected


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_with_products():
    """Test VEX conversion extracts vulnerable packages from products."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-3000"},
                "status": "affected",
                "justification": "",
                "statement": "Vulnerability in nginx package",
                "products": [
                    {
                        "@id": "pkg:oci/nginx@sha256:abc123",
                        "subcomponents": [
                            {"@id": "pkg:pypi/starlette@0.46.2"},
                            {"@id": "pkg:npm/express@4.18.0"},
                        ],
                    }
                ],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 1
    result = results[0]

    assert result["cve_id"] == "CVE-2024-3000"
    assert len(result["vulnerable_files"]) == 2
    assert "starlette@0.46.2" in result["vulnerable_files"]
    assert "express@4.18.0" in result["vulnerable_files"]


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_with_action():
    """Test VEX conversion includes action statements."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-4000"},
                "status": "affected",
                "justification": "",
                "statement": "Update required",
                "action_statement": "Upgrade to version 2.0.0 or later",
                "products": [],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 1
    result = results[0]

    assert result["cve_id"] == "CVE-2024-4000"
    assert "Action: Upgrade to version 2.0.0 or later" in result["reason"]


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_empty_document():
    """Test VEX conversion with empty document."""
    vex_document = None

    results = convert_vex_statements_to_reachability(vex_document)

    assert results == []


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_no_statements():
    """Test VEX conversion with document but no statements."""
    vex_document = {"statements": []}

    results = convert_vex_statements_to_reachability(vex_document)

    assert results == []


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_malformed_statement():
    """Test VEX conversion handles malformed statements gracefully."""
    vex_document = {
        "statements": [
            {
                # Missing vulnerability field
                "status": "affected",
            },
            {
                # Valid statement
                "vulnerability": {"name": "CVE-2024-5000"},
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "statement": "Code not present",
                "products": [],
            },
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    # Should handle first statement gracefully and process second
    assert len(results) >= 1
    # Find the valid one
    valid_result = next((r for r in results if r["cve_id"] == "CVE-2024-5000"), None)
    assert valid_result is not None


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_statements_multiple_statuses():
    """Test VEX conversion with mixed vulnerability statuses."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-6001"},
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "statement": "Not reachable",
                "products": [],
            },
            {
                "vulnerability": {"name": "CVE-2024-6002"},
                "status": "affected",
                "justification": "",
                "statement": "Confirmed vulnerability",
                "products": [],
            },
            {
                "vulnerability": {"name": "CVE-2024-6003"},
                "status": "under_investigation",
                "justification": "",
                "statement": "Analysis in progress",
                "products": [],
            },
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 3

    # Verify each status
    statuses = {r["cve_id"]: r["status"] for r in results}
    assert statuses["CVE-2024-6001"] == "not_affected"
    assert statuses["CVE-2024-6002"] == "affected"
    assert statuses["CVE-2024-6003"] == "under_investigation"

    # Verify confidence scores vary by status
    confidence_scores = {r["cve_id"]: r["confidence_score"] for r in results}
    assert confidence_scores["CVE-2024-6001"] >= 0.95  # not_affected
    assert confidence_scores["CVE-2024-6002"] >= 0.90  # affected
    assert 0.50 <= confidence_scores["CVE-2024-6003"] < 0.90  # under_investigation


# =============================================================================
# Test: _calculate_confidence_score
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_calculate_confidence_score_not_affected():
    """Test confidence score for 'not_affected' status."""
    score = _calculate_confidence_score("not_affected", "")
    assert score == 0.95


@pytest.mark.unit
@pytest.mark.kubescape
def test_calculate_confidence_score_not_affected_with_justification():
    """Test confidence score for 'not_affected' with strong justification."""
    score = _calculate_confidence_score(
        "not_affected", "vulnerable_code_not_in_execute_path"
    )
    assert score >= 0.95
    assert score <= 0.98


@pytest.mark.unit
@pytest.mark.kubescape
def test_calculate_confidence_score_affected():
    """Test confidence score for 'affected' status."""
    score = _calculate_confidence_score("affected", "")
    assert score == 0.90


@pytest.mark.unit
@pytest.mark.kubescape
def test_calculate_confidence_score_under_investigation():
    """Test confidence score for 'under_investigation' status."""
    score = _calculate_confidence_score("under_investigation", "")
    assert score == 0.60


@pytest.mark.unit
@pytest.mark.kubescape
def test_calculate_confidence_score_unknown():
    """Test confidence score for unknown status."""
    score = _calculate_confidence_score("unknown", "")
    assert score == 0.50


@pytest.mark.unit
@pytest.mark.kubescape
def test_calculate_confidence_score_high_confidence_justifications():
    """Test confidence boost for high-confidence justifications."""
    justifications = [
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "component_not_present",
    ]

    for justification in justifications:
        score = _calculate_confidence_score("not_affected", justification)
        # Should be higher than base score of 0.95
        assert score > 0.95
        assert score <= 0.98


# =============================================================================
# Test: process_kubescape_vex
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_process_kubescape_vex_with_document():
    """Test processing a complete Kubescape VEX document."""
    vex_crd = get_sample_vex_crd(deployment_name="test-deployment")
    vex_document = vex_crd["spec"]  # Extract the spec part

    mock_job = Mock()
    mock_job.id = "job-123"

    result = process_kubescape_vex(vex_document, mock_job)

    # Assertions
    assert result is not None
    assert "metadata" in result
    assert "statements" in result
    assert result["metadata"]["author"] == "Kubescape"


@pytest.mark.unit
@pytest.mark.kubescape
def test_process_kubescape_vex_with_none():
    """Test processing with None VEX document."""
    mock_job = Mock()
    mock_job.id = "job-123"

    result = process_kubescape_vex(None, mock_job)

    # Should return empty or default structure
    assert result is not None


@pytest.mark.unit
@pytest.mark.kubescape
def test_process_kubescape_vex_preserves_metadata():
    """Test that VEX processing preserves metadata."""
    vex_document = {
        "metadata": {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://vexxy.io/vex/test",
            "author": "Kubescape",
            "timestamp": "2024-01-01T00:00:00Z",
            "version": "1",
        },
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-7000"},
                "status": "not_affected",
                "justification": "vulnerable_code_not_present",
                "statement": "Code not present",
                "products": [],
            }
        ],
    }

    mock_job = Mock()
    mock_job.id = "job-123"

    result = process_kubescape_vex(vex_document, mock_job)

    # Metadata should be preserved
    assert result["metadata"]["author"] == "Kubescape"
    assert result["metadata"]["@id"] == "https://vexxy.io/vex/test"


# =============================================================================
# Test: Integration with Fixtures
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_sample_vex_fixture(sample_processed_vex):
    """Test converting the sample VEX fixture."""
    results = convert_vex_statements_to_reachability(sample_processed_vex)

    assert len(results) >= 1
    assert all(r["cve_id"].startswith("CVE-") for r in results)
    assert all("confidence_score" in r for r in results)


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_mixed_status_vex_fixture(sample_vex_with_mixed_status):
    """Test converting VEX with mixed statuses."""
    # Extract spec from CRD
    vex_document = sample_vex_with_mixed_status["spec"]

    results = convert_vex_statements_to_reachability(vex_document)

    # Should have 3 results with different statuses
    assert len(results) == 3

    statuses = {r["cve_id"]: r["status"] for r in results}
    assert "not_affected" in statuses.values()
    assert "affected" in statuses.values()
    assert "under_investigation" in statuses.values()


@pytest.mark.unit
@pytest.mark.kubescape
def test_reachability_results_format(sample_reachability_results):
    """Test that reachability results have the expected format."""
    # This tests the fixture itself
    assert isinstance(sample_reachability_results, dict)
    assert all(cve.startswith("CVE-") for cve in sample_reachability_results.keys())

    for cve_id, result in sample_reachability_results.items():
        assert "reachable" in result
        assert "justification" in result
        assert "confidence" in result
        assert "method" in result


# =============================================================================
# Test: Edge Cases
# =============================================================================


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_with_unknown_status():
    """Test VEX conversion with unknown status."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-8000"},
                "status": "some_weird_status",  # Unknown status
                "justification": "",
                "statement": "Unknown",
                "products": [],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 1
    result = results[0]

    # Should handle gracefully with default confidence
    assert result["status"] == "some_weird_status"
    assert 0.0 <= result["confidence_score"] <= 1.0


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_with_missing_vulnerability_name():
    """Test VEX conversion when vulnerability name is missing."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {},  # No name field
                "status": "affected",
                "justification": "",
                "statement": "Test",
                "products": [],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) >= 1
    # Should use "UNKNOWN" as fallback
    assert any(r["cve_id"] == "UNKNOWN" for r in results)


@pytest.mark.unit
@pytest.mark.kubescape
def test_convert_vex_with_complex_products():
    """Test VEX conversion with nested product structures."""
    vex_document = {
        "statements": [
            {
                "vulnerability": {"name": "CVE-2024-9000"},
                "status": "affected",
                "justification": "",
                "statement": "Complex product structure",
                "products": [
                    {
                        "@id": "pkg:oci/nginx@sha256:abc123",
                        "subcomponents": [
                            {"@id": "pkg:pypi/django@4.2.0"},
                            {"@id": "pkg:pypi/requests@2.31.0"},
                            {"@id": "pkg:npm/lodash@4.17.21"},
                        ],
                    },
                    {
                        "@id": "pkg:deb/ubuntu/openssl@1.1.1",
                        "subcomponents": [],  # No subcomponents
                    },
                ],
            }
        ]
    }

    results = convert_vex_statements_to_reachability(vex_document)

    assert len(results) == 1
    result = results[0]

    # Should extract all vulnerable packages
    assert len(result["vulnerable_files"]) >= 3
    assert any("django@4.2.0" in f for f in result["vulnerable_files"])
    assert any("requests@2.31.0" in f for f in result["vulnerable_files"])
    assert any("lodash@4.17.21" in f for f in result["vulnerable_files"])
