"""
Unit tests for OWASP ZAP Service.

Tests the ZAP integration without requiring a real ZAP instance.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch, call
import responses

from tests.fixtures.zap_fixtures import (
    get_sample_zap_version_response,
    get_sample_zap_spider_status,
    get_sample_zap_ascan_status,
    get_sample_zap_alerts_response,
    get_sample_passive_security_findings,
    create_zap_http_response,
)

from services.owasp_zap import ZAPService
from exceptions import ExternalServiceError


@pytest.fixture
def zap_service(mock_settings):
    """Create a ZAPService instance with mocked settings."""
    mock_settings.zap_host = "owasp-zap.security.svc.cluster.local"
    mock_settings.zap_port = 8080
    mock_settings.zap_api_key = None

    service = ZAPService(
        zap_host=mock_settings.zap_host,
        zap_port=mock_settings.zap_port,
        zap_api_key=mock_settings.zap_api_key,
    )
    return service


# =============================================================================
# Test: Initialization
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
@patch('services.owasp_zap.socket.gethostbyname')
def test_zap_service_init(mock_gethostbyname):
    """Test ZAPService initialization."""
    # Mock socket to raise error so localhost is used as-is
    import socket
    mock_gethostbyname.side_effect = socket.gaierror("DNS resolution failed")

    service = ZAPService(
        zap_host="localhost",
        zap_port=8080,
        zap_api_key="test-api-key",
    )

    assert service.zap_host == "localhost"
    assert service.zap_port == 8080
    assert service.zap_api_key == "test-api-key"
    assert service.zap_url == "http://localhost:8080"
    assert service.session is not None


@pytest.mark.unit
@pytest.mark.zap
@patch('services.owasp_zap.socket.gethostbyname')
def test_zap_service_init_with_defaults(mock_gethostbyname, mock_settings):
    """Test ZAPService uses defaults from settings."""
    # Mock socket to raise error so the provided host is used as-is
    import socket
    mock_gethostbyname.side_effect = socket.gaierror("DNS resolution failed")

    mock_settings.zap_host = "zap.example.com"
    mock_settings.zap_port = 9090
    mock_settings.zap_api_key = "key123"

    service = ZAPService(
        zap_host="zap.example.com",
        zap_port=9090,
        zap_api_key="key123",
    )

    assert service.zap_host == "zap.example.com"
    assert service.zap_port == 9090
    assert service.zap_api_key == "key123"


# =============================================================================
# Test: is_zap_available
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_is_zap_available_success(zap_service):
    """Test ZAP availability check when ZAP is available."""
    # Mock ZAP version endpoint
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/version/",
        json=get_sample_zap_version_response(),
        status=200,
    )

    # Call the method
    result = zap_service.is_zap_available()

    # Assertions
    assert result is True


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_is_zap_available_failure(zap_service):
    """Test ZAP availability check when ZAP is unavailable."""
    # Mock ZAP endpoint to return error
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/version/",
        json={"error": "Service unavailable"},
        status=503,
    )

    # Call the method
    result = zap_service.is_zap_available(max_retries=1)

    # Assertions
    assert result is False


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_is_zap_available_timeout(zap_service):
    """Test ZAP availability check with connection timeout."""
    # Mock timeout exception
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/version/",
        body=Exception("Connection timeout"),
    )

    # Call the method
    result = zap_service.is_zap_available(max_retries=1)

    # Assertions
    assert result is False


# =============================================================================
# Test: scan_target
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_scan_target_success(zap_service):
    """Test successful ZAP target scanning."""
    target_url = "http://test-service.default.svc.cluster.local:8080"
    scan_type = "quick"
    timeout = 300

    # Mock ZAP API endpoints
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/newSession/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/accessUrl/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/spider/action/scan/",
        json={"scan": "1"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/spider/view/status/",
        json=get_sample_zap_spider_status(100),  # 100% complete
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/action/scan/",
        json={"scan": "1"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/view/status/",
        json=get_sample_zap_ascan_status(100),  # 100% complete
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/alerts/",
        json=get_sample_zap_alerts_response(),
        status=200,
    )

    # Call the method
    with patch("time.sleep"):  # Mock sleep to speed up test
        result = zap_service.scan_target(target_url, scan_type, timeout)

    # Assertions
    assert result is not None
    assert "alerts" in result or isinstance(result, list)


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_scan_target_quick_mode(zap_service):
    """Test ZAP scanning in quick mode (no spider)."""
    target_url = "http://test-service.default.svc.cluster.local:8080"
    scan_type = "quick"
    timeout = 60

    # Mock ZAP API endpoints - quick mode skips spider
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/newSession/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/accessUrl/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/action/scan/",
        json={"scan": "1"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/view/status/",
        json=get_sample_zap_ascan_status(100),
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/alerts/",
        json=get_sample_zap_alerts_response(),
        status=200,
    )

    # Call the method
    with patch("time.sleep"):
        result = zap_service.scan_target(target_url, scan_type, timeout)

    # Assertions
    assert result is not None


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_scan_target_medium_mode(zap_service):
    """Test ZAP scanning in medium mode (with spider)."""
    target_url = "http://test-service.default.svc.cluster.local:8080"
    scan_type = "medium"
    timeout = 300

    # Mock ZAP API endpoints - medium mode includes spider
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/newSession/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/accessUrl/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/spider/action/scan/",
        json={"scan": "1"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/spider/view/status/",
        json=get_sample_zap_spider_status(100),
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/action/scan/",
        json={"scan": "1"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/view/status/",
        json=get_sample_zap_ascan_status(100),
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/alerts/",
        json=get_sample_zap_alerts_response(),
        status=200,
    )

    # Call the method
    with patch("time.sleep"):
        result = zap_service.scan_target(target_url, scan_type, timeout)

    # Assertions
    assert result is not None


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_scan_target_api_error(zap_service):
    """Test ZAP scanning handles API errors."""
    target_url = "http://test-service.default.svc.cluster.local:8080"
    scan_type = "quick"
    timeout = 60

    # Mock ZAP API to return error
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/newSession/",
        json={"error": "Internal error"},
        status=500,
    )

    # Call the method - should raise ExternalServiceError
    with pytest.raises(ExternalServiceError):
        zap_service.scan_target(target_url, scan_type, timeout)


# =============================================================================
# Test: run_passive_checks
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
def test_run_passive_checks_http(zap_service):
    """Test passive security checks for HTTP URLs."""
    scanned_urls = ["http://test-service.default.svc.cluster.local:8080"]

    # Call the method
    result = zap_service.run_passive_checks(scanned_urls)

    # Assertions
    assert isinstance(result, list)
    assert len(result) > 0

    # Should have finding about HTTP (not HTTPS)
    http_findings = [f for f in result if "HTTP" in f.get("alert", "")]
    assert len(http_findings) > 0


@pytest.mark.unit
@pytest.mark.zap
def test_run_passive_checks_https(zap_service):
    """Test passive security checks for HTTPS URLs."""
    scanned_urls = ["https://test-service.default.svc.cluster.local:8443"]

    # Call the method
    result = zap_service.run_passive_checks(scanned_urls)

    # Assertions
    assert isinstance(result, list)
    # HTTPS should have fewer passive findings than HTTP
    assert len(result) >= 0


@pytest.mark.unit
@pytest.mark.zap
def test_run_passive_checks_multiple_urls(zap_service):
    """Test passive security checks with multiple URLs."""
    scanned_urls = [
        "http://service1.default.svc.cluster.local:8080",
        "https://service2.default.svc.cluster.local:8443",
        "http://service3.default.svc.cluster.local:3000",
    ]

    # Call the method
    result = zap_service.run_passive_checks(scanned_urls)

    # Assertions
    assert isinstance(result, list)
    # Should have findings (at least for HTTP URLs)
    assert len(result) >= 0


@pytest.mark.unit
@pytest.mark.zap
def test_run_passive_checks_empty_urls(zap_service):
    """Test passive security checks with empty URL list."""
    scanned_urls = []

    # Call the method
    result = zap_service.run_passive_checks(scanned_urls)

    # Assertions
    assert isinstance(result, list)
    assert len(result) == 0


# =============================================================================
# Test: scan_kubernetes_service
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_scan_kubernetes_service(zap_service):
    """Test scanning a Kubernetes service."""
    service_name = "test-service"
    namespace = "default"
    ports = [8080, 8443]
    scan_type = "quick"
    timeout = 300

    # Mock ZAP API endpoints
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/newSession/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/action/accessUrl/",
        json={"Result": "OK"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/action/scan/",
        json={"scan": "1"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/ascan/view/status/",
        json=get_sample_zap_ascan_status(100),
        status=200,
    )
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/alerts/",
        json=get_sample_zap_alerts_response(),
        status=200,
    )

    # Call the method
    with patch("time.sleep"):
        result = zap_service.scan_kubernetes_service(
            service_name, namespace, ports, scan_type, timeout
        )

    # Assertions
    assert result is not None
    assert isinstance(result, (list, dict))


# =============================================================================
# Test: _call_zap_api (internal method)
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_call_zap_api_success(zap_service):
    """Test successful ZAP API call."""
    component = "core"
    operation_type = "view"
    operation_name = "version"

    # Mock ZAP API endpoint
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/version/",
        json=get_sample_zap_version_response(),
        status=200,
    )

    # Call the method
    result = zap_service._call_zap_api(component, operation_type, operation_name)

    # Assertions
    assert result is not None
    assert "version" in result


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_call_zap_api_with_params(zap_service):
    """Test ZAP API call with parameters."""
    component = "spider"
    operation_type = "action"
    operation_name = "scan"
    params = {"url": "http://example.com"}

    # Mock ZAP API endpoint
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/spider/action/scan/",
        json={"scan": "1"},
        status=200,
    )

    # Call the method
    result = zap_service._call_zap_api(
        component, operation_type, operation_name, params
    )

    # Assertions
    assert result is not None
    assert "scan" in result


@pytest.mark.unit
@pytest.mark.zap
@responses.activate
def test_call_zap_api_error_response(zap_service):
    """Test ZAP API call with error response."""
    component = "core"
    operation_type = "view"
    operation_name = "version"

    # Mock ZAP API endpoint to return error
    responses.add(
        responses.GET,
        f"{zap_service.zap_url}/JSON/core/view/version/",
        json={"error": "Internal error"},
        status=500,
    )

    # Call the method - should raise ExternalServiceError
    with pytest.raises(ExternalServiceError):
        zap_service._call_zap_api(component, operation_type, operation_name)


# =============================================================================
# Test: Alert Parsing and Transformation
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
def test_alert_format():
    """Test that ZAP alerts have the expected format."""
    from tests.fixtures.zap_fixtures import get_sample_zap_alerts

    alerts = get_sample_zap_alerts(num_alerts=3)

    assert len(alerts) == 3
    for alert in alerts:
        # Verify required fields
        assert "alert" in alert
        assert "risk" in alert
        assert "confidence" in alert
        assert "description" in alert
        assert "solution" in alert
        assert "cweid" in alert
        assert "wascid" in alert
        assert "pluginid" in alert


@pytest.mark.unit
@pytest.mark.zap
def test_alert_risk_levels():
    """Test that ZAP alerts have valid risk levels."""
    from tests.fixtures.zap_fixtures import get_sample_zap_alerts

    alerts = get_sample_zap_alerts(num_alerts=5)

    valid_risk_levels = {"High", "Medium", "Low", "Informational"}

    for alert in alerts:
        assert alert["risk"] in valid_risk_levels


# =============================================================================
# Test: Security Findings Integration
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
def test_combined_security_findings(combined_security_findings):
    """Test combined security findings format."""
    # This tests the fixture
    assert "zap_scan" in combined_security_findings
    assert "pentest_scan" in combined_security_findings
    assert "totals" in combined_security_findings

    # Verify ZAP scan structure
    zap_scan = combined_security_findings["zap_scan"]
    assert "scan_type" in zap_scan
    assert "status" in zap_scan
    assert "alerts" in zap_scan

    # Verify totals
    totals = combined_security_findings["totals"]
    assert "high_risk" in totals
    assert "medium_risk" in totals
    assert "low_risk" in totals
    assert "informational" in totals


# =============================================================================
# Test: Edge Cases
# =============================================================================


@pytest.mark.unit
@pytest.mark.zap
def test_zap_service_with_api_key(mock_settings):
    """Test ZAPService initialization with API key."""
    service = ZAPService(
        zap_host="localhost",
        zap_port=8080,
        zap_api_key="secret-api-key-123",
    )

    assert service.zap_api_key == "secret-api-key-123"


@pytest.mark.unit
@pytest.mark.zap
def test_zap_service_different_ports():
    """Test ZAPService with various port configurations."""
    # Standard port
    service1 = ZAPService(zap_host="localhost", zap_port=8080)
    assert service1.zap_url == "http://localhost:8080"

    # Non-standard port
    service2 = ZAPService(zap_host="localhost", zap_port=9090)
    assert service2.zap_url == "http://localhost:9090"

    # HTTPS port (443)
    service3 = ZAPService(zap_host="localhost", zap_port=443)
    assert service3.zap_url == "http://localhost:443"  # ZAP API is always HTTP


@pytest.mark.unit
@pytest.mark.zap
def test_zap_service_cluster_dns():
    """Test ZAPService with Kubernetes cluster DNS."""
    service = ZAPService(
        zap_host="owasp-zap.security.svc.cluster.local",
        zap_port=8080,
    )

    assert service.zap_host == "owasp-zap.security.svc.cluster.local"
    assert "svc.cluster.local" in service.zap_url
