# VEXxy Premium Service - Test Suite

This directory contains the test suite for the VEXxy Premium Service, covering unit tests, integration tests, and end-to-end tests.

## Test Structure

```
tests/
├── unit/                           # Fast unit tests with mocked dependencies
│   ├── test_kubescape_service.py   # KubescapeService tests (25+ tests)
│   ├── test_vex_processing.py      # VEX processing logic tests (30+ tests)
│   └── test_zap_service.py         # ZAPService tests (23+ tests)
├── fixtures/                       # Reusable test fixtures and mocks
│   ├── k8s_mocks.py               # Kubernetes client mocks
│   ├── kubescape_fixtures.py       # Sample VEX and SBOM CRDs
│   └── zap_fixtures.py             # Sample ZAP scan results
├── integration/                    # Integration tests (TODO: Phase 2)
├── conftest.py                     # Shared pytest fixtures
├── pytest.ini                      # Pytest configuration
└── README.md                       # This file
```

## Quick Start

### Install Dependencies

```bash
cd /home/plamen/all-vexxy/vexxy-enterprise/premium-service

# Install test dependencies
pip install -r requirements-dev.txt
```

### Run All Unit Tests

```bash
# Run all unit tests (fast)
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=services --cov=workers --cov-report=html

# Run in parallel (faster)
pytest tests/unit/ -v -n auto
```

### Run Specific Test Categories

```bash
# Run only Kubescape tests
pytest tests/unit/ -v -m kubescape

# Run only ZAP tests
pytest tests/unit/ -v -m zap

# Run only pentesting tests
pytest tests/unit/ -v -m pentest

# Run all tests except slow ones
pytest tests/ -v -m "not slow"
```

### Run Specific Test Files

```bash
# Run KubescapeService tests only
pytest tests/unit/test_kubescape_service.py -v

# Run VEX processing tests only
pytest tests/unit/test_vex_processing.py -v

# Run ZAPService tests only
pytest tests/unit/test_zap_service.py -v
```

### Run Specific Tests

```bash
# Run a specific test by name
pytest tests/unit/test_kubescape_service.py::test_extract_runtime_vex_success -v

# Run tests matching a pattern
pytest tests/unit/ -v -k "vex"
```

## Test Markers

Tests are organized with pytest markers for easy filtering:

- `@pytest.mark.unit` - Unit tests (fast, mocked)
- `@pytest.mark.integration` - Integration tests (slow, requires K8s)
- `@pytest.mark.e2e` - End-to-end tests (very slow, full stack)
- `@pytest.mark.slow` - Tests that take > 5 seconds
- `@pytest.mark.kubescape` - Kubescape integration tests
- `@pytest.mark.zap` - ZAP integration tests
- `@pytest.mark.pentest` - Pentesting feature tests

## Coverage Reports

Generate and view coverage reports:

```bash
# Generate HTML coverage report
pytest tests/unit/ --cov=services --cov=workers --cov-report=html

# Open in browser
xdg-open htmlcov/index.html

# Terminal coverage report
pytest tests/unit/ --cov=services --cov=workers --cov-report=term-missing
```

## Writing New Tests

### Test Naming Convention

- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Using Fixtures

```python
import pytest
from tests.fixtures.k8s_mocks import mock_k8s_clients
from tests.fixtures.kubescape_fixtures import sample_vex_crd

@pytest.mark.unit
@pytest.mark.kubescape
def test_my_function(mock_k8s_clients, sample_vex_crd):
    # Test implementation
    pass
```

### Mocking Kubernetes APIs

```python
def test_with_k8s_mocks(mock_k8s_clients):
    # mock_k8s_clients provides:
    # - apps_v1: AppsV1Api mock
    # - core_v1: CoreV1Api mock
    # - custom_objects: CustomObjectsApi mock
    # - batch_v1: BatchV1Api mock
    # - dynamic: DynamicClient mock

    mock_k8s_clients["apps_v1"].create_namespaced_deployment.return_value = ...
```

### Using Sample Data

```python
from tests.fixtures.kubescape_fixtures import get_sample_vex_crd

def test_vex_extraction():
    vex_crd = get_sample_vex_crd(
        deployment_name="test-deployment",
        namespace="test-ns",
        num_vulnerabilities=5
    )
    # Test with sample CRD
```

## Current Test Coverage

### Phase 1 (Completed) ✅

**Unit Tests:**
- ✅ KubescapeService (25+ tests)
  - Initialization and configuration
  - VEX extraction from CRDs
  - Filtered SBOM extraction
  - Workload deployment with/without sidecars
  - Pentesting sidecar creation
  - Cleanup operations
  - Namespace management

- ✅ VEX Processing (30+ tests)
  - VEX statement conversion to reachability format
  - Confidence score calculation
  - Product/subcomponent extraction
  - Edge cases and error handling

- ✅ ZAPService (23+ tests)
  - Service initialization
  - Availability checks
  - Active scanning (quick/medium/thorough modes)
  - Passive security checks
  - Kubernetes service scanning
  - Alert parsing and transformation

**Total:** 78+ unit tests

### Phase 2 (TODO) - Integration Tests

Integration tests will test against a real Kind cluster:

- Kubescape deployment → CRD creation → extraction flow
- Pentesting sidecar injection and execution
- ZAP scanning against deployed workloads
- Worker task end-to-end execution
- Concurrent deployment handling

### Phase 3 (TODO) - CI/CD Pipeline

- GitHub Actions workflows for automated testing
- Coverage tracking and reporting
- Integration tests on merge to main
- E2E smoke tests for releases

## Troubleshooting

### Import Errors

If you see import errors, make sure you're running pytest from the premium-service directory:

```bash
cd /home/plamen/all-vexxy/vexxy-enterprise/premium-service
pytest tests/unit/ -v
```

### Fixture Not Found

Make sure `conftest.py` is in the correct location and imports are correct:

```python
from tests.fixtures.k8s_mocks import mock_k8s_clients
```

### Mock Not Working

Verify you're patching the correct import path:

```python
# Patch where it's used, not where it's defined
@patch("services.kubescape.client.AppsV1Api")
def test_something(mock_api):
    pass
```

## Next Steps

1. **Run the tests:** `pytest tests/unit/ -v`
2. **Check coverage:** `pytest tests/unit/ --cov=services --cov=workers`
3. **Phase 2:** Add integration tests with Kind cluster
4. **Phase 3:** Setup CI/CD pipeline with GitHub Actions

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [pytest-mock Documentation](https://pytest-mock.readthedocs.io/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [VEXxy Premium Service Plan](/home/plamen/.claude/plans/functional-discovering-hamster.md)
