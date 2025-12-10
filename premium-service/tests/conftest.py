"""
Pytest configuration and shared fixtures for VEXxy Premium Service tests.
"""
import os
import sys
from typing import Generator
from unittest.mock import MagicMock, Mock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models.database import Base


@pytest.fixture(scope="session")
def test_db_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    return engine


@pytest.fixture
def db_session(test_db_engine) -> Generator:
    """Create a new database session for a test."""
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_db_engine
    )
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def mock_k8s_config(mocker):
    """Mock Kubernetes configuration loading."""
    # Mock the kubernetes.config module
    mock_config = mocker.patch("kubernetes.config")
    mock_config.load_incluster_config = Mock()
    mock_config.load_kube_config = Mock()
    return mock_config


@pytest.fixture
def mock_settings(mocker):
    """Mock application settings."""
    mock_settings_obj = MagicMock()

    # Database settings
    mock_settings_obj.database_url = "sqlite:///:memory:"
    mock_settings_obj.db_pool_size = 5
    mock_settings_obj.db_max_overflow = 10

    # Redis settings
    mock_settings_obj.redis_url = "redis://localhost:6379/0"

    # K8s settings
    mock_settings_obj.k8s_in_cluster = False
    mock_settings_obj.k8s_sandbox_namespace = "vexxy-sandbox"
    mock_settings_obj.k8s_job_ttl_seconds = 300

    # Analysis settings
    mock_settings_obj.default_timeout = 900
    mock_settings_obj.max_timeout = 1800

    # ZAP settings
    mock_settings_obj.zap_host = "owasp-zap.security.svc.cluster.local"
    mock_settings_obj.zap_port = 8080
    mock_settings_obj.zap_api_key = None

    # Storage settings
    mock_settings_obj.storage_backend = "local"
    mock_settings_obj.local_storage_path = "/tmp/vexxy-test"

    # Billing settings
    mock_settings_obj.stripe_enabled = False

    mocker.patch("config.settings.settings", mock_settings_obj)
    return mock_settings_obj
