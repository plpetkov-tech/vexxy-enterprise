"""
API endpoint tests
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from uuid import uuid4

from api.main import app
from models.database import Base, get_db
from config.settings import settings

# Test database (use in-memory SQLite for tests)
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for tests"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Create test database tables"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == settings.service_name
    assert data["version"] == settings.version


def test_submit_analysis():
    """Test submitting analysis job"""
    response = client.post(
        f"{settings.api_prefix}/analysis/submit",
        json={
            "image_ref": "nginx:latest",
            "image_digest": "sha256:4c0fdaa8b6341bfdeca5f18f7a2a65e6f4c7e37e32c66c62a7f0c6b9e4e71e5e",
            "config": {"enable_fuzzing": True, "test_timeout": 300},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    assert data["image_ref"] == "nginx:latest"


def test_submit_analysis_invalid_digest():
    """Test submitting with invalid digest format"""
    response = client.post(
        f"{settings.api_prefix}/analysis/submit",
        json={
            "image_ref": "nginx:latest",
            "image_digest": "invalid-digest",  # Invalid format
            "config": {},
        },
    )
    assert response.status_code == 422  # Validation error


def test_get_analysis_status():
    """Test getting analysis status"""
    # First submit a job
    submit_response = client.post(
        f"{settings.api_prefix}/analysis/submit",
        json={
            "image_ref": "nginx:latest",
            "image_digest": "sha256:4c0fdaa8b6341bfdeca5f18f7a2a65e6f4c7e37e32c66c62a7f0c6b9e4e71e5e",
        },
    )
    job_id = submit_response.json()["job_id"]

    # Then check status
    status_response = client.get(f"{settings.api_prefix}/analysis/{job_id}/status")
    assert status_response.status_code == 200
    data = status_response.json()
    assert data["job_id"] == job_id
    assert data["status"] in ["queued", "running", "analyzing", "complete", "failed"]


def test_get_analysis_status_not_found():
    """Test getting status for non-existent job"""
    fake_id = uuid4()
    response = client.get(f"{settings.api_prefix}/analysis/{fake_id}/status")
    assert response.status_code == 404


def test_get_analysis_results_not_complete():
    """Test getting results for incomplete job"""
    # Submit a job
    submit_response = client.post(
        f"{settings.api_prefix}/analysis/submit",
        json={
            "image_ref": "nginx:latest",
            "image_digest": "sha256:4c0fdaa8b6341bfdeca5f18f7a2a65e6f4c7e37e32c66c62a7f0c6b9e4e71e5e",
        },
    )
    job_id = submit_response.json()["job_id"]

    # Try to get results (should fail - not complete)
    results_response = client.get(f"{settings.api_prefix}/analysis/{job_id}/results")
    assert results_response.status_code == 400  # Bad request


def test_cancel_analysis():
    """Test cancelling analysis job"""
    # Submit a job
    submit_response = client.post(
        f"{settings.api_prefix}/analysis/submit",
        json={
            "image_ref": "nginx:latest",
            "image_digest": "sha256:4c0fdaa8b6341bfdeca5f18f7a2a65e6f4c7e37e32c66c62a7f0c6b9e4e71e5e",
        },
    )
    job_id = submit_response.json()["job_id"]

    # Cancel it
    cancel_response = client.delete(f"{settings.api_prefix}/analysis/{job_id}")
    assert cancel_response.status_code == 200
    data = cancel_response.json()
    assert data["status"] == "cancelled"
    assert data["job_id"] == job_id


def test_list_analyses():
    """Test listing analysis jobs"""
    # Submit a few jobs
    for i in range(3):
        client.post(
            f"{settings.api_prefix}/analysis/submit",
            json={
                "image_ref": f"nginx:{i}",
                "image_digest": "sha256:4c0fdaa8b6341bfdeca5f18f7a2a65e6f4c7e37e32c66c62a7f0c6b9e4e71e5e",
            },
        )

    # List them
    list_response = client.get(f"{settings.api_prefix}/analysis")
    assert list_response.status_code == 200
    data = list_response.json()
    assert "total" in data
    assert "jobs" in data
    assert data["total"] >= 3
    assert len(data["jobs"]) >= 3


def test_list_analyses_with_filter():
    """Test listing with status filter"""
    response = client.get(
        f"{settings.api_prefix}/analysis", params={"status_filter": "queued"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "jobs" in data
    # All returned jobs should be queued
    for job in data["jobs"]:
        assert job["status"] == "queued"
