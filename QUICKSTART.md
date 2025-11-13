# Premium VEX Service - Quick Start Guide

Get the Ultimate tier feature running in **2 weeks** with this accelerated development path.

---

## 🎯 Goal: Week 1

**Working sandbox that can execute containers and return basic execution logs**

### Day 1: Project Setup

```bash
# 1. Create service structure
mkdir -p premium-service/{api,workers,models,services,tests}
cd premium-service

# 2. Initialize Python project
python -m venv venv
source venv/bin/activate

# 3. Install dependencies
cat > requirements.txt << EOF
fastapi==0.104.1
uvicorn[standard]==0.24.0
celery[redis]==5.3.4
redis==5.0.1
psycopg2-binary==2.9.9
sqlalchemy==2.0.23
alembic==1.13.0
pydantic==2.5.0
pydantic-settings==2.1.0
kubernetes==28.1.0
httpx==0.25.2
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
prometheus-client==0.19.0
EOF

pip install -r requirements.txt

# 4. Install dev dependencies
cat > requirements-dev.txt << EOF
pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.11.0
ruff==0.1.6
mypy==1.7.1
EOF

pip install -r requirements-dev.txt
```

### Day 2: FastAPI Service Skeleton

Create `api/main.py`:

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from uuid import UUID, uuid4
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="VEXxy Premium Analysis Service",
    description="Automated reachability-based VEX generation",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response models
class AnalysisConfig(BaseModel):
    """Configuration for analysis job"""
    test_script: Optional[str] = None
    test_timeout: int = Field(default=300, ge=60, le=900)
    enable_fuzzing: bool = True
    enable_profiling: bool = True
    ports: list[int] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)

class AnalysisRequest(BaseModel):
    """Request to analyze container image"""
    image_ref: str = Field(..., description="Container image reference")
    image_digest: str = Field(..., description="Image digest (sha256:...)")
    sbom_id: Optional[UUID] = None
    config: AnalysisConfig = Field(default_factory=AnalysisConfig)

class AnalysisJobResponse(BaseModel):
    """Response for analysis job submission"""
    job_id: UUID
    status: str
    image_ref: str
    estimated_duration_minutes: int
    created_at: datetime

class AnalysisStatusResponse(BaseModel):
    """Status of analysis job"""
    job_id: UUID
    status: str  # queued, running, analyzing, complete, failed, cancelled
    progress_percent: int
    current_phase: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "premium-vex-service",
        "version": "0.1.0"
    }

# Analysis endpoints
@app.post("/api/v1/analysis/submit", response_model=AnalysisJobResponse)
async def submit_analysis(request: AnalysisRequest):
    """
    Submit container image for premium reachability analysis

    This endpoint:
    1. Validates the request
    2. Creates an analysis job
    3. Queues it for processing
    4. Returns job ID for tracking
    """
    logger.info(f"Received analysis request for {request.image_ref}")

    # TODO: Authentication & authorization
    # TODO: Quota check

    # Create job ID
    job_id = uuid4()

    # TODO: Queue the job in Celery
    logger.info(f"Created analysis job {job_id}")

    return AnalysisJobResponse(
        job_id=job_id,
        status="queued",
        image_ref=request.image_ref,
        estimated_duration_minutes=10,
        created_at=datetime.utcnow()
    )

@app.get("/api/v1/analysis/{job_id}/status", response_model=AnalysisStatusResponse)
async def get_analysis_status(job_id: UUID):
    """Get status of analysis job"""
    logger.info(f"Status check for job {job_id}")

    # TODO: Query database for job status

    return AnalysisStatusResponse(
        job_id=job_id,
        status="queued",
        progress_percent=0,
        current_phase="pending"
    )

@app.get("/api/v1/analysis/{job_id}/results")
async def get_analysis_results(job_id: UUID):
    """Get results of completed analysis"""
    logger.info(f"Results request for job {job_id}")

    # TODO: Fetch results from database

    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Results retrieval not yet implemented"
    )

@app.delete("/api/v1/analysis/{job_id}")
async def cancel_analysis(job_id: UUID):
    """Cancel running analysis job"""
    logger.info(f"Cancel request for job {job_id}")

    # TODO: Cancel Celery task and cleanup

    return {"status": "cancelled", "job_id": job_id}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
```

**Test it:**
```bash
# Run the service
python api/main.py

# In another terminal
curl http://localhost:8001/health
curl -X POST http://localhost:8001/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx:latest",
    "image_digest": "sha256:abc123"
  }'
```

### Day 3: Database Models

Create `models/database.py`:

```python
from sqlalchemy import create_engine, Column, String, Integer, DateTime, JSON, Enum, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
import enum

Base = declarative_base()

class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"

class PremiumAnalysisJob(Base):
    __tablename__ = "premium_analysis_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)  # TODO: Add FK

    # Image info
    image_ref = Column(String(500), nullable=False)
    image_digest = Column(String(100), nullable=False, index=True)
    sbom_id = Column(UUID(as_uuid=True), nullable=True)

    # Job status
    status = Column(Enum(JobStatus), nullable=False, default=JobStatus.QUEUED, index=True)
    priority = Column(Integer, default=0)

    # Configuration
    config = Column(JSON, nullable=False, default=dict)

    # Progress tracking
    progress_percent = Column(Integer, default=0)
    current_phase = Column(String(100))

    # Results
    execution_profile = Column(JSON)
    reachability_results = Column(JSON)
    generated_vex_id = Column(UUID(as_uuid=True))

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)

    # Billing
    billed_at = Column(DateTime)
    cost_credits = Column(Integer, default=1)

class AnalysisEvidence(Base):
    __tablename__ = "analysis_evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_job_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    evidence_type = Column(String(50), nullable=False)  # execution_trace, syscall_log, etc.
    evidence_data = Column(JSON)

    # For large files
    storage_path = Column(String(500))
    file_size = Column(Integer)

    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
def init_db(database_url: str):
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return engine
```

Create database migration:

```bash
# Initialize Alembic
alembic init alembic

# Edit alembic/env.py to point to your database
# Then create migration
alembic revision --autogenerate -m "Initial schema"
alembic upgrade head
```

### Day 4: Celery Worker Setup

Create `workers/tasks.py`:

```python
from celery import Celery, Task
from celery.signals import task_prerun, task_postrun, task_failure
import logging
from datetime import datetime
from uuid import UUID

logger = logging.getLogger(__name__)

# Celery app
celery_app = Celery(
    "premium-vex-worker",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,  # 30 minutes max
    task_soft_time_limit=1500,  # 25 minutes soft limit
)

class AnalysisTask(Task):
    """Base task with common functionality"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(f"Task {task_id} failed: {exc}")
        # TODO: Update database with error

    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success"""
        logger.info(f"Task {task_id} succeeded")
        # TODO: Update database

@celery_app.task(base=AnalysisTask, bind=True)
def run_premium_analysis(self, job_id: str, image_ref: str, image_digest: str, config: dict):
    """
    Main task for premium analysis

    Phases:
    1. Setup sandbox
    2. Run container with profiling
    3. Execute tests/fuzzing
    4. Collect execution profile
    5. Analyze reachability
    6. Generate VEX
    7. Cleanup
    """
    logger.info(f"Starting premium analysis for job {job_id}")

    try:
        # Update status to running
        update_job_status(job_id, "running", 0, "Initializing")

        # Phase 1: Setup sandbox
        logger.info("Phase 1: Setting up sandbox")
        update_job_status(job_id, "running", 10, "Setting up sandbox")
        sandbox_id = setup_sandbox(image_ref, image_digest, config)

        # Phase 2: Start container with profiling
        logger.info("Phase 2: Starting container with profiling")
        update_job_status(job_id, "running", 30, "Starting container")
        start_container_with_profiling(sandbox_id, config)

        # Phase 3: Execute tests
        logger.info("Phase 3: Running tests and fuzzing")
        update_job_status(job_id, "running", 50, "Executing tests")
        execute_tests(sandbox_id, config)

        # Phase 4: Collect execution profile
        logger.info("Phase 4: Collecting execution profile")
        update_job_status(job_id, "analyzing", 70, "Analyzing execution")
        execution_profile = collect_execution_profile(sandbox_id)

        # Phase 5: Analyze reachability
        logger.info("Phase 5: Analyzing reachability")
        update_job_status(job_id, "analyzing", 85, "Determining reachability")
        reachability_results = analyze_reachability(execution_profile, image_digest)

        # Phase 6: Generate VEX
        logger.info("Phase 6: Generating VEX document")
        update_job_status(job_id, "analyzing", 95, "Generating VEX")
        vex_document = generate_vex_document(reachability_results, execution_profile)

        # Phase 7: Save results
        logger.info("Phase 7: Saving results")
        save_analysis_results(job_id, execution_profile, reachability_results, vex_document)

        # Complete
        update_job_status(job_id, "complete", 100, "Complete")
        logger.info(f"Analysis {job_id} completed successfully")

        return {
            "status": "success",
            "job_id": job_id,
            "vex_statements": len(vex_document.get("statements", []))
        }

    except Exception as e:
        logger.error(f"Analysis {job_id} failed: {e}", exc_info=True)
        update_job_status(job_id, "failed", 0, f"Error: {str(e)}")
        raise

    finally:
        # Always cleanup sandbox
        logger.info(f"Cleaning up sandbox for {job_id}")
        cleanup_sandbox(sandbox_id)

# Stub functions to implement
def update_job_status(job_id: str, status: str, progress: int, phase: str):
    """Update job status in database"""
    logger.info(f"Job {job_id}: {status} - {progress}% - {phase}")
    # TODO: Database update

def setup_sandbox(image_ref: str, image_digest: str, config: dict) -> str:
    """Setup isolated sandbox environment"""
    logger.info(f"Setting up sandbox for {image_ref}")
    # TODO: Create K8s Job
    return "sandbox-123"

def start_container_with_profiling(sandbox_id: str, config: dict):
    """Start container with eBPF profiling attached"""
    logger.info(f"Starting container in {sandbox_id}")
    # TODO: K8s Job with Tracee sidecar

def execute_tests(sandbox_id: str, config: dict):
    """Execute tests and fuzzing"""
    logger.info(f"Running tests in {sandbox_id}")
    # TODO: Execute user script or auto-fuzzing

def collect_execution_profile(sandbox_id: str) -> dict:
    """Collect execution profile from profiler"""
    logger.info(f"Collecting profile from {sandbox_id}")
    # TODO: Parse Tracee output
    return {
        "files_accessed": ["/app/main.py"],
        "syscalls": ["read", "write"],
        "duration_seconds": 120
    }

def analyze_reachability(execution_profile: dict, image_digest: str) -> dict:
    """Determine CVE reachability"""
    logger.info("Analyzing reachability")
    # TODO: CVE mapping logic
    return {
        "cves_analyzed": 10,
        "not_affected": 8,
        "affected": 2
    }

def generate_vex_document(reachability_results: dict, execution_profile: dict) -> dict:
    """Generate OpenVEX document"""
    logger.info("Generating VEX document")
    # TODO: VEX generation
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": []
    }

def save_analysis_results(job_id: str, execution_profile: dict, reachability: dict, vex: dict):
    """Save results to database"""
    logger.info(f"Saving results for {job_id}")
    # TODO: Database save

def cleanup_sandbox(sandbox_id: str):
    """Cleanup sandbox resources"""
    logger.info(f"Cleaning up {sandbox_id}")
    # TODO: Delete K8s Job
```

**Run worker:**
```bash
celery -A workers.tasks worker --loglevel=info
```

### Day 5: Integration Testing

Create `tests/test_api.py`:

```python
import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_submit_analysis():
    response = client.post("/api/v1/analysis/submit", json={
        "image_ref": "nginx:latest",
        "image_digest": "sha256:abc123",
        "config": {
            "enable_fuzzing": True,
            "test_timeout": 300
        }
    })
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"

def test_get_status():
    # First submit a job
    submit_response = client.post("/api/v1/analysis/submit", json={
        "image_ref": "nginx:latest",
        "image_digest": "sha256:abc123"
    })
    job_id = submit_response.json()["job_id"]

    # Then check status
    status_response = client.get(f"/api/v1/analysis/{job_id}/status")
    assert status_response.status_code == 200
    assert status_response.json()["job_id"] == job_id
```

Run tests:
```bash
pytest tests/ -v
```

---

## 🎯 Goal: Week 2

**Sandbox can execute containers and capture basic logs**

### Day 6-7: Kubernetes Integration

Create `services/sandbox.py`:

```python
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import logging
from uuid import uuid4
from typing import Optional

logger = logging.getLogger(__name__)

class SandboxManager:
    """Manage sandbox execution in Kubernetes"""

    def __init__(self, namespace: str = "vexxy-sandbox"):
        # Load kubeconfig
        try:
            config.load_incluster_config()  # When running in cluster
        except:
            config.load_kube_config()  # Local development

        self.batch_v1 = client.BatchV1Api()
        self.core_v1 = client.CoreV1Api()
        self.namespace = namespace

    def create_sandbox_job(
        self,
        image_ref: str,
        image_digest: str,
        job_config: dict
    ) -> str:
        """Create Kubernetes Job for sandbox execution"""

        job_id = str(uuid4())[:8]
        job_name = f"vex-analysis-{job_id}"

        # Job specification
        job = client.V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=client.V1ObjectMeta(
                name=job_name,
                namespace=self.namespace,
                labels={
                    "app": "vexxy-premium",
                    "component": "sandbox",
                    "job-id": job_id
                }
            ),
            spec=client.V1JobSpec(
                ttl_seconds_after_finished=600,  # Cleanup after 10 min
                backoff_limit=0,  # No retries
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(
                        labels={
                            "app": "vexxy-premium",
                            "job-id": job_id
                        }
                    ),
                    spec=client.V1PodSpec(
                        restart_policy="Never",
                        security_context=client.V1PodSecurityContext(
                            run_as_non_root=True,
                            seccomp_profile=client.V1SeccompProfile(
                                type="RuntimeDefault"
                            )
                        ),
                        containers=[
                            # Main container (user's image)
                            client.V1Container(
                                name="target",
                                image=f"{image_ref}@{image_digest}",
                                command=job_config.get("command", ["/bin/sh", "-c", "sleep 300"]),
                                resources=client.V1ResourceRequirements(
                                    limits={
                                        "cpu": "2",
                                        "memory": "4Gi"
                                    },
                                    requests={
                                        "cpu": "1",
                                        "memory": "2Gi"
                                    }
                                ),
                                env=[
                                    client.V1EnvVar(name=k, value=v)
                                    for k, v in job_config.get("environment", {}).items()
                                ]
                            ),
                            # Logger sidecar (captures logs)
                            client.V1Container(
                                name="logger",
                                image="busybox:latest",
                                command=[
                                    "/bin/sh",
                                    "-c",
                                    "while true; do date; ps aux; sleep 10; done"
                                ],
                                resources=client.V1ResourceRequirements(
                                    limits={"cpu": "100m", "memory": "128Mi"}
                                )
                            )
                        ]
                    )
                )
            )
        )

        try:
            self.batch_v1.create_namespaced_job(
                namespace=self.namespace,
                body=job
            )
            logger.info(f"Created sandbox job {job_name}")
            return job_id

        except ApiException as e:
            logger.error(f"Failed to create sandbox job: {e}")
            raise

    def get_job_status(self, job_id: str) -> dict:
        """Get status of sandbox job"""
        job_name = f"vex-analysis-{job_id}"

        try:
            job = self.batch_v1.read_namespaced_job(
                name=job_name,
                namespace=self.namespace
            )

            status = "unknown"
            if job.status.succeeded:
                status = "succeeded"
            elif job.status.failed:
                status = "failed"
            elif job.status.active:
                status = "running"

            return {
                "job_id": job_id,
                "status": status,
                "start_time": job.status.start_time,
                "completion_time": job.status.completion_time
            }

        except ApiException as e:
            logger.error(f"Failed to get job status: {e}")
            return {"job_id": job_id, "status": "not_found"}

    def get_job_logs(self, job_id: str, container: str = "target") -> str:
        """Get logs from sandbox job"""
        job_name = f"vex-analysis-{job_id}"

        try:
            # Find pod for this job
            pods = self.core_v1.list_namespaced_pod(
                namespace=self.namespace,
                label_selector=f"job-id={job_id}"
            )

            if not pods.items:
                return "No pods found"

            pod_name = pods.items[0].metadata.name

            # Get logs
            logs = self.core_v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=self.namespace,
                container=container
            )

            return logs

        except ApiException as e:
            logger.error(f"Failed to get logs: {e}")
            return f"Error: {e}"

    def delete_job(self, job_id: str):
        """Delete sandbox job"""
        job_name = f"vex-analysis-{job_id}"

        try:
            self.batch_v1.delete_namespaced_job(
                name=job_name,
                namespace=self.namespace,
                propagation_policy="Foreground"
            )
            logger.info(f"Deleted sandbox job {job_name}")

        except ApiException as e:
            logger.error(f"Failed to delete job: {e}")
```

Update `workers/tasks.py` to use SandboxManager:

```python
from services.sandbox import SandboxManager

sandbox_manager = SandboxManager()

def setup_sandbox(image_ref: str, image_digest: str, config: dict) -> str:
    """Setup isolated sandbox environment"""
    return sandbox_manager.create_sandbox_job(image_ref, image_digest, config)

def collect_execution_profile(sandbox_id: str) -> dict:
    """Collect execution profile from profiler"""
    # Get job status
    status = sandbox_manager.get_job_status(sandbox_id)

    # Get logs
    logs = sandbox_manager.get_job_logs(sandbox_id)

    return {
        "sandbox_id": sandbox_id,
        "status": status,
        "logs": logs,
        "files_accessed": [],  # TODO: Parse from profiler
        "syscalls": []  # TODO: Parse from profiler
    }

def cleanup_sandbox(sandbox_id: str):
    """Cleanup sandbox resources"""
    sandbox_manager.delete_job(sandbox_id)
```

### Day 8: End-to-End Test

Create namespace:
```bash
kubectl create namespace vexxy-sandbox
```

Submit test job via API:
```bash
curl -X POST http://localhost:8001/api/v1/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{
    "image_ref": "nginx",
    "image_digest": "sha256:4c0fdaa8b6341bfdeca5f18f7a2a65e6f4c7e37e32c66c62a7f0c6b9e4e71e5e",
    "config": {
      "test_timeout": 60,
      "environment": {
        "ENV": "test"
      }
    }
  }'
```

Check job in Kubernetes:
```bash
kubectl get jobs -n vexxy-sandbox
kubectl get pods -n vexxy-sandbox
kubectl logs -n vexxy-sandbox <pod-name> -c target
```

---

## Week 1 Success Criteria

✅ FastAPI service running
✅ Celery worker processing jobs
✅ PostgreSQL storing job records
✅ Kubernetes jobs created for analysis
✅ Logs retrieved from sandbox
✅ End-to-end flow working (minimal)

**Demo:** Submit image → Job created → Logs returned

---

## Next: Week 2

Add runtime profiling with Tracee and basic reachability analysis.

See `PREMIUM_VEX_INTEGRATION_PLAN.md` for full roadmap.
