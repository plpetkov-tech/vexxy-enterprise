"""
Main FastAPI application for Premium VEX Service
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
from uuid import UUID
import logging

from config.settings import settings
from models import get_db, PremiumAnalysisJob, JobStatus
from .schemas import (
    AnalysisRequest,
    AnalysisJobResponse,
    AnalysisStatusResponse,
    AnalysisResults,
    HealthResponse,
    JobStatusEnum
)

# Configure logging
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="VEXxy Premium Analysis Service",
    description="Automated reachability-based VEX generation through runtime analysis",
    version=settings.version,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info(f"Starting {settings.service_name} v{settings.version}")
    logger.info(f"Environment: {settings.environment}")

    # Initialize database
    from models.database import init_db
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info(f"Shutting down {settings.service_name}")


# Health check
@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint

    Returns service status and version information.
    """
    return HealthResponse(
        status="healthy",
        service=settings.service_name,
        version=settings.version,
        timestamp=datetime.utcnow()
    )


# Analysis endpoints
@app.post(
    f"{settings.api_prefix}/analysis/submit",
    response_model=AnalysisJobResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Analysis"]
)
async def submit_analysis(
    request: AnalysisRequest,
    db: Session = Depends(get_db)
):
    """
    Submit container image for premium reachability analysis

    This endpoint:
    1. Validates the request
    2. Creates an analysis job record
    3. Queues it for processing by Celery workers
    4. Returns job ID for tracking

    **Authentication required** (TODO: Implement JWT validation)

    **Quota enforcement** (TODO: Check organization tier and usage)
    """
    logger.info(f"Received analysis request for {request.image_ref}@{request.image_digest}")

    # TODO: Authentication & authorization
    # For now, use a dummy organization ID
    organization_id = "00000000-0000-0000-0000-000000000000"

    # TODO: Quota check

    # Create analysis job
    job = PremiumAnalysisJob(
        organization_id=organization_id,
        image_ref=request.image_ref,
        image_digest=request.image_digest,
        sbom_id=request.sbom_id,
        config=request.config.model_dump(),
        status=JobStatus.QUEUED,
        priority=0,  # TODO: Set based on tier
        progress_percent=0,
        current_phase="pending"
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    logger.info(f"Created analysis job {job.id}")

    # TODO: Queue the job in Celery
    # from workers.tasks import run_premium_analysis
    # run_premium_analysis.delay(
    #     job_id=str(job.id),
    #     image_ref=request.image_ref,
    #     image_digest=request.image_digest,
    #     config=request.config.model_dump()
    # )

    return AnalysisJobResponse(
        job_id=job.id,
        status=JobStatusEnum(job.status.value),
        image_ref=job.image_ref,
        image_digest=job.image_digest,
        estimated_duration_minutes=10,
        created_at=job.created_at
    )


@app.get(
    f"{settings.api_prefix}/analysis/{{job_id}}/status",
    response_model=AnalysisStatusResponse,
    tags=["Analysis"]
)
async def get_analysis_status(
    job_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Get status of analysis job

    Returns current status, progress, and phase information.
    """
    logger.info(f"Status check for job {job_id}")

    # Query database
    job = db.query(PremiumAnalysisJob).filter(
        PremiumAnalysisJob.id == job_id
    ).first()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job {job_id} not found"
        )

    return AnalysisStatusResponse(
        job_id=job.id,
        status=JobStatusEnum(job.status.value),
        progress_percent=job.progress_percent or 0,
        current_phase=job.current_phase,
        started_at=job.started_at,
        completed_at=job.completed_at,
        error_message=job.error_message,
        sandbox_id=job.sandbox_id
    )


@app.get(
    f"{settings.api_prefix}/analysis/{{job_id}}/results",
    response_model=AnalysisResults,
    tags=["Analysis"]
)
async def get_analysis_results(
    job_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Get results of completed analysis

    Returns execution profile, reachability analysis, and generated VEX document.
    """
    logger.info(f"Results request for job {job_id}")

    # Query database
    job = db.query(PremiumAnalysisJob).filter(
        PremiumAnalysisJob.id == job_id
    ).first()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job {job_id} not found"
        )

    if job.status != JobStatus.COMPLETE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Analysis job {job_id} is not complete (status: {job.status.value})"
        )

    return AnalysisResults(
        job_id=job.id,
        status=JobStatusEnum(job.status.value),
        image_ref=job.image_ref,
        image_digest=job.image_digest,
        execution_profile=job.execution_profile,
        reachability_results=job.reachability_results or [],
        generated_vex_id=job.generated_vex_id,
        created_at=job.created_at,
        completed_at=job.completed_at
    )


@app.delete(
    f"{settings.api_prefix}/analysis/{{job_id}}",
    tags=["Analysis"]
)
async def cancel_analysis(
    job_id: UUID,
    db: Session = Depends(get_db)
):
    """
    Cancel running analysis job

    Stops the analysis and cleans up resources.
    """
    logger.info(f"Cancel request for job {job_id}")

    # Query database
    job = db.query(PremiumAnalysisJob).filter(
        PremiumAnalysisJob.id == job_id
    ).first()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job {job_id} not found"
        )

    if job.status in [JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.CANCELLED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job in status: {job.status.value}"
        )

    # Update status
    job.status = JobStatus.CANCELLED
    job.completed_at = datetime.utcnow()
    db.commit()

    # TODO: Cancel Celery task and cleanup sandbox

    logger.info(f"Cancelled analysis job {job_id}")

    return {
        "status": "cancelled",
        "job_id": job_id,
        "message": "Analysis job cancelled successfully"
    }


@app.get(
    f"{settings.api_prefix}/analysis",
    tags=["Analysis"]
)
async def list_analyses(
    skip: int = 0,
    limit: int = 50,
    status_filter: JobStatusEnum = None,
    db: Session = Depends(get_db)
):
    """
    List analysis jobs

    Supports pagination and filtering by status.
    """
    query = db.query(PremiumAnalysisJob)

    # Filter by status if provided
    if status_filter:
        query = query.filter(PremiumAnalysisJob.status == JobStatus(status_filter.value))

    # Order by created_at desc
    query = query.order_by(PremiumAnalysisJob.created_at.desc())

    # Pagination
    total = query.count()
    jobs = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "jobs": [job.to_dict() for job in jobs]
    }


# Run with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
        log_level=settings.log_level.lower()
    )
