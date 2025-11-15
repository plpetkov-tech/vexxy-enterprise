"""
Main FastAPI application for Premium VEX Service
"""
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
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
from exceptions import (
    JobNotFoundError,
    InvalidJobStateError,
    DatabaseError,
    InternalServiceError
)
from middleware import (
    error_handler_middleware,
    correlation_id_middleware,
    logging_middleware
)
from middleware.logging_middleware import configure_json_logging
from utils.kubernetes_config import load_kubernetes_config

# Configure structured logging if enabled
if settings.environment == "production":
    configure_json_logging(log_level=settings.log_level)
else:
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

# Add custom middleware (order matters - applied in reverse)
# 1. Error handlers (should be last to catch all errors)
error_handler_middleware(app)

# 2. Logging middleware
logging_middleware(app)

# 3. Correlation ID middleware (should be early to set correlation ID)
correlation_id_middleware(app)

# 4. CORS middleware
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
    logger.info(
        f"Starting {settings.service_name} v{settings.version}",
        extra={
            "event": "startup",
            "service": settings.service_name,
            "version": settings.version,
            "environment": settings.environment
        }
    )

    # Load Kubernetes configuration once at startup
    # This must happen before any Kubernetes-related services are instantiated
    try:
        logger.info("Loading Kubernetes configuration...", extra={"event": "k8s_config_load_start"})
        load_kubernetes_config(in_cluster=settings.k8s_in_cluster)
        logger.info("Kubernetes configuration loaded successfully", extra={"event": "k8s_config_load_success"})
    except Exception as e:
        logger.error(
            f"Kubernetes configuration loading failed: {e}",
            extra={
                "event": "k8s_config_load_failed",
                "error": str(e),
                "error_type": type(e).__name__
            },
            exc_info=True
        )
        # Don't exit - allow app to start but Kubernetes-dependent features will fail
        # This enables graceful degradation

    # Initialize database with proper error handling
    from models.database import init_db
    try:
        init_db()
        logger.info("Database initialized successfully", extra={"event": "database_init_success"})
    except Exception as e:
        logger.error(
            f"Database initialization failed: {e}",
            extra={
                "event": "database_init_failed",
                "error": str(e),
                "error_type": type(e).__name__
            },
            exc_info=True
        )
        # Don't exit - allow app to start but health check will fail
        # This enables graceful degradation and better visibility

    # Install Kubescape on startup (one-time setup)
    try:
        from services import KubescapeService
        logger.info("Checking Kubescape installation...", extra={"event": "kubescape_init_start"})

        kubescape_service = KubescapeService()
        if kubescape_service.is_kubescape_installed():
            logger.info("Kubescape is already installed", extra={"event": "kubescape_already_installed"})
        else:
            logger.info("Kubescape not found, installing...", extra={"event": "kubescape_installing"})
            success = kubescape_service.install_kubescape()

            if success:
                logger.info("Kubescape installed successfully", extra={"event": "kubescape_install_success"})
            else:
                logger.error("Kubescape installation failed", extra={"event": "kubescape_install_failed"})
                # Don't exit - allow app to start but analysis tasks will fail
    except Exception as e:
        logger.error(
            f"Kubescape initialization failed: {e}",
            extra={
                "event": "kubescape_init_failed",
                "error": str(e),
                "error_type": type(e).__name__
            },
            exc_info=True
        )
        # Don't exit - allow app to start but analysis tasks will fail

    # Install OWASP ZAP on startup (one-time setup)
    # Note: ZAP runs without API key authentication (api.disablekey=true)
    # API key can be configured via settings.zap_api_key when needed for production
    try:
        from services import ZAPService
        logger.info("Checking OWASP ZAP installation...", extra={"event": "zap_init_start"})

        # Check if ZAP is installed in the cluster
        zap_namespace = getattr(settings, 'zap_namespace', 'security')

        if ZAPService.is_zap_installed(namespace=zap_namespace):
            logger.info("OWASP ZAP is already installed", extra={"event": "zap_already_installed"})
        else:
            logger.info("OWASP ZAP not found, installing...", extra={"event": "zap_installing"})
            success = ZAPService.install_zap(namespace=zap_namespace)

            if success:
                logger.info("OWASP ZAP installed successfully", extra={"event": "zap_install_success"})
            else:
                logger.error("OWASP ZAP installation failed", extra={"event": "zap_install_failed"})
                # Don't exit - allow app to start but security scanning will be skipped

        # Verify ZAP is accessible
        zap_host = getattr(settings, 'zap_host', f'owasp-zap.{zap_namespace}.svc.cluster.local')
        zap_service = ZAPService(
            zap_host=zap_host,
            zap_port=getattr(settings, 'zap_port', 8080),
            zap_api_key=None  # No API key - ZAP runs with api.disablekey=true
        )

        if zap_service.is_zap_available():
            logger.info(
                "OWASP ZAP is available and ready for security scanning",
                extra={"event": "zap_available", "zap_host": zap_host}
            )
        else:
            logger.warning(
                "OWASP ZAP is not yet available - it may still be starting up",
                extra={"event": "zap_not_available", "zap_host": zap_host}
            )
            # Don't fail startup - ZAP may still be starting

    except Exception as e:
        logger.error(
            f"OWASP ZAP initialization failed: {e}",
            extra={
                "event": "zap_init_failed",
                "error": str(e),
                "error_type": type(e).__name__
            },
            exc_info=True
        )
        # Don't exit - allow app to start but security scanning will be skipped


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info(f"Shutting down {settings.service_name}")


# Health check with dependency verification
@app.get("/health", tags=["Health"])
async def health_check(request: Request, db: Session = Depends(get_db)):
    """
    Enhanced health check endpoint

    Checks:
    - Service is running
    - Database connectivity
    - Redis connectivity (for Celery)

    Returns:
    - 200: All systems healthy
    - 503: One or more dependencies unhealthy
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    health_status = {
        "status": "healthy",
        "service": settings.service_name,
        "version": settings.version,
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }

    if correlation_id:
        health_status["request_id"] = correlation_id

    overall_healthy = True

    # Check database
    try:
        db.execute(text("SELECT 1"))
        health_status["checks"]["database"] = {
            "status": "healthy",
            "message": "Database connection OK"
        }
        logger.debug("Health check: database OK", extra={"correlation_id": correlation_id})
    except Exception as e:
        overall_healthy = False
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}"
        }
        logger.error(
            f"Health check: database failed: {e}",
            extra={"correlation_id": correlation_id, "error": str(e)},
            exc_info=True
        )

    # Check Redis/Celery
    try:
        from workers.celery_app import celery_app
        celery_inspect = celery_app.control.inspect()

        # Quick ping with timeout
        stats = celery_inspect.stats()
        if stats:
            health_status["checks"]["celery"] = {
                "status": "healthy",
                "message": "Celery workers available",
                "workers": len(stats)
            }
            logger.debug(
                f"Health check: Celery OK ({len(stats)} workers)",
                extra={"correlation_id": correlation_id, "worker_count": len(stats)}
            )
        else:
            overall_healthy = False
            health_status["checks"]["celery"] = {
                "status": "unhealthy",
                "message": "No Celery workers available"
            }
            logger.warning(
                "Health check: No Celery workers available",
                extra={"correlation_id": correlation_id}
            )
    except Exception as e:
        overall_healthy = False
        health_status["checks"]["celery"] = {
            "status": "unhealthy",
            "message": f"Celery check failed: {str(e)}"
        }
        logger.error(
            f"Health check: Celery failed: {e}",
            extra={"correlation_id": correlation_id, "error": str(e)},
            exc_info=True
        )

    # Set overall status
    if not overall_healthy:
        health_status["status"] = "degraded"
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=health_status
        )

    return health_status


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

    # Queue the job in Celery for Kubescape-based analysis
    from workers.tasks import run_premium_analysis

    # Prepare config with analysis settings
    config = {}
    if request.config:
        config = request.config.model_dump()

    # Set default analysis duration if not specified (5 minutes)
    if "analysis_duration" not in config:
        config["analysis_duration"] = 300

    run_premium_analysis.delay(
        job_id=str(job.id),
        image_ref=request.image_ref,
        image_digest=request.image_digest,
        config=config
    )

    logger.info(f"Queued analysis job {job.id} in Celery")

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
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Get status of analysis job

    Returns current status, progress, and phase information.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.info(
        f"Status check for job {job_id}",
        extra={"correlation_id": correlation_id, "job_id": str(job_id)}
    )

    try:
        # Query database
        job = db.query(PremiumAnalysisJob).filter(
            PremiumAnalysisJob.id == job_id
        ).first()

        if not job:
            raise JobNotFoundError(job_id=str(job_id))

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
    except JobNotFoundError:
        raise
    except Exception as e:
        logger.error(
            f"Failed to get status for job {job_id}: {e}",
            extra={"correlation_id": correlation_id, "job_id": str(job_id), "error": str(e)},
            exc_info=True
        )
        raise DatabaseError(operation="query job status", error=str(e))


@app.get(
    f"{settings.api_prefix}/analysis/{{job_id}}/results",
    response_model=AnalysisResults,
    tags=["Analysis"]
)
async def get_analysis_results(
    job_id: UUID,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Get results of completed analysis

    Returns execution profile, reachability analysis, and generated VEX document.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.info(
        f"Results request for job {job_id}",
        extra={"correlation_id": correlation_id, "job_id": str(job_id)}
    )

    try:
        # Query database
        job = db.query(PremiumAnalysisJob).filter(
            PremiumAnalysisJob.id == job_id
        ).first()

        if not job:
            raise JobNotFoundError(job_id=str(job_id))

        if job.status != JobStatus.COMPLETE:
            raise InvalidJobStateError(
                job_id=str(job_id),
                current_state=job.status.value,
                required_state="COMPLETE"
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
    except (JobNotFoundError, InvalidJobStateError):
        raise
    except Exception as e:
        logger.error(
            f"Failed to get results for job {job_id}: {e}",
            extra={"correlation_id": correlation_id, "job_id": str(job_id), "error": str(e)},
            exc_info=True
        )
        raise DatabaseError(operation="query job results", error=str(e))


@app.delete(
    f"{settings.api_prefix}/analysis/{{job_id}}",
    tags=["Analysis"]
)
async def cancel_analysis(
    job_id: UUID,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Cancel running analysis job

    Stops the analysis and cleans up resources.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    logger.info(
        f"Cancel request for job {job_id}",
        extra={"correlation_id": correlation_id, "job_id": str(job_id)}
    )

    try:
        # Query database
        job = db.query(PremiumAnalysisJob).filter(
            PremiumAnalysisJob.id == job_id
        ).first()

        if not job:
            raise JobNotFoundError(job_id=str(job_id))

        if job.status in [JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.CANCELLED]:
            raise InvalidJobStateError(
                job_id=str(job_id),
                current_state=job.status.value,
                required_state="QUEUED, RUNNING, or ANALYZING"
            )

        # Update status
        job.status = JobStatus.CANCELLED
        job.completed_at = datetime.utcnow()
        db.commit()

        # TODO: Cancel Celery task and cleanup sandbox

        logger.info(
            f"Cancelled analysis job {job_id}",
            extra={"correlation_id": correlation_id, "job_id": str(job_id)}
        )

        return {
            "status": "cancelled",
            "job_id": str(job_id),
            "message": "Analysis job cancelled successfully"
        }
    except (JobNotFoundError, InvalidJobStateError):
        raise
    except Exception as e:
        logger.error(
            f"Failed to cancel job {job_id}: {e}",
            extra={"correlation_id": correlation_id, "job_id": str(job_id), "error": str(e)},
            exc_info=True
        )
        raise DatabaseError(operation="cancel job", error=str(e))


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
