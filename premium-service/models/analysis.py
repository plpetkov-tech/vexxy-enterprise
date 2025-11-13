"""
Analysis job models
"""
from sqlalchemy import Column, String, Integer, DateTime, JSON, Enum, Text, BigInteger, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
import enum

from .database import Base


class JobStatus(str, enum.Enum):
    """Analysis job status"""
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvidenceType(str, enum.Enum):
    """Types of evidence collected"""
    EXECUTION_TRACE = "execution_trace"
    SYSCALL_LOG = "syscall_log"
    FILE_ACCESS_LOG = "file_access_log"
    NETWORK_LOG = "network_log"
    FUZZING_RESULTS = "fuzzing_results"
    CODE_COVERAGE = "code_coverage"
    PROFILER_OUTPUT = "profiler_output"


class PremiumAnalysisJob(Base):
    """Premium analysis job tracking"""
    __tablename__ = "premium_analysis_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Image information
    image_ref = Column(String(500), nullable=False)
    image_digest = Column(String(100), nullable=False, index=True)
    sbom_id = Column(UUID(as_uuid=True), nullable=True)

    # Job status
    status = Column(Enum(JobStatus), nullable=False, default=JobStatus.QUEUED, index=True)
    priority = Column(Integer, default=0, index=True)

    # Progress tracking
    progress_percent = Column(Integer, default=0)
    current_phase = Column(String(100))

    # Configuration
    config = Column(JSON, nullable=False, default=dict)

    # Results
    execution_profile = Column(JSON)
    reachability_results = Column(JSON)
    generated_vex_id = Column(UUID(as_uuid=True), nullable=True)

    # Sandbox tracking
    sandbox_id = Column(String(100), nullable=True)
    sandbox_job_name = Column(String(100), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Error handling
    error_message = Column(Text, nullable=True)
    error_traceback = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    # Billing
    billed_at = Column(DateTime, nullable=True)
    cost_credits = Column(Integer, default=1)

    def __repr__(self):
        return f"<PremiumAnalysisJob {self.id} - {self.status.value}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "organization_id": str(self.organization_id),
            "image_ref": self.image_ref,
            "image_digest": self.image_digest,
            "status": self.status.value,
            "priority": self.priority,
            "progress_percent": self.progress_percent,
            "current_phase": self.current_phase,
            "config": self.config,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
        }


class AnalysisEvidence(Base):
    """Evidence collected during analysis"""
    __tablename__ = "analysis_evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_job_id = Column(
        UUID(as_uuid=True),
        ForeignKey("premium_analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # Evidence details
    evidence_type = Column(Enum(EvidenceType), nullable=False, index=True)
    evidence_data = Column(JSON, nullable=True)

    # Storage reference for large files
    storage_path = Column(String(500), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    checksum = Column(String(64), nullable=True)  # SHA256

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    description = Column(Text, nullable=True)

    def __repr__(self):
        return f"<AnalysisEvidence {self.id} - {self.evidence_type.value}>"

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "id": str(self.id),
            "analysis_job_id": str(self.analysis_job_id),
            "evidence_type": self.evidence_type.value,
            "evidence_data": self.evidence_data,
            "storage_path": self.storage_path,
            "file_size": self.file_size,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "description": self.description,
        }
