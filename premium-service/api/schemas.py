"""
Pydantic schemas for API request/response validation
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, List
from datetime import datetime
from uuid import UUID
from enum import Enum


class JobStatusEnum(str, Enum):
    """Job status values"""
    QUEUED = "queued"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisConfig(BaseModel):
    """Configuration for analysis job"""
    test_script: Optional[str] = Field(
        None,
        description="Custom test script to execute during analysis"
    )
    test_timeout: int = Field(
        default=300,
        ge=60,
        le=900,
        description="Timeout for test execution in seconds"
    )
    enable_fuzzing: bool = Field(
        default=True,
        description="Enable OWASP ZAP fuzzing"
    )
    enable_profiling: bool = Field(
        default=True,
        description="Enable eBPF profiling with Tracee"
    )
    enable_code_coverage: bool = Field(
        default=False,
        description="Enable code coverage analysis (requires debug symbols)"
    )
    ports: List[int] = Field(
        default_factory=list,
        description="Ports to expose for testing"
    )
    environment: Dict[str, str] = Field(
        default_factory=dict,
        description="Environment variables for the container"
    )
    command: Optional[List[str]] = Field(
        None,
        description="Override container command"
    )

    @field_validator('ports')
    @classmethod
    def validate_ports(cls, v):
        """Validate port numbers"""
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")
        return v


class AnalysisRequest(BaseModel):
    """Request to analyze container image"""
    image_ref: str = Field(
        ...,
        description="Container image reference (e.g., nginx:latest)",
        min_length=1
    )
    image_digest: str = Field(
        ...,
        description="Image digest (e.g., sha256:abc123...)",
        pattern=r"^sha256:[a-f0-9]{64}$"
    )
    sbom_id: Optional[UUID] = Field(
        None,
        description="SBOM ID from VEXxy core (for reachability analysis)"
    )
    config: AnalysisConfig = Field(
        default_factory=AnalysisConfig,
        description="Analysis configuration"
    )


class AnalysisJobResponse(BaseModel):
    """Response for analysis job submission"""
    job_id: UUID
    status: JobStatusEnum
    image_ref: str
    image_digest: str
    estimated_duration_minutes: int
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisStatusResponse(BaseModel):
    """Status of analysis job"""
    job_id: UUID
    status: JobStatusEnum
    progress_percent: int
    current_phase: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    sandbox_id: Optional[str] = None

    model_config = {"from_attributes": True}


class ExecutionProfile(BaseModel):
    """Execution profile from runtime analysis"""
    sandbox_id: str
    duration_seconds: int
    files_accessed: List[str] = Field(default_factory=list)
    syscalls: List[str] = Field(default_factory=list)
    network_connections: List[str] = Field(default_factory=list)
    loaded_libraries: List[str] = Field(default_factory=list)
    code_coverage_percent: Optional[float] = None

    model_config = {"extra": "ignore"}  # Allow extra fields for metadata


class ReachabilityResult(BaseModel):
    """Reachability analysis result for a CVE"""
    cve_id: str
    status: str  # affected, not_affected, under_investigation, unknown
    justification: Optional[str] = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    reason: str
    vulnerable_files: List[str] = Field(default_factory=list)
    executed_files: List[str] = Field(default_factory=list)


class SecurityAlert(BaseModel):
    """Security alert from OWASP ZAP or similar scanners"""
    alert_id: str
    name: str
    risk: str  # High, Medium, Low, Informational
    confidence: str  # High, Medium, Low
    description: str
    url: Optional[str] = None
    method: Optional[str] = None
    param: Optional[str] = None
    solution: Optional[str] = None
    reference: Optional[str] = None
    cwe_id: Optional[int] = None
    wasc_id: Optional[int] = None


class SecurityFindings(BaseModel):
    """Security scan findings from OWASP ZAP and other tools"""
    scan_type: str = Field(default="owasp_zap", description="Type of security scan performed")
    status: str = Field(description="Scan status: completed, failed, skipped")
    scan_duration_seconds: Optional[int] = None
    target_urls: List[str] = Field(default_factory=list, description="URLs that were scanned")

    # Summary statistics
    total_alerts: int = Field(default=0)
    high_risk: int = Field(default=0)
    medium_risk: int = Field(default=0)
    low_risk: int = Field(default=0)
    informational: int = Field(default=0)

    # Detailed alerts (optional, can be large)
    alerts: List[SecurityAlert] = Field(default_factory=list, description="Detailed security alerts")

    # Additional metadata
    scan_timestamp: Optional[datetime] = None
    scanner_version: Optional[str] = None
    error_message: Optional[str] = None


class AnalysisResults(BaseModel):
    """Complete analysis results"""
    job_id: UUID
    status: JobStatusEnum
    image_ref: str
    image_digest: str
    execution_profile: Optional[ExecutionProfile] = None
    reachability_results: List[ReachabilityResult] = Field(default_factory=list)
    security_findings: Optional[SecurityFindings] = None
    generated_vex_id: Optional[UUID] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    version: str
    timestamp: datetime
