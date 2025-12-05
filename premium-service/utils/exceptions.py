"""
Custom exception hierarchy for VEXxy Premium Service

Provides structured error handling with proper HTTP status codes and error context.
"""

from typing import Optional, Dict, Any
from datetime import datetime


class VexxyException(Exception):
    """
    Base exception for all VEXxy errors

    Attributes:
        message: Human-readable error message
        error_code: Machine-readable error code
        status_code: HTTP status code
        details: Additional error context
        timestamp: When the error occurred
    """

    def __init__(
        self,
        message: str,
        error_code: str = "VEXXY_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }


# 400 - Client Errors
class ValidationError(VexxyException):
    """Invalid input data"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            status_code=400,
            details=details,
        )


class InvalidImageError(ValidationError):
    """Invalid container image reference or digest"""

    def __init__(self, image_ref: str, reason: str):
        super().__init__(
            message=f"Invalid image: {reason}",
            details={"image_ref": image_ref, "reason": reason},
        )


class InvalidConfigurationError(ValidationError):
    """Invalid analysis configuration"""

    def __init__(self, message: str, config_key: Optional[str] = None):
        details = {"config_key": config_key} if config_key else {}
        super().__init__(message=message, details=details)


# 401 - Authentication Errors
class UnauthorizedError(VexxyException):
    """Authentication required or failed"""

    def __init__(
        self,
        message: str = "Authentication required",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message, error_code="UNAUTHORIZED", status_code=401, details=details
        )


# 403 - Authorization Errors
class ForbiddenError(VexxyException):
    """Insufficient permissions"""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message, error_code="FORBIDDEN", status_code=403, details=details
        )


# 404 - Not Found Errors
class ResourceNotFoundError(VexxyException):
    """Requested resource does not exist"""

    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            message=f"{resource_type} not found: {resource_id}",
            error_code="RESOURCE_NOT_FOUND",
            status_code=404,
            details={"resource_type": resource_type, "resource_id": resource_id},
        )


class JobNotFoundError(ResourceNotFoundError):
    """Analysis job not found"""

    def __init__(self, job_id: str):
        super().__init__(resource_type="Analysis Job", resource_id=job_id)


# 409 - Conflict Errors
class ResourceConflictError(VexxyException):
    """Resource conflict or invalid state transition"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="RESOURCE_CONFLICT",
            status_code=409,
            details=details,
        )


class InvalidJobStateError(ResourceConflictError):
    """Job is in invalid state for requested operation"""

    def __init__(self, job_id: str, current_state: str, required_state: str):
        super().__init__(
            message=f"Job {job_id} is in state '{current_state}', required '{required_state}'",
            details={
                "job_id": job_id,
                "current_state": current_state,
                "required_state": required_state,
            },
        )


# 429 - Rate Limiting
class QuotaExceededError(VexxyException):
    """Organization quota exceeded"""

    def __init__(self, quota_type: str, limit: int, current: int):
        super().__init__(
            message=f"{quota_type} quota exceeded: {current}/{limit}",
            error_code="QUOTA_EXCEEDED",
            status_code=429,
            details={"quota_type": quota_type, "limit": limit, "current": current},
        )


# 500 - Internal Server Errors
class InternalServiceError(VexxyException):
    """Internal service error"""

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        error_details = details or {}
        if service:
            error_details["service"] = service
        super().__init__(
            message=message,
            error_code="INTERNAL_ERROR",
            status_code=500,
            details=error_details,
        )


class DatabaseError(InternalServiceError):
    """Database operation failed"""

    def __init__(self, operation: str, error: str):
        super().__init__(
            message=f"Database {operation} failed: {error}",
            service="database",
            details={"operation": operation, "error": error},
        )


# 502 - External Service Errors
class ExternalServiceError(VexxyException):
    """External service or dependency error"""

    def __init__(
        self, service: str, message: str, details: Optional[Dict[str, Any]] = None
    ):
        error_details = details or {}
        error_details["service"] = service
        super().__init__(
            message=f"{service} error: {message}",
            error_code="EXTERNAL_SERVICE_ERROR",
            status_code=502,
            details=error_details,
        )


class KubernetesError(ExternalServiceError):
    """Kubernetes API error"""

    def __init__(
        self, operation: str, error: str, details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            service="kubernetes",
            message=f"Kubernetes {operation} failed: {error}",
            details=details,
        )


class KubescapeError(ExternalServiceError):
    """Kubescape service error"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(service="kubescape", message=message, details=details)


class SandboxError(ExternalServiceError):
    """Sandbox/container execution error"""

    def __init__(self, message: str, sandbox_id: Optional[str] = None):
        details = {"sandbox_id": sandbox_id} if sandbox_id else {}
        super().__init__(service="sandbox", message=message, details=details)


# 503 - Service Unavailable
class ServiceUnavailableError(VexxyException):
    """Service temporarily unavailable"""

    def __init__(self, service: str, reason: str):
        super().__init__(
            message=f"{service} service unavailable: {reason}",
            error_code="SERVICE_UNAVAILABLE",
            status_code=503,
            details={"service": service, "reason": reason},
        )


# 504 - Timeout Errors
class TimeoutError(VexxyException):
    """Operation timed out"""

    def __init__(self, operation: str, timeout_seconds: int):
        super().__init__(
            message=f"{operation} timed out after {timeout_seconds}s",
            error_code="TIMEOUT",
            status_code=504,
            details={"operation": operation, "timeout_seconds": timeout_seconds},
        )


class AnalysisTimeoutError(TimeoutError):
    """Analysis operation timed out"""

    def __init__(self, job_id: str, phase: str, timeout_seconds: int):
        super().__init__(
            operation=f"Analysis phase '{phase}'", timeout_seconds=timeout_seconds
        )
        self.details["job_id"] = job_id
        self.details["phase"] = phase
