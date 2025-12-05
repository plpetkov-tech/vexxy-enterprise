"""
Global error handler middleware

Provides consistent error responses across the API
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging

from exceptions import VexxyException

logger = logging.getLogger(__name__)


async def vexxy_exception_handler(
    request: Request, exc: VexxyException
) -> JSONResponse:
    """
    Handle VexxyException and return structured error response

    Args:
        request: FastAPI request
        exc: VexxyException instance

    Returns:
        JSONResponse with error details
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    logger.error(
        f"VexxyException: {exc.error_code} - {exc.message}",
        extra={
            "correlation_id": correlation_id,
            "error_code": exc.error_code,
            "details": exc.details,
            "path": request.url.path,
        },
    )

    error_response = exc.to_dict()
    if correlation_id:
        error_response["request_id"] = correlation_id

    return JSONResponse(status_code=exc.status_code, content=error_response)


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Handle Pydantic validation errors

    Args:
        request: FastAPI request
        exc: RequestValidationError instance

    Returns:
        JSONResponse with validation error details
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    logger.warning(
        f"Validation error: {exc.errors()}",
        extra={
            "correlation_id": correlation_id,
            "path": request.url.path,
            "errors": exc.errors(),
        },
    )

    error_response = {
        "error": "VALIDATION_ERROR",
        "message": "Request validation failed",
        "details": {"errors": exc.errors()},
    }

    if correlation_id:
        error_response["request_id"] = correlation_id

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, content=error_response
    )


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """
    Handle HTTP exceptions

    Args:
        request: FastAPI request
        exc: HTTPException instance

    Returns:
        JSONResponse with error details
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail}",
        extra={
            "correlation_id": correlation_id,
            "status_code": exc.status_code,
            "path": request.url.path,
        },
    )

    error_response = {"error": "HTTP_ERROR", "message": str(exc.detail), "details": {}}

    if correlation_id:
        error_response["request_id"] = correlation_id

    return JSONResponse(status_code=exc.status_code, content=error_response)


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions

    Args:
        request: FastAPI request
        exc: Exception instance

    Returns:
        JSONResponse with generic error
    """
    correlation_id = getattr(request.state, "correlation_id", None)

    # Log full traceback for debugging
    logger.error(
        f"Unhandled exception: {type(exc).__name__}: {str(exc)}",
        extra={
            "correlation_id": correlation_id,
            "path": request.url.path,
            "exception_type": type(exc).__name__,
        },
        exc_info=True,
    )

    error_response = {
        "error": "INTERNAL_ERROR",
        "message": "An internal error occurred",
        "details": {"type": type(exc).__name__},
    }

    if correlation_id:
        error_response["request_id"] = correlation_id

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=error_response
    )


def error_handler_middleware(app):
    """
    Add error handlers to FastAPI app

    Args:
        app: FastAPI application instance
    """
    # Custom exception handlers
    app.add_exception_handler(VexxyException, vexxy_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    logger.info("Error handler middleware registered")
