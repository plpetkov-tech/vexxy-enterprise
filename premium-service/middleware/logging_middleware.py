"""
Structured logging middleware

Provides JSON-formatted logging with request/response context
"""

import time
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from typing import Callable
import json

logger = logging.getLogger(__name__)


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all requests with structured data

    Logs include:
    - Request method, path, query params
    - Correlation ID
    - Response status code
    - Request duration
    - User agent, IP address
    """

    async def dispatch(self, request: Request, call_next: Callable):
        # Start timer
        start_time = time.time()

        # Get correlation ID from request state
        correlation_id = getattr(request.state, "correlation_id", None)

        # Log request
        logger.info(
            "Request started",
            extra={
                "event": "request_started",
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "query_params": str(request.query_params),
                "client_host": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )

        # Process request
        try:
            response = await call_next(request)
        except Exception as exc:
            # Log exception
            duration = time.time() - start_time
            logger.error(
                "Request failed",
                extra={
                    "event": "request_failed",
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": round(duration * 1000, 2),
                    "exception": str(exc),
                    "exception_type": type(exc).__name__,
                },
                exc_info=True,
            )
            raise

        # Calculate duration
        duration = time.time() - start_time

        # Log response
        logger.info(
            "Request completed",
            extra={
                "event": "request_completed",
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
            },
        )

        # Add timing header
        response.headers["X-Response-Time"] = f"{round(duration * 1000, 2)}ms"

        return response


def logging_middleware(app):
    """Add structured logging middleware to FastAPI app"""
    app.add_middleware(StructuredLoggingMiddleware)


class JsonFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging

    Outputs log records as JSON with all extra fields
    """

    def format(self, record: logging.LogRecord) -> str:
        # Base log entry
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add all extra fields from the record
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "thread",
                "threadName",
                "exc_info",
                "exc_text",
                "stack_info",
                "taskName",
            ]:
                log_data[key] = value

        return json.dumps(log_data)


def configure_json_logging(log_level: str = "INFO"):
    """
    Configure JSON logging for the application

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Get root logger
    root_logger = logging.getLogger()

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler with JSON formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JsonFormatter())

    # Set level and add handler
    root_logger.setLevel(getattr(logging, log_level.upper()))
    root_logger.addHandler(console_handler)

    logger.info("JSON logging configured", extra={"log_level": log_level})
