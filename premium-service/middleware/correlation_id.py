"""
Request correlation ID middleware

Adds X-Request-ID header to all requests for distributed tracing
"""
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import logging

logger = logging.getLogger(__name__)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add correlation IDs to requests

    - Accepts existing X-Request-ID header from client
    - Generates new UUID if not provided
    - Adds correlation ID to response headers
    - Stores in request state for logging
    """

    async def dispatch(self, request: Request, call_next):
        # Get or generate correlation ID
        correlation_id = request.headers.get("X-Request-ID")
        if not correlation_id:
            correlation_id = str(uuid.uuid4())

        # Store in request state
        request.state.correlation_id = correlation_id

        # Process request
        response = await call_next(request)

        # Add to response headers
        response.headers["X-Request-ID"] = correlation_id

        return response


def correlation_id_middleware(app):
    """Add correlation ID middleware to FastAPI app"""
    app.add_middleware(CorrelationIdMiddleware)
