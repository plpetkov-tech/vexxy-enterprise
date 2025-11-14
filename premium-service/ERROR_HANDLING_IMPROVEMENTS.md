# Error Handling and Reliability Improvements

## Overview

This document describes the comprehensive error handling, logging, and stability improvements made to the VEXxy Premium Service.

## Summary of Changes

### 1. Custom Exception Hierarchy (`exceptions.py`)

Created a structured exception hierarchy with proper HTTP status codes and error context:

**Base Exception:**
- `VexxyException` - Base class with error codes, status codes, timestamps, and details

**Client Errors (4xx):**
- `ValidationError` (400) - Invalid input data
- `InvalidImageError` (400) - Invalid container image
- `InvalidConfigurationError` (400) - Invalid analysis configuration
- `ResourceNotFoundError` (404) - Resource not found
- `JobNotFoundError` (404) - Specific to analysis jobs
- `ResourceConflictError` (409) - Conflict or invalid state
- `InvalidJobStateError` (409) - Invalid job state transition
- `QuotaExceededError` (429) - Rate limiting/quota exceeded

**Server Errors (5xx):**
- `InternalServiceError` (500) - Internal service errors
- `DatabaseError` (500) - Database operation failures
- `ExternalServiceError` (502) - External service errors
- `KubernetesError` (502) - Kubernetes API errors
- `KubescapeError` (502) - Kubescape service errors
- `SandboxError` (502) - Sandbox/container execution errors
- `ServiceUnavailableError` (503) - Service temporarily unavailable
- `TimeoutError` (504) - Operation timeouts
- `AnalysisTimeoutError` (504) - Analysis-specific timeouts

**Benefits:**
- Consistent error structure across the API
- Machine-readable error codes
- Proper HTTP status code mapping
- Rich error context for debugging
- Easy to extend for new error types

### 2. Global Error Handler Middleware (`middleware/error_handler.py`)

Implemented centralized error handling for the entire application:

**Features:**
- Catches all `VexxyException` instances and returns structured JSON responses
- Handles Pydantic validation errors with detailed field-level errors
- Catches HTTP exceptions and formats them consistently
- Catches unexpected exceptions and logs full tracebacks
- Includes correlation IDs in all error responses
- Logs errors with appropriate severity levels

**Benefits:**
- Consistent error responses across all endpoints
- No need to write try-catch in every endpoint
- Automatic error logging with context
- Better debugging with correlation IDs

### 3. Request Correlation ID Middleware (`middleware/correlation_id.py`)

Added request correlation IDs for distributed tracing:

**Features:**
- Accepts `X-Request-ID` header from clients
- Generates UUID if not provided
- Stores in request state for access by handlers
- Returns in response headers
- Included in all log messages and error responses

**Benefits:**
- Trace requests across services
- Debug issues by following a single request ID
- Better observability in distributed systems
- Helps correlate logs from multiple services

### 4. Structured JSON Logging (`middleware/logging_middleware.py`)

Implemented structured logging with JSON format:

**Features:**
- `StructuredLoggingMiddleware` logs all requests/responses with:
  - Request method, path, query params
  - Correlation ID
  - Response status code
  - Request duration in milliseconds
  - User agent, client IP
- `JsonFormatter` outputs logs as JSON with all extra fields
- `configure_json_logging()` sets up JSON logging globally
- Automatic timing header (`X-Response-Time`)

**Benefits:**
- Easy to parse logs programmatically
- Better integration with log aggregation tools (ELK, Splunk, etc.)
- Structured fields for filtering and searching
- Performance monitoring with request durations
- Production-ready logging format

### 5. Retry Logic with Exponential Backoff (`utils/retry.py`)

Created robust retry utilities for transient failures:

**Features:**
- `@retry_with_backoff` decorator for synchronous functions
- `@retry_async_with_backoff` decorator for async functions
- `RetryConfig` for configurable retry behavior:
  - Max attempts
  - Initial delay
  - Max delay
  - Exponential base
  - Jitter to prevent thundering herd
- `CircuitBreaker` class for preventing cascading failures

**Benefits:**
- Automatic retry for transient network/API failures
- Exponential backoff prevents overwhelming failing services
- Jitter prevents synchronized retries (thundering herd)
- Circuit breaker pattern for better resilience
- Configurable retry behavior per operation

### 6. Enhanced Health Checks (`api/main.py`)

Improved health check endpoint to verify dependencies:

**Features:**
- Checks database connectivity with `SELECT 1`
- Checks Celery worker availability
- Returns detailed status for each dependency
- Returns 503 if any dependency is unhealthy
- Includes correlation ID in response
- Detailed error messages for each failed check

**Benefits:**
- Better observability of system health
- Kubernetes can use for readiness/liveness probes
- Early detection of dependency failures
- Helps diagnose infrastructure issues
- Graceful degradation with partial failures

### 7. Improved API Error Handling (`api/main.py`)

Updated all API endpoints to use new error handling:

**Changes:**
- Replace `HTTPException` with custom exceptions
- Add correlation ID to all log messages
- Add structured logging with extra fields
- Wrap database operations in try-catch
- Use `JobNotFoundError` instead of generic 404
- Use `InvalidJobStateError` for state validation
- Use `DatabaseError` for database failures

**Benefits:**
- Consistent error responses
- Better error messages for clients
- Easier to debug with correlation IDs
- Rich context in error responses

### 8. Improved Service Error Handling (`services/kubescape.py`)

Enhanced error handling in Kubernetes/Kubescape service:

**Changes:**
- Wrap all Kubernetes API calls with proper exception handling
- Convert `ApiException` to `KubernetesError` with context
- Add retry logic to transient operations
- Add structured logging with extra fields
- Include operation details in errors
- Graceful handling of 404 errors

**Benefits:**
- Better error messages from Kubernetes operations
- Automatic retry for transient API failures
- Rich error context for debugging
- Consistent error handling across service layer

### 9. Startup Error Handling (`api/main.py`)

Improved application startup error handling:

**Changes:**
- Don't exit on database initialization failure
- Log detailed error information
- Allow app to start in degraded mode
- Health check will report unhealthy state

**Benefits:**
- Better visibility into startup issues
- Graceful degradation
- Kubernetes can detect unhealthy state via health checks
- Easier debugging of initialization failures

## Usage Examples

### Using Custom Exceptions

```python
from exceptions import JobNotFoundError, InvalidJobStateError, DatabaseError

# In your code
if not job:
    raise JobNotFoundError(job_id=str(job_id))

if job.status != JobStatus.COMPLETE:
    raise InvalidJobStateError(
        job_id=str(job_id),
        current_state=job.status.value,
        required_state="COMPLETE"
    )
```

### Using Retry Logic

```python
from utils import retry_with_backoff, RetryConfig

@retry_with_backoff(
    exceptions=(ApiException, ConnectionError),
    config=RetryConfig(max_attempts=5, initial_delay=2.0)
)
def call_external_api():
    return api_client.fetch_data()
```

### Structured Logging

```python
logger.info(
    "Processing job",
    extra={
        "correlation_id": correlation_id,
        "job_id": str(job_id),
        "status": job.status.value
    }
)
```

### Error Responses

Clients now receive consistent error responses:

```json
{
  "error": "RESOURCE_NOT_FOUND",
  "message": "Analysis Job not found: 123e4567-e89b-12d3-a456-426614174000",
  "details": {
    "resource_type": "Analysis Job",
    "resource_id": "123e4567-e89b-12d3-a456-426614174000"
  },
  "timestamp": "2025-11-13T21:30:45.123456",
  "request_id": "7f3d2a1b-9c8e-4f5d-a6b7-c8d9e0f1a2b3"
}
```

## Testing Recommendations

### 1. Unit Tests
- Test custom exception hierarchy
- Test retry logic with mock failures
- Test circuit breaker state transitions
- Test error handler middleware

### 2. Integration Tests
- Test API endpoints with invalid inputs
- Test database connection failures
- Test Kubernetes API failures
- Test timeout scenarios

### 3. Load Tests
- Test retry behavior under load
- Test circuit breaker activation
- Test correlation ID propagation
- Test logging performance

## Configuration

### Environment Variables

```bash
# Logging
LOG_LEVEL=INFO  # Use INFO in production for structured logging
ENVIRONMENT=production  # Enables JSON logging

# Retry Configuration (can be customized in code)
DEFAULT_MAX_RETRIES=3
DEFAULT_INITIAL_DELAY=1.0
DEFAULT_MAX_DELAY=60.0
```

### Middleware Order

Middleware is applied in reverse order. Current order:
1. CORS (outermost)
2. Correlation ID
3. Structured Logging
4. Error Handlers (innermost - catches all errors)

## Monitoring and Observability

### Key Metrics to Monitor

1. **Error Rates**
   - Track error responses by status code
   - Alert on high 5xx rates
   - Monitor specific error codes

2. **Retry Metrics**
   - Track retry attempts and success rates
   - Monitor backoff delays
   - Alert on high retry rates

3. **Request Durations**
   - Track p50, p95, p99 latencies
   - Monitor slow requests
   - Correlate with retry activity

4. **Health Check Status**
   - Monitor database health
   - Monitor Celery worker availability
   - Alert on degraded state

### Log Aggregation

Structured JSON logs can be easily ingested by:
- Elasticsearch + Kibana (ELK Stack)
- Splunk
- Datadog
- CloudWatch Logs Insights
- Loki + Grafana

Example log queries:
```
# Find all errors for a specific request
correlation_id: "7f3d2a1b-9c8e-4f5d-a6b7-c8d9e0f1a2b3"

# Find all database errors
error_code: "DATABASE_ERROR"

# Find slow requests (>1000ms)
duration_ms > 1000
```

## Best Practices

### 1. Always Use Custom Exceptions
- Don't raise generic `Exception` or `RuntimeError`
- Use the most specific exception type
- Include relevant context in details

### 2. Add Correlation IDs
- Access from `request.state.correlation_id`
- Include in all log messages
- Pass to downstream services

### 3. Log Appropriately
- DEBUG: Detailed internal state
- INFO: Normal operations, request completion
- WARNING: Recoverable errors, retries
- ERROR: Errors requiring attention
- Include structured extra fields

### 4. Handle Errors Gracefully
- Catch specific exceptions
- Re-raise as appropriate custom exceptions
- Include original error context
- Clean up resources in finally blocks

### 5. Use Retry Logic Wisely
- Only retry transient failures
- Set appropriate max attempts
- Use exponential backoff
- Add jitter to prevent thundering herd
- Don't retry validation errors

## Future Improvements

1. **Metrics/Observability**
   - Add Prometheus metrics
   - Track error rates by type
   - Monitor retry success rates

2. **Alerting**
   - Alert on high error rates
   - Alert on circuit breaker activations
   - Alert on health check failures

3. **Tracing**
   - Add OpenTelemetry integration
   - Distributed tracing across services
   - Performance profiling

4. **Error Recovery**
   - Automatic job retry for transient failures
   - Dead letter queue for failed jobs
   - Graceful degradation strategies

## Conclusion

These improvements significantly enhance the reliability, observability, and maintainability of the VEXxy Premium Service. The structured approach to error handling makes it easier to:
- Debug production issues
- Monitor system health
- Handle failures gracefully
- Provide better user experience
- Scale the system reliably
