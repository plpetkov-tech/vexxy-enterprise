"""
Retry utilities with exponential backoff

Provides robust retry logic for transient failures
"""

import time
import logging
from typing import Callable, TypeVar, Optional, Tuple, Type, Awaitable, Coroutine, Any
from functools import wraps
from dataclasses import dataclass

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """
    Configuration for retry behavior

    Attributes:
        max_attempts: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay between retries
        exponential_base: Base for exponential backoff calculation
        jitter: Add randomness to delay to prevent thundering herd
    """

    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True


def retry_with_backoff(
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[Exception, int], None]] = None,
):
    """
    Decorator for retrying functions with exponential backoff

    Args:
        exceptions: Tuple of exception types to retry on
        config: RetryConfig instance for retry behavior
        on_retry: Optional callback called before each retry with (exception, attempt)

    Example:
        @retry_with_backoff(
            exceptions=(ConnectionError, TimeoutError),
            config=RetryConfig(max_attempts=5, initial_delay=2.0)
        )
        def fetch_data():
            return api_client.get_data()
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(1, config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt >= config.max_attempts:
                        logger.error(
                            f"Function {func.__name__} failed after {config.max_attempts} attempts",
                            extra={
                                "function": func.__name__,
                                "attempts": config.max_attempts,
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                            },
                        )
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(
                        config.initial_delay
                        * (config.exponential_base ** (attempt - 1)),
                        config.max_delay,
                    )

                    # Add jitter if enabled
                    if config.jitter:
                        import random

                        delay *= 0.5 + random.random() * 0.5

                    logger.warning(
                        f"Function {func.__name__} failed (attempt {attempt}/{config.max_attempts}), retrying in {delay:.2f}s",
                        extra={
                            "function": func.__name__,
                            "attempt": attempt,
                            "max_attempts": config.max_attempts,
                            "delay": delay,
                            "exception": str(e),
                            "exception_type": type(e).__name__,
                        },
                    )

                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(e, attempt)
                        except Exception as callback_error:
                            logger.error(f"Retry callback failed: {callback_error}")

                    # Wait before retry
                    time.sleep(delay)

            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
            raise RuntimeError(f"Function {func.__name__} failed without exception")

        return wrapper

    return decorator


def retry_async_with_backoff(
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[Exception, int], None]] = None,
):
    """
    Decorator for retrying async functions with exponential backoff

    Args:
        exceptions: Tuple of exception types to retry on
        config: RetryConfig instance for retry behavior
        on_retry: Optional callback called before each retry with (exception, attempt)

    Example:
        @retry_async_with_backoff(
            exceptions=(ConnectionError, TimeoutError),
            config=RetryConfig(max_attempts=5, initial_delay=2.0)
        )
        async def fetch_data():
            return await api_client.get_data()
    """
    import asyncio

    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(1, config.max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt >= config.max_attempts:
                        logger.error(
                            f"Async function {func.__name__} failed after {config.max_attempts} attempts",
                            extra={
                                "function": func.__name__,
                                "attempts": config.max_attempts,
                                "exception": str(e),
                                "exception_type": type(e).__name__,
                            },
                        )
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(
                        config.initial_delay
                        * (config.exponential_base ** (attempt - 1)),
                        config.max_delay,
                    )

                    # Add jitter if enabled
                    if config.jitter:
                        import random

                        delay *= 0.5 + random.random() * 0.5

                    logger.warning(
                        f"Async function {func.__name__} failed (attempt {attempt}/{config.max_attempts}), retrying in {delay:.2f}s",
                        extra={
                            "function": func.__name__,
                            "attempt": attempt,
                            "max_attempts": config.max_attempts,
                            "delay": delay,
                            "exception": str(e),
                            "exception_type": type(e).__name__,
                        },
                    )

                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(e, attempt)
                        except Exception as callback_error:
                            logger.error(f"Retry callback failed: {callback_error}")

                    # Wait before retry
                    await asyncio.sleep(delay)

            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
            raise RuntimeError(f"Async function {func.__name__} failed without exception")

        return wrapper  # type: ignore[return-value]

    return decorator


class CircuitBreaker:
    """
    Circuit breaker pattern implementation

    Prevents cascading failures by failing fast when error rate is high.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Too many failures, requests fail immediately
    - HALF_OPEN: Testing if service recovered, limited requests allowed
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: Type[Exception] = Exception,
    ):
        """
        Initialize circuit breaker

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds before attempting recovery
            expected_exception: Exception type to track
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function through circuit breaker

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result

        Raises:
            Exception if circuit is open or function fails
        """
        if self.state == "OPEN":
            # Check if recovery timeout has passed
            if (
                self.last_failure_time
                and time.time() - self.last_failure_time >= self.recovery_timeout
            ):
                logger.info("Circuit breaker entering HALF_OPEN state")
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)

            # Success - reset on HALF_OPEN or CLOSED
            if self.state == "HALF_OPEN":
                logger.info("Circuit breaker entering CLOSED state")
                self.state = "CLOSED"
                self.failure_count = 0

            return result

        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            logger.warning(
                f"Circuit breaker failure {self.failure_count}/{self.failure_threshold}",
                extra={
                    "state": self.state,
                    "failure_count": self.failure_count,
                    "exception": str(e),
                },
            )

            # Open circuit if threshold exceeded
            if self.failure_count >= self.failure_threshold:
                logger.error("Circuit breaker entering OPEN state")
                self.state = "OPEN"

            raise
