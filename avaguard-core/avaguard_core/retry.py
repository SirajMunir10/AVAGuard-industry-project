# avaguard-core/avaguard_core/retry.py

import time
import logging
from functools import wraps
from typing import Tuple, Type

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = {429, 500, 502, 503}
PERMANENT_FAILURE_CODES = {401, 403}

def retry(max_retries: int = 3, backoff_base: float = 2.0, max_wait: float = 30.0):
    """
    Decorator for retrying HTTP calls with exponential backoff.

    Retries on: 429 (rate limit), 500, 502, 503 (transient server errors)
    Never retries on: 401 (auth failure), 403 (permission denied)
    Respects Retry-After header when present on 429 responses.

    Args:
        max_retries: Maximum number of retry attempts (default 3)
        backoff_base: Base multiplier for exponential backoff in seconds (default 2.0)
        max_wait: Maximum wait time between retries in seconds (default 30.0)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):  # +1 for initial attempt
                try:
                    return func(*args, **kwargs)

                except Exception as exc:
                    status_code = _extract_status_code(exc)

                    if status_code in PERMANENT_FAILURE_CODES:
                        logger.error(
                            f"{func.__name__} failed permanently "
                            f"(HTTP {status_code}). Not retrying."
                        )
                        raise

                    if status_code is None and not _is_retryable_exception(exc):
                        raise

                    if attempt >= max_retries:
                        logger.error(
                            f"{func.__name__} failed after {max_retries} retries. "
                            f"Last error: {exc}"
                        )
                        raise

                    wait_time = _calculate_wait(exc, attempt, backoff_base, max_wait)

                    logger.warning(
                        f"{func.__name__} attempt {attempt + 1}/{max_retries} failed "
                        f"(HTTP {status_code or 'unknown'}). "
                        f"Retrying in {wait_time:.1f}s..."
                    )
                    time.sleep(wait_time)
                    last_exception = exc

            raise last_exception
        return wrapper
    return decorator


def _extract_status_code(exc: Exception):
    """Extract HTTP status code from various exception types."""
    if hasattr(exc, 'response') and hasattr(exc.response, 'status_code'):
        return exc.response.status_code
    if hasattr(exc, 'status_code'):
        return exc.status_code
    return None


def _is_retryable_exception(exc: Exception) -> bool:
    """Determine if a non-HTTP exception is worth retrying."""
    try:
        import requests
        return isinstance(exc, (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ChunkedEncodingError,
        ))
    except ImportError:
        return False


def _calculate_wait(exc: Exception, attempt: int, backoff_base: float, max_wait: float) -> float:
    """
    Calculate wait time. Respects Retry-After header for 429 responses.
    Falls back to exponential backoff.
    """
    if hasattr(exc, 'response') and exc.response is not None:
        retry_after = exc.response.headers.get('Retry-After')
        if retry_after:
            try:
                return min(float(retry_after), max_wait)
            except (ValueError, TypeError):
                pass

    return min((backoff_base ** attempt) * backoff_base, max_wait)
