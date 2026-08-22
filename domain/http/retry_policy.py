import time
from typing import Optional, Callable
from requests import Response
from requests.exceptions import RequestException, Timeout, HTTPError

from utils.logging import get_logger

logger = get_logger()


class RetryPolicy:
    def __init__(self, max_retries: int = 2, backoff_factor: float = 1.0):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        if attempt >= self.max_retries:
            return False

        if isinstance(exception, Timeout):
            return True

        if isinstance(exception, HTTPError):
            if hasattr(exception, 'response') and exception.response:
                if exception.response.status_code == 500 and attempt < 1:
                    return True

        if isinstance(exception, RequestException):
            return True

        return False

    def get_backoff_delay(self, attempt: int) -> float:
        return self.backoff_factor * (2 ** attempt)

    def execute_with_retry(self,
                          request_func: Callable[[], Response],
                          attempt: int = 0) -> Optional[Response]:
        try:
            response = request_func()
            return response
        except HTTPError as e:
            if hasattr(e, 'response') and e.response is not None:
                return e.response
            if self.should_retry(e, attempt):
                delay = self.get_backoff_delay(attempt)
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}). "
                    f"Retrying in {delay:.1f}s... Error: {e}"
                )
                time.sleep(delay)
                return self.execute_with_retry(request_func, attempt + 1)
            else:
                if hasattr(e, 'response') and e.response is not None:
                    return e.response
                logger.error(f"Request failed after {attempt + 1} attempts: {e}")
                raise
        except Exception as e:
            # RequestSender handles this as a normal scan stop, not a network
            # failure that should be retried or logged as an error.
            if e.__class__.__name__ == "RequestBudgetExceeded":
                raise
            if self.should_retry(e, attempt):
                delay = self.get_backoff_delay(attempt)
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}). "
                    f"Retrying in {delay:.1f}s... Error: {e}"
                )
                time.sleep(delay)
                return self.execute_with_retry(request_func, attempt + 1)
            else:
                logger.error(f"Request failed after {attempt + 1} attempts: {e}")
                raise

