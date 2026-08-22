import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Optional, Tuple, List

import requests

from utils.logging import get_logger


logger = get_logger()


class RateLimitAuditor:

    RATE_LIMIT_TEXT_INDICATORS = [
        "too many requests",
        "rate limit",
        "slow down",
        "try again later",
        "request limit",
        "temporarily blocked",
        "temporarily unavailable",
    ]

    CAPTCHA_TEXT_INDICATORS = [
        "captcha",
        "recaptcha",
        "g-recaptcha",
        "hcaptcha",
        "are you human",
        "verify you are human",
    ]

    RATE_LIMIT_HEADER_CANDIDATES = [
        "x-ratelimit-remaining",
        "x-ratelimit-limit",
        "retry-after",
    ]

    def __init__(
        self,
        max_requests: int = 50,
        concurrency: int = 10,
        timeout: int = 10,
        session: Optional[requests.Session] = None,
        verify_ssl: bool = True,
    ) -> None:
        if max_requests <= 0:
            raise ValueError("max_requests must be > 0")
        if concurrency <= 0:
            raise ValueError("concurrency must be > 0")

        self.max_requests = max_requests
        self.concurrency = min(concurrency, max_requests)
        self.timeout = timeout
        self.session = session or self._create_session()
        self.verify_ssl = verify_ssl

    def _create_session(self) -> requests.Session:
        from requests.adapters import HTTPAdapter

        try:
            from urllib3.util.retry import Retry
        except ImportError:  # pragma: no cover - fallback for old environments
            from requests.packages.urllib3.util.retry import Retry  # type: ignore

        session = requests.Session()

        no_retry = Retry(total=0, backoff_factor=0, status_forcelist=())
        adapter = HTTPAdapter(max_retries=no_retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def audit(
        self,
        url: str,
        method: str = "POST",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        method = method.upper()
        if method not in ("GET", "POST"):
            raise ValueError("method must be 'GET' or 'POST'")

        stop_event = threading.Event()
        lock = threading.Lock()

        first_block_request: Optional[int] = None
        total_sent = 0
        exception_count = 0
        status_codes: List[int] = []
        text_indicators_hits = 0
        captcha_hits = 0
        detected_headers: Dict[str, Any] = {}

        start_time = time.time()

        def _record_headers(headers: Dict[str, Any]) -> None:
            nonlocal detected_headers
            for name in self.RATE_LIMIT_HEADER_CANDIDATES:
                if name in headers and name not in detected_headers:
                    detected_headers[name] = headers.get(name)

        def _worker(seq: int) -> Tuple[int, Optional[int]]:
            nonlocal first_block_request, total_sent, exception_count, captcha_hits, text_indicators_hits

            if stop_event.is_set():
                return seq, None

            try:
                if method == "POST":
                    resp = self.session.post(
                        url, data=payload or {}, timeout=self.timeout, allow_redirects=False,
                        verify=self.verify_ssl
                    )
                else:
                    resp = self.session.get(
                        url, params=payload or {}, timeout=self.timeout, allow_redirects=False,
                        verify=self.verify_ssl
                    )

                with lock:
                    total_sent += 1
                    status_codes.append(resp.status_code)

                _record_headers({k.lower(): v for k, v in resp.headers.items()})

                body_lower = resp.text.lower() if resp.text else ""

                if any(ind in body_lower for ind in self.CAPTCHA_TEXT_INDICATORS):
                    with lock:
                        captcha_hits += 1

                if any(ind in body_lower for ind in self.RATE_LIMIT_TEXT_INDICATORS):
                    with lock:
                        text_indicators_hits += 1

                if resp.status_code in (429, 403):
                    with lock:
                        if first_block_request is None:
                            first_block_request = seq
                            logger.warning(
                                f"Rate limit / block detected at request #{seq} "
                                f"(status={resp.status_code})"
                            )
                            stop_event.set()

                return seq, resp.status_code

            except requests.RequestException as e:
                logger.debug(f"Request #{seq} failed during rate limit audit: {e}")
                with lock:
                    total_sent += 1
                    exception_count += 1
                return seq, None

        # Send one extra request for boundary-sensitive implementations that block at N+1.
        total_planned_requests = self.max_requests + 1
        effective_workers = min(self.concurrency, total_planned_requests)

        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            futures = [
                executor.submit(_worker, i + 1) for i in range(total_planned_requests)
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:  # pragma: no cover - defensive
                    logger.debug(f"Unexpected worker error in RateLimitAuditor: {e}")

        duration = time.time() - start_time if total_sent else 0.0
        rps = float(total_sent) / duration if duration > 0 else 0.0

        any_rate_limit_header = bool(detected_headers)
        any_hard_block = first_block_request is not None
        any_rate_limit_code = any(code in (429, 403) for code in status_codes)

        if first_block_request is None and any_rate_limit_code:
            for idx, code in enumerate(status_codes):
                if code in (429, 403):
                    first_block_request = idx + 1
                    break

        exception_ratio = (exception_count / total_sent) if total_sent else 0.0
        exception_storm = exception_ratio >= 0.5 and total_sent >= 10

        captcha_triggered = captcha_hits > 0

        is_vulnerable: bool
        confidence: str

        protection_seen = any_rate_limit_code or any_rate_limit_header or exception_storm or captcha_triggered

        if protection_seen:
            is_vulnerable = False

            if any_rate_limit_code or any_rate_limit_header:
                confidence = "High"
            elif captcha_triggered:
                confidence = "Medium"
            elif exception_storm:
                confidence = "Low"
            else:
                confidence = "Low"
        else:
            is_vulnerable = True
            if total_sent >= total_planned_requests:
                confidence = "High"
            elif total_sent >= total_planned_requests // 2:
                confidence = "Medium"
            else:
                confidence = "Low"

        result: Dict[str, Any] = {
            "is_vulnerable": is_vulnerable,
            "blocked_at_request_count": first_block_request,
            "detected_headers": detected_headers,
            "confidence": confidence,
            "total_requests_sent": total_sent,
            "exceptions": exception_count,
            "rps": round(rps, 2),
            "duration_seconds": round(duration, 2),
            "rate_limit_text_hits": text_indicators_hits,
            "captcha_hits": captcha_hits,
            "status_codes": status_codes,
        }

        return result


if __name__ == "__main__":

    auditor = RateLimitAuditor(max_requests=50, concurrency=10, timeout=10)


    dummy_payload = {"username": "dummy_user", "password": "dummy_pass"}

    target_url = "http://127.0.0.1:5000/lp/rate-limit-login"

    summary = auditor.audit(target_url, method="POST", payload=dummy_payload)

    print("Rate Limit Audit Result:")
    for k, v in summary.items():
        print(f"  {k}: {v}")

