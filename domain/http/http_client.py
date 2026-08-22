from typing import Optional
from requests import Response

from domain.http.client import HTTPClientProtocol
from domain.http.request_sender import RequestSender
from domain.http.response_evaluator import ResponseEvaluator
from domain.http.retry_policy import RetryPolicy
from domain.http.session_manager import SessionManager


class HTTPClient:
    def __init__(self, timeout: int = 10, max_retries: int = 2, proxy: Optional[str] = None, use_cloudscraper: bool = False, user_agent: Optional[str] = None, verify_ssl: bool = True, max_requests: int = 0):
        self.timeout = timeout
        self.max_retries = max_retries
        self.use_cloudscraper = use_cloudscraper
        self.verify_ssl = verify_ssl


        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session_manager = SessionManager(timeout=timeout, proxy=proxy, use_cloudscraper=use_cloudscraper, user_agent=user_agent, verify_ssl=verify_ssl)
        self.retry_policy = RetryPolicy(max_retries=max_retries)
        self.session = self.session_manager.create_session(max_retries=max_retries)
        self.request_sender = RequestSender(self.session, self.retry_policy, verify_ssl=verify_ssl, max_requests=max_requests)
        self.response_evaluator = ResponseEvaluator()
        self._cloudscraper_session = None

    def _switch_to_cloudscraper(self):
        if self._cloudscraper_session is None:
            try:
                import cloudscraper
                scraper = cloudscraper.create_scraper(
                    browser={
                        'browser': 'chrome',
                        'platform': 'windows',
                        'desktop': True
                    }
                )
                scraper.timeout = self.timeout

                if self.session_manager.proxy:
                    scraper.proxies = {"http": self.session_manager.proxy, "https": self.session_manager.proxy}

                browser_headers = {
                    'User-Agent': self.session_manager.user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                scraper.headers.update(browser_headers)

                self._cloudscraper_session = scraper
                previous_count = self.request_sender.request_count
                self.request_sender = RequestSender(self._cloudscraper_session, self.retry_policy, verify_ssl=self.verify_ssl, max_requests=self.request_sender.max_requests)
                self.request_sender.request_count = previous_count
                self.session = self._cloudscraper_session
                return True
            except ImportError:
                from utils.logging import get_logger
                logger = get_logger()
                logger.warning("cloudscraper not installed. Install it with: pip install cloudscraper")
                self._cloudscraper_session = False
                return False
        return self._cloudscraper_session is not False

    def request(self, method: str, url: str, **kwargs) -> Optional[Response]:
        return self.request_sender.send_request(method, url, timeout=self.timeout, **kwargs)

    def get(self, url: str, **kwargs) -> Optional[Response]:
        return self.request_sender.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[Response]:
        return self.request_sender.post(url, **kwargs)

