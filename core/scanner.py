from datetime import datetime
from typing import Dict, List, Optional, Any
from tqdm import tqdm

from domain.http import HTTPClient
from domain.auth import CredentialProviderProtocol, DefaultCredentialProvider
from utils.logging import get_logger
from core.form_parser import FormParser, FormData
from core.discovery import LoginPageDiscovery
from core.tester import CredentialTester, InjectionTester
from core.user_enumeration import UsernameEnumerationTester
from core.api_discovery import APIDiscovery
from core.api_tester import APITester
from detection.success import LoginSuccessDetector
from payloads.injections import INJECTION_PAYLOADS
from config.settings import Config
from core.rate_limit_auditor import RateLimitAuditor

logger = get_logger()


class LoginScanner:
    def __init__(self,
                 config: Config,
                 language_keywords: Dict[str, List[str]],
                 credential_provider: Optional[CredentialProviderProtocol] = None):
        self.config = config
        self.language_keywords = language_keywords

        self.client = HTTPClient(
            timeout=config.timeout,
            max_retries=config.max_retries,
            proxy=config.proxy,
            user_agent=config.user_agent,
            verify_ssl=config.verify_ssl
        )


        if not config.verify_ssl:
            logger.warning("⚠ SSL certificate verification disabled (--insecure mode)")

        self.detector = LoginSuccessDetector(
            threshold_low=config.confidence_threshold_low,
            threshold_medium=config.confidence_threshold_medium,
            threshold_high=config.confidence_threshold_high
        )

        self.form_parser = FormParser()
        self.discovery = LoginPageDiscovery(self.client, language_keywords)
        self.credential_tester = CredentialTester(self.client, self.detector)
        self.injection_tester = InjectionTester(self.client, self.detector)
        self.rate_limit_auditor = RateLimitAuditor(
            max_requests=config.rate_limit_requests,
            concurrency=config.rate_limit_threads,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl,
        )
        self.user_enumeration_tester = UsernameEnumerationTester(self.client)
        self.api_discovery = APIDiscovery(self.client)
        self.api_tester = APITester(self.client, self.detector)

        self.credential_provider = credential_provider or DefaultCredentialProvider()


        self._csrf_token = None
        self._csrf_cookies = {}
        self._login_page_url = None

    def _get_payloads_for_api_test(self, injection_type: str) -> List[str]:
        payloads = INJECTION_PAYLOADS.get(injection_type, [])
        if not payloads:
            return []
        # Avoid destructive payloads in auth-bypass checks.
        return [
            p for p in payloads
            if "drop table" not in p.lower() and "truncate" not in p.lower()
        ]

    def _fetch_csrf_token(self, login_page_url: str) -> Optional[str]:
        import re

        try:
            logger.debug(f"[CSRF] Fetching CSRF token from: {login_page_url}")

            response = self.client.get(login_page_url, allow_redirects=True)

            if response is None:
                logger.debug("[CSRF] No response from login page")
                return None


            if hasattr(response, 'cookies'):
                for cookie_name, cookie_value in response.cookies.items():
                    self._csrf_cookies[cookie_name] = cookie_value
                    logger.debug(f"[CSRF] Stored cookie: {cookie_name}={cookie_value[:50]}...")

            html = response.text if response.text else ""


            csrf_patterns = [
                r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
                r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']_token["\']',
                r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
                r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']',
                r'<input[^>]*name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
            ]

            for pattern in csrf_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    logger.debug(f"[CSRF] Found CSRF token: {token[:20]}...")
                    self._csrf_token = token
                    return token


            xsrf_cookie = self._csrf_cookies.get('XSRF-TOKEN')
            if xsrf_cookie:
                import urllib.parse
                token = urllib.parse.unquote(xsrf_cookie)
                logger.debug(f"[CSRF] Found XSRF-TOKEN cookie: {token[:20]}...")
                self._csrf_token = token
                return token

            logger.debug("[CSRF] No CSRF token found")
            return None

        except Exception as e:
            logger.debug(f"[CSRF] Error fetching CSRF token: {e}")
            return None

    def _make_csrf_request(self, endpoint: str, payload: dict, use_json: bool = True) -> Optional[Any]:
        import json as json_lib
        from urllib.parse import urlparse

        headers = {}
        data = None

        if use_json:
            headers['Content-Type'] = 'application/json'
            data = json_lib.dumps(payload)
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

            if self._csrf_token:
                payload = payload.copy()
                payload['_token'] = self._csrf_token
            data = payload


        if self._csrf_token:
            headers['X-CSRF-TOKEN'] = self._csrf_token
            headers['X-XSRF-TOKEN'] = self._csrf_token


        if self._csrf_cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
            headers['Cookie'] = cookie_str


        if self._login_page_url:
            headers['Referer'] = self._login_page_url
            parsed = urlparse(self._login_page_url)
            headers['Origin'] = f"{parsed.scheme}://{parsed.netloc}"

        response = self.client.post(
            endpoint,
            data=data,
            headers=headers,
            allow_redirects=False
        )


        if response is not None and response.status_code == 419:
            logger.debug(f"[CSRF] Got 419, fetching fresh token...")

            if self._login_page_url and self._fetch_csrf_token(self._login_page_url):

                retry_payload = payload.copy() if isinstance(payload, dict) else payload
                if isinstance(retry_payload, dict):
                    retry_payload['_token'] = self._csrf_token

                retry_headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-TOKEN': self._csrf_token,
                    'X-XSRF-TOKEN': self._csrf_token,
                }

                if self._csrf_cookies:
                    retry_headers['Cookie'] = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                if self._login_page_url:
                    retry_headers['Referer'] = self._login_page_url

                response = self.client.post(
                    endpoint,
                    data=retry_payload,
                    headers=retry_headers,
                    allow_redirects=False
                )

                if response is not None:
                    logger.debug(f"[CSRF] Retry response: {response.status_code}")

        return response

    def _is_registration_page(self, url: str, content: Optional[str] = None) -> bool:
        url_lower = url.lower()
        registration_keywords = ['register', 'signup', 'sign-up', 'sign.up', 'signup', 'create.account', 'create-account']

        if any(keyword in url_lower for keyword in registration_keywords):
            return True

        if content:
            content_lower = content.lower()
            registration_indicators = [
                'create account', 'sign up', 'register', 'registration',
                'new account', 'create your account', 'join us', 'signup',
                'confirm password', 'password confirmation'
            ]
            if any(indicator in content_lower for indicator in registration_indicators):
                login_indicators = ['login', 'sign in', 'signin']
                has_login_indicator = any(indicator in content_lower for indicator in login_indicators)
                if not has_login_indicator or content_lower.count('register') > content_lower.count('login'):
                    return True

        return False

    def _test_baseline_login(self, form_data: FormData, url: str,
                            username: str, password: str,
                            success_keywords: List[str], failure_keywords: List[str],
                            original_content_length: int) -> Optional[Dict[str, Any]]:
        try:
            username_field = form_data.username_input.get('name')
            if not username_field:
                username_field = form_data.username_input.get('id')

            password_field = form_data.password_input.get('name')
            if not password_field:
                password_field = form_data.password_input.get('id')

            if not username_field or not password_field:
                logger.warning("Cannot perform baseline login: field names not found")
                return None

            payload_data = {
                username_field: username,
                password_field: password
            }

            if form_data.csrf_input:
                csrf_name = form_data.csrf_input.get('name')
                csrf_value = form_data.csrf_input.get('value')
                if csrf_name and csrf_value:
                    payload_data[csrf_name] = csrf_value

            for other_input in form_data.other_inputs:
                other_name = other_input.get('name')
                other_value = other_input.get('value')
                if other_name:
                    payload_data[other_name] = '' if other_value is None else other_value

            if self.config.http_method == "POST":
                response = self.client.post(form_data.action, data=payload_data, allow_redirects=False)
            else:
                response = self.client.get(form_data.action, params=payload_data, allow_redirects=False)

            if not response:
                return None

            detection_result = self.detector.detect(
                response, url, original_content_length,
                success_keywords, failure_keywords, self.client,
                language_keywords=self.language_keywords
            )



            status_code = response.status_code if hasattr(response, 'status_code') else 0
            headers_dict = {}
            if hasattr(response, 'headers'):
                headers_dict = dict(response.headers)

            logger.info("✓ Test account login treated as successful (forced baseline).")
            logger.info(f"  Raw confidence: {detection_result.confidence_level.value} ({detection_result.confidence_score})")
            if detection_result.confidence_score < self.detector.threshold_medium:
                logger.warning(
                    f"  Warning: detector confidence is below medium threshold "
                    f"({detection_result.confidence_score} < {self.detector.threshold_medium}). "
                    f"Make sure the test account credentials are truly valid."
                )

            if detection_result.details.get("session_cookie_name"):
                logger.info(f"  Session cookie: {detection_result.details.get('session_cookie_name')}")
            if detection_result.details.get("redirect_url"):
                logger.info(f"  Redirect URL: {detection_result.details.get('redirect_url')}")

            return {
                "success": True,
                "confidence_score": detection_result.confidence_score,
                "confidence_level": detection_result.confidence_level.value,
                "status_code": status_code,
                "indicators": detection_result.details.get("indicators", []),
                "redirect_url": detection_result.details.get("redirect_url"),
                "session_cookie": detection_result.details.get("session_cookie_name"),
                "response_length": len(response.text) if hasattr(response, 'text') and response.text else 0,
                "headers": headers_dict
            }
        except Exception as e:
            logger.error(f"Error during baseline login test: {e}")
            return None

    def scan(self,
             url: str,
             credential_provider: Optional[CredentialProviderProtocol] = None) -> Dict[str, Any]:
        start_time = datetime.now()
        results = {
            "url": url,
            "start_time": start_time.isoformat(),
            "tests": {},
            "summary": {}
        }

        try:
            logger.info(f"Starting tests for URL: {url}")

            response = self.client.get(url)
            if response is None:
                logger.error("No response received from server")
                results["error"] = "No response received from server. Possible reasons: SSL certificate issues, firewall/WAF protection (e.g., Cloudflare), network connectivity, or server unreachable."
                return results

            if response.status_code == 403:
                content_lower = response.text.lower() if response.text else ""
                is_cloudflare = 'cloudflare' in content_lower or 'challenge' in content_lower or 'cf-ray' in str(response.headers).lower()
                if is_cloudflare:
                    logger.warning(f"Access forbidden (403) for {url}. Cloudflare protection detected.")
                    logger.info("Attempting to bypass Cloudflare using cloudscraper...")
                    if self.client._switch_to_cloudscraper():
                        response = self.client.get(url)
                        if response and response.status_code == 200:
                            logger.info("Successfully bypassed Cloudflare protection!")
                        elif response and response.status_code != 403:
                            logger.info(f"Cloudflare bypass attempt returned status {response.status_code}")
                        else:
                            logger.warning("Cloudflare bypass failed. Tool will attempt to continue with limited testing.")
                    else:
                        logger.warning("cloudscraper not available. Tool will attempt to continue with limited testing.")
                else:
                    logger.warning(f"Access forbidden (403) for {url}. This might be due to WAF protection or IP blocking.")

                if response and len(response.text) == 0:
                    results["error"] = f"Access forbidden (403) with empty response. Possible WAF protection or IP blocking."
                    results["status_code"] = 403
                    return results

                if response is None:
                    results["error"] = f"Access forbidden (403) with no response. Possible WAF protection or IP blocking."
                    results["status_code"] = 403
                    return results

            if response.status_code == 429:
                logger.warning("Rate limit detected on initial request (429). Skipping all tests for this URL.")
                results["error"] = "Rate limit detected (429) on initial request"
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                results["end_time"] = end_time.isoformat()
                results["duration_seconds"] = duration
                results["summary"] = {
                    "total_requests": 1
                }
                return results

            if response.status_code not in [200, 403]:
                try:
                    response.raise_for_status()
                except Exception as e:
                    raise

            if not hasattr(response, 'text') or not response.text:
                logger.error("Response has no text content")
                results["error"] = "Response has no text content"
                return results

            if self._is_registration_page(url, response.text):
                logger.warning(f"Registration page detected: {url}")
                logger.info("Skipping injection tests on registration pages to avoid false positives.")
                logger.info("Registration pages use different success indicators than login pages.")
                results["note"] = "Registration page detected - injection tests skipped to avoid false positives"
                results["tests"]["registration_page"] = {
                    "status": "Skipped",
                    "reason": "Registration pages use different authentication flow than login pages"
                }
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                results["end_time"] = end_time.isoformat()
                results["duration_seconds"] = duration
                results["summary"] = {
                    "total_requests": 1
                }
                return results

            original_content_length = len(response.text)
            logger.debug(f"Original page content length: {original_content_length} bytes")

            form_data = self.form_parser.parse(
                response.text,
                url,
                use_selenium=self.config.use_selenium,
                selenium_wait_time=self.config.selenium_wait_time,
                user_agent=self.config.user_agent
            )

            if not form_data:
                logger.warning("Login form not found. Attempting alternative detection methods...")

                if not self.config.use_selenium:
                    try:
                        logger.info("Form not found in static HTML. Trying Selenium to render JavaScript (SPA detection)...")
                        form_data = self.form_parser.parse(
                            response.text,
                            url,
                            use_selenium=True,
                            selenium_wait_time=self.config.selenium_wait_time,
                            user_agent=self.config.user_agent
                        )
                        if form_data:
                            logger.info("✓ Form found after Selenium rendering!")
                        else:
                            logger.debug("Form still not found after Selenium rendering.")
                    except Exception as e:
                        logger.debug(f"Selenium auto-detection failed: {e}")
                        logger.info("Tip: Install Selenium and ChromeDriver, then use --use-selenium flag for better SPA support.")

            if not form_data:
                discovered_urls = self.discovery.discover(
                    url,
                    verify=self.config.discovery_verify_pages,
                    verbose=self.config.verbose
                )

                if discovered_urls:
                    logger.info(f"Found {len(discovered_urls)} HTML login page(s)")
                    for discovered_url in discovered_urls:
                        logger.debug(f"Discovered login page: {discovered_url}")

                    results["discovered_pages"] = discovered_urls
                    results["note"] = "Login form not found on main page, but login pages were discovered"
                    return results

                logger.info("No HTML forms found. Attempting to discover API endpoints...")
                json_endpoints = self.api_discovery.discover_json_endpoints(url)
                graphql_endpoints = self.api_discovery.discover_graphql_endpoints(url)

                if json_endpoints or graphql_endpoints:
                    from urllib.parse import urlparse
                    path_hint = (urlparse(url).path or "").lower()
                    prefer_graphql = "graphql" in path_hint
                    prefer_json = "json" in path_hint

                    logger.info(
                        f"Found {len(json_endpoints)} JSON API endpoint(s) and {len(graphql_endpoints)} "
                        f"GraphQL endpoint(s); probing login APIs (use -v on for per-endpoint logs)"
                    )
                    results["api_endpoints"] = {
                        "json": json_endpoints,
                        "graphql": graphql_endpoints
                    }
                    results["note"] = "No HTML forms found, but API endpoints discovered. Testing API endpoints..."

                    provider = credential_provider or self.credential_provider
                    credentials_list = provider.get_credentials()
                    success_keywords = self.language_keywords.get("success", [])
                    failure_keywords = self.language_keywords.get("failure", [])

                    if not prefer_graphql:
                        for endpoint in json_endpoints[:3]:
                            success, credential, details = self.api_tester.test_json_api(
                                endpoint, credentials_list[:5],
                                success_keywords, failure_keywords,
                                original_content_length,
                                self.config.http_method,
                                self.language_keywords,
                                login_page_url=url,
                                verbose=self.config.verbose,
                            )
                            if success:
                                results["tests"]["JSON API Login"] = {
                                    "status": "Successful",
                                    "endpoint": endpoint,
                                    "credential": credential,
                                    "details": details
                                }
                                logger.info(f"✓ JSON API login successful at {endpoint}")

                    if not prefer_json:
                        for endpoint in graphql_endpoints[:2]:
                            success, credential, details = self.api_tester.test_graphql(
                                endpoint, credentials_list[:3],
                                success_keywords, failure_keywords,
                                original_content_length,
                                self.language_keywords,
                                verbose=self.config.verbose,
                            )
                            if success:
                                results["tests"]["GraphQL Login"] = {
                                    "status": "Successful",
                                    "endpoint": endpoint,
                                    "credential": credential,
                                    "details": details
                                }
                                logger.info(f"✓ GraphQL login successful at {endpoint}")

                    if not results.get("tests"):
                        results["note"] = "API endpoints found but login tests were unsuccessful"

                    api_total_requests = 1
                    api_total_requests += len(json_endpoints[:3]) * 5
                    api_total_requests += len(graphql_endpoints[:2]) * 5
                    api_total_requests += len(json_endpoints[:3]) * min(5, len(credentials_list))
                    api_total_requests += len(graphql_endpoints[:2]) * min(3, len(credentials_list))

                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()
                    results["end_time"] = end_time.isoformat()
                    results["duration_seconds"] = duration
                    results["summary"] = {
                        "total_requests": api_total_requests
                    }

                    return results
                else:
                    logger.error("No login form, HTML pages, or API endpoints found.")
                    results["error"] = "No login form, HTML pages, or API endpoints found"
                    return results

            if not form_data.username_input or not form_data.password_input:
                logger.warning("Form found but username/password fields not detected. Trying API endpoints...")

                json_endpoints = self.api_discovery.discover_json_endpoints(url)
                if json_endpoints:
                    logger.info(f"Found {len(json_endpoints)} JSON API endpoint(s) as fallback")
                    results["api_endpoints"] = {"json": json_endpoints}
                    results["note"] = "Form fields not detected, testing API endpoints..."

                    provider = credential_provider or self.credential_provider
                    credentials_list = provider.get_credentials()
                    success_keywords = self.language_keywords.get("success", [])
                    failure_keywords = self.language_keywords.get("failure", [])

                    for endpoint in json_endpoints[:2]:
                        success, credential, details = self.api_tester.test_json_api(
                            endpoint, credentials_list[:3],
                            success_keywords, failure_keywords,
                            original_content_length,
                            self.config.http_method,
                            self.language_keywords,
                            login_page_url=url,
                            verbose=self.config.verbose,
                        )
                        if success:
                            results["tests"]["JSON API Login"] = {
                                "status": "Successful",
                                "endpoint": endpoint,
                                "credential": credential,
                                "details": details
                            }
                            fallback_total_requests = 1
                            fallback_total_requests += len(json_endpoints[:2]) * 5
                            fallback_total_requests += len(json_endpoints[:2]) * min(3, len(credentials_list))

                            end_time = datetime.now()
                            duration = (end_time - start_time).total_seconds()
                            results["end_time"] = end_time.isoformat()
                            results["duration_seconds"] = duration
                            results["summary"] = {
                                "total_requests": fallback_total_requests
                            }
                            return results

                logger.error("Form fields not detected and no API endpoints found.")
                results["error"] = "Form fields not detected and no API endpoints found"
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                results["end_time"] = end_time.isoformat()
                results["duration_seconds"] = duration
                results["summary"] = {
                    "total_requests": 1
                }
                return results

            username_field = form_data.username_input.get('name', 'N/A')
            password_field = form_data.password_input.get('name', 'N/A')

            logger.info(f"Username input found: {username_field}")
            logger.info(f"Password input found: {password_field}")
            logger.debug(f"[DEBUG] Form action URL: {form_data.action}")


            is_spa = self._is_spa_form(
                form_data.action,
                url,
                form_data.csrf_input,
                getattr(form_data, "action_is_implicit", False),
            )
            logger.debug(f"[DEBUG] SPA detection result: {is_spa}")
            if is_spa:
                logger.warning("SPA detected (form action points to client-side route). Attempting API discovery...")
                spa_api_result = self._handle_spa_login(url, form_data, credential_provider, original_content_length, results, start_time)
                if spa_api_result:
                    return spa_api_result
                logger.warning("API discovery failed for SPA. Falling back to form-based testing (may not work).")

            csrf_found = form_data.csrf_input is not None
            if csrf_found:
                logger.info("CSRF token found")
            else:
                logger.warning("CSRF token not found. The form might be vulnerable to CSRF attacks.")

            captcha_found = form_data.captcha_input is not None
            if captcha_found:
                logger.warning("⚠ CAPTCHA detected! Automated testing may be limited. Manual verification recommended.")
                results["captcha_detected"] = True
                results["captcha_warning"] = "CAPTCHA protection detected. Some tests may fail or be skipped."
            else:
                logger.info("No CAPTCHA detected")
                results["captcha_detected"] = False

            results["form_info"] = {
                "username_field": username_field,
                "password_field": password_field,
                "csrf_found": csrf_found,
                "csrf_field": form_data.csrf_input.get('name') if form_data.csrf_input else None,
                "captcha_found": captcha_found
            }

            try:
                self._perform_invalid_login_probe(form_data, url)
            except Exception as e:
                logger.debug(f"Failed to perform invalid login probe: {e}")

            success_keywords = self.language_keywords.get("success", [])
            failure_keywords = self.language_keywords.get("failure", [])

            baseline_result = None
            if self.config.test_account_username and self.config.test_account_password:
                logger.info(f"Test account found: Attempting login with {self.config.test_account_username}...")
                baseline_result = self._test_baseline_login(
                    form_data, url,
                    self.config.test_account_username,
                    self.config.test_account_password,
                    success_keywords, failure_keywords,
                    original_content_length
                )
                if baseline_result and baseline_result.get("success"):
                    results["baseline_login"] = baseline_result
                    logger.info("  Using this as reference for confidence scoring.")
                else:
                    if baseline_result:
                        reason = baseline_result.get("reason", "Unknown")
                        logger.warning(f"Baseline login failed: {reason}")
                        logger.info("  Continuing with normal testing...")
                    else:
                        logger.warning("Baseline login failed. Continuing with normal testing...")

            provider = credential_provider or self.credential_provider
            credentials_list = provider.get_credentials()

            if provider.is_empty():
                logger.warning("No credentials available for testing")

            total_payloads = sum(len(payloads) for payloads in INJECTION_PAYLOADS.values())

            total_tests = total_payloads + len(credentials_list)

            pbar = None
            if self.config.show_progress:
                pbar = tqdm(total=total_tests, desc="Testing", unit="test", disable=False)

            if not captcha_found:
                enum_vulnerable, enum_username, enum_details = self.user_enumeration_tester.test(
                    form_data, url,
                    test_usernames=None,
                    http_method=self.config.http_method,
                    language_keywords=self.language_keywords
                )
                if enum_vulnerable:
                    results["username_enumeration"] = {
                        "vulnerable": True,
                        "details": enum_details
                    }
                    logger.warning(f"⚠ Username enumeration vulnerability detected! "
                                 f"Test username: {enum_username}")
                else:
                    results["username_enumeration"] = {
                        "vulnerable": False
                    }
            else:
                logger.info("Skipping username enumeration test (CAPTCHA detected)")
                results["username_enumeration"] = {
                    "vulnerable": None,
                    "skipped": True,
                    "reason": "CAPTCHA detected"
                }

            cred_success, cred_rate_limit, successful_cred, cred_details = self.credential_tester.test(
                form_data, url, credentials_list,
                success_keywords, failure_keywords,
                self.config.http_method, original_content_length,
                self.config.verbose, pbar,
                language_keywords=self.language_keywords,
                baseline_result=baseline_result
            )

            if cred_success:
                results["tests"]["Default Credentials"] = {
                    "status": "Successful",
                    "credential": successful_cred,
                    "confidence_score": cred_details.get("confidence_score", 0) if cred_details else 0,
                    "confidence_level": cred_details.get("confidence_level", "Unknown") if cred_details else "Unknown",
                    "manual_verification_recommended": cred_details.get("manual_verification_recommended", False) if cred_details else False,
                    "details": cred_details
                }
            else:
                results["tests"]["Default Credentials"] = {
                    "status": "Failed",
                    "rate_limited_at": cred_rate_limit
                }

            for injection_type, payloads in INJECTION_PAYLOADS.items():
                success, payload, details, rate_limited_at = self.injection_tester.test(
                    form_data, url, injection_type, payloads,
                    success_keywords, failure_keywords,
                    self.config.http_method, original_content_length,
                    self.config.verbose, pbar,
                    nosql_progressive_mode=getattr(self.config, 'nosql_progressive_mode', True),
                    nosql_admin_patterns=getattr(self.config, 'nosql_admin_patterns', None),
                    language_keywords=self.language_keywords,
                    baseline_result=baseline_result,
                    scan_mode=self.config.scan_mode
                )

                if success:
                    results["tests"][injection_type] = {
                        "status": "Successful",
                        "payload": payload,
                        "confidence_score": details.get("confidence_score", 0),
                        "confidence_level": details.get("confidence_level", "Unknown"),
                        "manual_verification_recommended": details.get("manual_verification_recommended", False),
                        "details": details
                    }
                else:
                    results["tests"][injection_type] = {
                        "status": "Failed",
                        "rate_limited_at": rate_limited_at
                    }

            try:
                if self.config.rate_limit_requests > 0:
                    logger.info(f"Testing rate limiting (sending {self.config.rate_limit_requests} requests)...")
                    rl_payload = {}
                    username_field = form_data.username_input.get('name') if form_data.username_input else None
                    if not username_field and form_data.username_input:
                        username_field = form_data.username_input.get('id')
                    password_field = form_data.password_input.get('name') if form_data.password_input else None
                    if not password_field and form_data.password_input:
                        password_field = form_data.password_input.get('id')

                    if username_field and password_field:
                        import uuid
                        suffix = uuid.uuid4().hex[:8]
                        rl_payload = {
                            username_field: f"htlogin_ratelimit_user_{suffix}",
                            password_field: f"htlogin_ratelimit_pass_{suffix}",
                        }

                    rl_result = self.rate_limit_auditor.audit(
                        url,
                        method=self.config.http_method,
                        payload=rl_payload or None,
                    )

                    if rl_result.get("is_vulnerable"):
                        status_text = f"No rate limit after {rl_result.get('total_requests_sent', 0)} requests"
                        logger.warning(f"⚠ Rate limit test: {status_text}")
                    else:
                        blocked_at = rl_result.get("blocked_at_request_count")
                        if blocked_at:
                            status_text = f"Rate limited at request #{blocked_at}"
                        else:
                            status_text = "Rate limiting detected"
                        logger.info(f"✓ Rate limit test: {status_text}")

                    results["tests"]["Rate Limit Test"] = {
                        "status": status_text,
                        "details": rl_result,
                    }
            except Exception as e:
                logger.debug(f"Error during rate limit audit: {e}")

            if pbar:
                pbar.close()

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            results["end_time"] = end_time.isoformat()
            results["duration_seconds"] = duration

            successful_tests = [k for k, v in results["tests"].items()
                              if v.get("status") == "Successful"]

            total_requests = 1

            if self.config.test_account_username and self.config.test_account_password:
                total_requests += 1

            if not captcha_found:
                total_requests += min(5, len(self.user_enumeration_tester.USERNAME_NOT_FOUND_INDICATORS) if hasattr(self.user_enumeration_tester, 'USERNAME_NOT_FOUND_INDICATORS') else 5)

            total_requests += total_payloads
            total_requests += len(credentials_list)

            if self.config.rate_limit_requests > 0 and "Rate Limit Test" in results.get("tests", {}):
                rl_details = results["tests"]["Rate Limit Test"].get("details", {})
                rl_requests_sent = rl_details.get("total_requests_sent", 0)
                if rl_requests_sent > 0:
                    total_requests += rl_requests_sent

            results["summary"] = {
                "total_tests": len(results["tests"]),
                "successful": len(successful_tests),
                "failed": len(results["tests"]) - len(successful_tests),
                "successful_tests": successful_tests,
                "duration_seconds": duration,
                "total_requests": total_requests
            }

            return results

        except KeyError as e:
            logger.error(f"Key error: {e}")
            results["error"] = f"Missing required data: {str(e)}"
            return results
        except AttributeError as e:
            logger.error(f"Attribute error: {e}")
            results["error"] = f"Invalid object attribute: {str(e)}"
            return results
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}", exc_info=True)
            results["error"] = f"Unexpected error: {str(e)}"
            return results

    def _is_spa_form(
        self,
        action: str,
        original_url: str,
        csrf_input=None,
        action_is_implicit: bool = False,
    ) -> bool:
        logger.debug(
            f"[DEBUG] _is_spa_form checking: action='{action}', original_url='{original_url}', "
            f"action_is_implicit={action_is_implicit}"
        )

        if not action:
            return False



        if action_is_implicit and "#/" not in original_url and "#!" not in original_url:
            logger.debug("[DEBUG] Not a SPA: implicit form action without hash-routed URL")
            return False


        if csrf_input is not None:
            csrf_name = csrf_input.get('name', '').lower() if hasattr(csrf_input, 'get') else ''

            if csrf_name in ['__requestverificationtoken', '_token']:
                logger.debug(f"[DEBUG] Not a SPA: Server-side CSRF token found ({csrf_name})")
                return False


        if '#/' in action or '#!' in action:
            logger.debug(f"[DEBUG] SPA detected via hash routing in action")
            return True


        if '#/' in original_url or '#!' in original_url:
            logger.debug(f"[DEBUG] SPA detected via hash routing in original URL")
            return True


        from urllib.parse import urlparse
        action_parsed = urlparse(action)
        original_parsed = urlparse(original_url)


        if (action_parsed.path == original_parsed.path and
            action_parsed.netloc == original_parsed.netloc):
            logger.debug(f"[DEBUG] SPA detected: action URL same as original")
            return True

        return False

    def _handle_spa_login(self, url: str, form_data, credential_provider,
                         original_content_length: int, results: dict,
                         start_time) -> Optional[dict]:
        from datetime import datetime


        self._login_page_url = url


        logger.debug("[CSRF] Pre-fetching CSRF token for SPA testing...")
        self._fetch_csrf_token(url)

        json_endpoints = self.api_discovery.discover_json_endpoints(url)
        graphql_endpoints = self.api_discovery.discover_graphql_endpoints(url)

        if not json_endpoints and not graphql_endpoints:
            logger.warning("No API endpoints discovered for SPA")
            return None

        logger.info(
            f"Found {len(json_endpoints)} JSON API and {len(graphql_endpoints)} GraphQL endpoints for SPA "
            f"(use -v on for per-endpoint logs)"
        )
        results["spa_detected"] = True
        results["api_endpoints"] = {
            "json": json_endpoints,
            "graphql": graphql_endpoints
        }

        provider = credential_provider or self.credential_provider
        credentials_list = provider.get_credentials()
        success_keywords = self.language_keywords.get("success", [])
        failure_keywords = self.language_keywords.get("failure", [])


        username_field_name = None
        password_field_name = None
        if form_data.username_input:
            username_field_name = form_data.username_input.get('name') or form_data.username_input.get('id')
        if form_data.password_input:
            password_field_name = form_data.password_input.get('name') or form_data.password_input.get('id')

        spa_captcha_found = form_data.captcha_input is not None

        working_endpoint = None
        total_requests = 1


        def prioritize_endpoints(endpoints):
            priority_order = [
                '/rest/user/', '/rest/', '/api/user/', '/api/auth/',
                '/api/v1/', '/api/v2/', '/api/', '/auth/', '/user/'
            ]

            def get_priority(ep):
                for i, pattern in enumerate(priority_order):
                    if pattern in ep:
                        return i
                return len(priority_order)

            return sorted(endpoints, key=get_priority)

        prioritized_endpoints = prioritize_endpoints(json_endpoints)
        logger.debug(f"[DEBUG] Prioritized endpoints (first 10): {prioritized_endpoints[:10]}")


        logger.info("Testing Default Credentials on API endpoints...")
        for endpoint in prioritized_endpoints[:10]:
            if self.config.verbose:
                logger.info(f"Testing SPA JSON API endpoint: {endpoint}")
            success, credential, details = self.api_tester.test_json_api(
                endpoint, credentials_list,
                success_keywords, failure_keywords,
                original_content_length,
                self.config.http_method,
                self.language_keywords,
                username_field=username_field_name,
                password_field=password_field_name,
                login_page_url=url,
                verbose=self.config.verbose,
            )
            total_requests += len(credentials_list)

            if success:
                results["tests"]["Default Credentials"] = {
                    "status": "Successful",
                    "endpoint": endpoint,
                    "credential": credential,
                    "confidence_score": 100,
                    "confidence_level": "High",
                    "details": details
                }
                working_endpoint = endpoint
                break

        if not working_endpoint and prioritized_endpoints:

            working_endpoint = prioritized_endpoints[0]
            results["tests"]["Default Credentials"] = {
                "status": "Failed",
                "note": "No default credentials worked",
                "confidence_score": 0,
                "confidence_level": "Low"
            }

        logger.debug(f"[DEBUG] Working endpoint for further tests: {working_endpoint}")

        if working_endpoint and not spa_captcha_found:
            api_user_field = username_field_name or "email"
            api_pass_field = password_field_name or "password"
            enum_vulnerable, enum_username, enum_details = self.user_enumeration_tester.test_json_api(
                working_endpoint,
                api_user_field,
                api_pass_field,
                language_keywords=self.language_keywords,
                post_json=lambda ep, pl: self._make_csrf_request(ep, pl, use_json=True),
            )
            total_requests += 5
            if enum_vulnerable:
                results["username_enumeration"] = {
                    "vulnerable": True,
                    "details": enum_details,
                }
                logger.warning(
                    f"⚠ Username enumeration vulnerability detected! Test username: {enum_username}"
                )
            else:
                results["username_enumeration"] = {"vulnerable": False}
        elif working_endpoint and spa_captcha_found:
            logger.info("Skipping username enumeration test (CAPTCHA detected)")
            results["username_enumeration"] = {
                "vulnerable": None,
                "skipped": True,
                "reason": "CAPTCHA detected",
            }


        if working_endpoint:
            logger.info("Testing SQL Injection on API endpoints...")
            sql_result = self._test_api_sql_injection(
                working_endpoint, username_field_name, password_field_name,
                success_keywords, failure_keywords, original_content_length
            )
            total_requests += 10

            sql_result["endpoint"] = working_endpoint
            sql_result["severity"] = "High" if sql_result["status"] == "Successful" else "Info"
            results["tests"]["SQL Injection"] = sql_result


        if working_endpoint:
            logger.info("Testing NoSQL Injection on API endpoints...")
            nosql_result = self._test_api_nosql_injection(
                working_endpoint, username_field_name, password_field_name,
                success_keywords, failure_keywords, original_content_length
            )
            total_requests += 15

            nosql_result["endpoint"] = working_endpoint
            nosql_result["severity"] = "High" if nosql_result["status"] == "Successful" else "Info"
            results["tests"]["NoSQL Injection"] = nosql_result


        if working_endpoint:
            logger.info("Testing XPath Injection on API endpoints...")
            xpath_result = self._test_api_xpath_injection(
                working_endpoint, username_field_name, password_field_name,
                success_keywords, failure_keywords, original_content_length
            )
            total_requests += 13

            xpath_result["endpoint"] = working_endpoint
            xpath_result["severity"] = "High" if xpath_result["status"] == "Successful" else "Info"
            results["tests"]["XPath Injection"] = xpath_result


        if working_endpoint:
            logger.info("Testing LDAP Injection on API endpoints...")
            ldap_result = self._test_api_ldap_injection(
                working_endpoint, username_field_name, password_field_name,
                success_keywords, failure_keywords
            )
            total_requests += 10

            ldap_result["endpoint"] = working_endpoint
            ldap_result["severity"] = "High" if ldap_result["status"] == "Successful" else "Info"
            results["tests"]["LDAP Injection"] = ldap_result


        if working_endpoint and self.config.rate_limit_requests > 0:
            logger.info(f"Testing Rate Limiting on API endpoint (sending {self.config.rate_limit_requests} requests)...")
            rate_limit_result = self._test_api_rate_limit(
                working_endpoint, username_field_name, password_field_name,
                self.config.rate_limit_requests
            )
            total_requests += self.config.rate_limit_requests

            results["tests"]["Rate Limit Test"] = rate_limit_result

        spa_username_display = (
            form_data.username_input.get("name", "N/A") if form_data.username_input else "N/A"
        )
        spa_password_display = (
            form_data.password_input.get("name", "N/A") if form_data.password_input else "N/A"
        )
        spa_csrf_found = form_data.csrf_input is not None
        if spa_captcha_found:
            results["captcha_detected"] = True
            results["captcha_warning"] = (
                "CAPTCHA protection detected. Some tests may fail or be skipped."
            )
        else:
            results["captcha_detected"] = False
        results["form_info"] = {
            "username_field": spa_username_display,
            "password_field": spa_password_display,
            "csrf_found": spa_csrf_found,
            "csrf_field": form_data.csrf_input.get("name") if form_data.csrf_input else None,
            "captcha_found": spa_captcha_found,
        }


        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = duration

        successful_tests = [k for k, v in results["tests"].items()
                          if v.get("status") == "Successful"]

        results["summary"] = {
            "total_tests": len(results["tests"]),
            "successful": len(successful_tests),
            "failed": len(results["tests"]) - len(successful_tests),
            "successful_tests": successful_tests,
            "total_requests": total_requests
        }

        return results

    def _test_api_sql_injection(self, endpoint: str, username_field: str,
                                password_field: str, success_keywords: list,
                                failure_keywords: list, original_content_length: int) -> dict:
        sql_payloads = self._get_payloads_for_api_test("SQL Injection")

        result = {
            "status": "Failed",
            "successful_payloads": [],
            "error_disclosures": [],
            "confidence_score": 0,
            "confidence_level": "Low"
        }

        is_full_mode = self.config.scan_mode == 'full'
        _emit = logger.info if self.config.verbose else logger.debug

        logger.debug(f"[SQL] Testing {len(sql_payloads)} SQL injection payloads on {endpoint}")
        logger.debug(f"[SQL] Mode: {'full (test all)' if is_full_mode else 'quick (stop at first success)'}")

        for idx, payload in enumerate(sql_payloads, 1):
            try:
                data = {
                    username_field or 'email': payload,
                    password_field or 'password': payload
                }

                logger.debug(f"[SQL] [{idx}/{len(sql_payloads)}] Testing payload: {payload}")


                response = self._make_csrf_request(endpoint, data, use_json=True)

                if response is None:
                    logger.debug(f"[SQL] [{idx}] No response received")
                    continue

                response_text = response.text.lower() if response.text else ""
                response_preview = response.text[:200] if response.text else "(empty)"

                logger.debug(f"[SQL] [{idx}] Status: {response.status_code}, Length: {len(response.text) if response.text else 0}")
                logger.debug(f"[SQL] [{idx}] Response preview: {response_preview}")


                if response.status_code in [200, 302]:


                    success_indicators = ['token', 'session', 'authentication', 'success', 'welcome']
                    found_success = [kw for kw in success_indicators if kw.lower() in response_text]
                    found_failure = [kw for kw in failure_keywords if kw.lower() in response_text]

                    logger.debug(f"[SQL] [{idx}] Success indicators found: {found_success}")
                    logger.debug(f"[SQL] [{idx}] Failure indicators found: {found_failure}")

                    if found_success and not found_failure:
                        _emit(f"✓ SQL Injection successful with payload: {payload[:30]}...")
                        logger.debug(f"[SQL] [{idx}] ✓ AUTH BYPASS DETECTED!")
                        result["successful_payloads"].append(payload)
                        result["status"] = "Successful"
                        result["confidence_score"] = 100
                        result["confidence_level"] = "High"
                        if not is_full_mode:
                            return result
                        continue


                    sql_errors = ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'oracle', 'mssql']
                    found_errors = [err for err in sql_errors if err in response_text]

                    if found_errors:
                        _emit(f"✓ SQL error disclosure detected with payload: {payload[:30]}...")
                        logger.debug(f"[SQL] [{idx}] ✓ ERROR DISCLOSURE: {found_errors}")
                        result["error_disclosures"].append(payload)
                        result["status"] = "Successful"
                        result["confidence_score"] = 90
                        result["confidence_level"] = "High"
                        if not is_full_mode:
                            return result

            except Exception as e:
                logger.debug(f"Error testing SQL injection: {e}")
                continue

        if result["successful_payloads"] or result["error_disclosures"]:
            total_found = len(result["successful_payloads"]) + len(result["error_disclosures"])
            logger.info(f"✓ SQL Injection: {total_found} vulnerable payload(s) found")
        if result.get("successful_payloads"):
            result["payload"] = result["successful_payloads"][0]
        elif result.get("error_disclosures"):
            result["payload"] = result["error_disclosures"][0]

        return result

    def _test_api_nosql_injection(self, endpoint: str, username_field: str,
                                  password_field: str, success_keywords: list,
                                  failure_keywords: list, original_content_length: int) -> dict:
        import json as json_lib

        user_field = username_field or 'email'
        pass_field = password_field or 'password'
        safe_pass = "htlogin_nosql_pass"

        # WSTG-aligned split: syntax injection first, then operator injection.
        phase_payloads = {
            "syntax_injection": [
                ({user_field: '{"$ne":""}', pass_field: safe_pass}, "json-string-$ne"),
                ({user_field: '{"$regex":".*"}', pass_field: safe_pass}, "json-string-$regex"),
                ({user_field: '{"$gt":""}', pass_field: safe_pass}, "json-string-$gt"),
            ],
            "operator_injection": [
                ({user_field: {"$ne": ""}, pass_field: {"$ne": ""}}, "operator-$ne"),
                ({user_field: {"$gt": ""}, pass_field: {"$gt": ""}}, "operator-$gt"),
                ({user_field: {"$regex": ".*"}, pass_field: {"$regex": ".*"}}, "operator-$regex"),
                ({user_field: "admin", pass_field: {"$ne": ""}}, "admin-plus-operator"),
                ({user_field: {"$exists": True}, pass_field: {"$exists": True}}, "operator-$exists"),
            ],
        }

        result = {
            "status": "Failed",
            "successful_payloads": [],
            "error_disclosures": [],
            "confidence_score": 0,
            "confidence_level": "Low",
            "phase_results": {},
        }

        is_full_mode = self.config.scan_mode == 'full'
        _emit = logger.info if self.config.verbose else logger.debug

        total_payloads = sum(len(v) for v in phase_payloads.values())
        logger.debug(f"[NoSQL] Testing {total_payloads} NoSQL injection payloads on {endpoint}")
        logger.debug(f"[NoSQL] Mode: {'full (test all)' if is_full_mode else 'quick (stop at first success)'}")

        global_idx = 0
        for phase_name, payloads in phase_payloads.items():
            phase_success_count = 0
            phase_error_count = 0
            logger.debug(f"[NoSQL] Starting phase: {phase_name} ({len(payloads)} payloads)")
            for payload_data, payload_type in payloads:
                global_idx += 1
                try:
                    logger.debug(f"[NoSQL] [{global_idx}/{total_payloads}] Testing payload: {payload_type}")
                    logger.debug(f"[NoSQL] [{global_idx}] Payload data: {json_lib.dumps(payload_data)}")


                    response = self._make_csrf_request(endpoint, payload_data, use_json=True)

                    if response is None:
                        logger.debug(f"[NoSQL] [{global_idx}] No response received")
                        continue

                    response_text = response.text.lower() if response.text else ""
                    response_preview = response.text[:200] if response.text else "(empty)"

                    logger.debug(f"[NoSQL] [{global_idx}] Status: {response.status_code}, Length: {len(response.text) if response.text else 0}")
                    logger.debug(f"[NoSQL] [{global_idx}] Response preview: {response_preview}")


                    if response.status_code in [200, 302]:
                        success_indicators = ['token', 'session', 'authentication', 'success']
                        found_success = [kw for kw in success_indicators if kw.lower() in response_text]
                        found_failure = [kw for kw in failure_keywords if kw.lower() in response_text]

                        logger.debug(f"[NoSQL] [{global_idx}] Success indicators found: {found_success}")
                        logger.debug(f"[NoSQL] [{global_idx}] Failure indicators found: {found_failure}")

                        if found_success and not found_failure:
                            _emit(f"✓ NoSQL Injection successful with {payload_type} payload")
                            logger.debug(f"[NoSQL] [{global_idx}] ✓ AUTH BYPASS DETECTED!")
                            result["successful_payloads"].append(f"{phase_name}:{payload_type}")
                            result["status"] = "Successful"
                            result["confidence_score"] = 100
                            result["confidence_level"] = "High"
                            phase_success_count += 1
                            if not is_full_mode:
                                result["phase_results"][phase_name] = {
                                    "successes": phase_success_count,
                                    "error_disclosures": phase_error_count,
                                }
                                return result
                            continue


                    mongo_errors = ['mongodb', 'mongoose', 'bson', 'objectid', '$where', '$gt', '$ne']
                    found_errors = [err for err in mongo_errors if err in response_text]

                    if found_errors:
                        _emit("✓ NoSQL error disclosure detected")
                        logger.debug(f"[NoSQL] [{global_idx}] ✓ ERROR DISCLOSURE: {found_errors}")
                        result["error_disclosures"].append(f"{phase_name}:{payload_type}")
                        result["status"] = "Successful"
                        result["confidence_score"] = 90
                        result["confidence_level"] = "High"
                        phase_error_count += 1
                        if not is_full_mode:
                            result["phase_results"][phase_name] = {
                                "successes": phase_success_count,
                                "error_disclosures": phase_error_count,
                            }
                            return result

                except Exception as e:
                    logger.debug(f"Error testing NoSQL injection ({phase_name}/{payload_type}): {e}")
                    continue

            result["phase_results"][phase_name] = {
                "successes": phase_success_count,
                "error_disclosures": phase_error_count,
            }

        if result["successful_payloads"] or result["error_disclosures"]:
            total_found = len(result["successful_payloads"]) + len(result["error_disclosures"])
            logger.info(f"✓ NoSQL Injection: {total_found} vulnerable payload(s) found")
        if result.get("successful_payloads"):
            result["payload"] = str(result["successful_payloads"][0])
        elif result.get("error_disclosures"):
            result["payload"] = str(result["error_disclosures"][0])

        return result

    def _test_api_ldap_injection(self, endpoint: str, username_field: str,
                                 password_field: str, success_keywords: list,
                                 failure_keywords: list) -> dict:
        ldap_payloads = [
            (payload, f"payload_{i + 1}")
            for i, payload in enumerate(self._get_payloads_for_api_test("LDAP Injection"))
        ]

        result = {
            "status": "Failed",
            "successful_payloads": [],
            "error_disclosures": [],
            "confidence_score": 0,
            "confidence_level": "Low"
        }

        is_full_mode = self.config.scan_mode == 'full'
        _emit = logger.info if self.config.verbose else logger.debug

        logger.debug(f"[LDAP] Testing {len(ldap_payloads)} LDAP injection payloads on {endpoint}")
        logger.debug(f"[LDAP] Mode: {'full (test all)' if is_full_mode else 'quick (stop at first success)'}")

        for idx, (payload, payload_name) in enumerate(ldap_payloads, 1):
            try:

                data = {
                    username_field or 'email': payload,
                    password_field or 'password': 'test'
                }

                logger.debug(f"[LDAP] [{idx}/{len(ldap_payloads)}] Testing payload: {payload_name}")
                logger.debug(f"[LDAP] [{idx}] Payload value: {payload}")


                response = self._make_csrf_request(endpoint, data, use_json=True)

                if response is None:
                    logger.debug(f"[LDAP] [{idx}] No response received")
                    continue

                response_text = response.text.lower() if response.text else ""
                response_preview = response.text[:200] if response.text else "(empty)"

                logger.debug(f"[LDAP] [{idx}] Status: {response.status_code}, Length: {len(response.text) if response.text else 0}")
                logger.debug(f"[LDAP] [{idx}] Response preview: {response_preview}")


                if response.status_code in [200, 302]:
                    success_indicators = ['token', 'session', 'authentication', 'success']
                    found_success = [kw for kw in success_indicators if kw.lower() in response_text]
                    found_failure = [kw for kw in failure_keywords if kw.lower() in response_text]

                    logger.debug(f"[LDAP] [{idx}] Success indicators found: {found_success}")
                    logger.debug(f"[LDAP] [{idx}] Failure indicators found: {found_failure}")

                    if found_success and not found_failure:
                        _emit(f"✓ LDAP Injection successful with {payload_name} payload")
                        logger.debug(f"[LDAP] [{idx}] ✓ AUTH BYPASS DETECTED!")
                        result["successful_payloads"].append(payload_name)
                        result["status"] = "Successful"
                        result["confidence_score"] = 100
                        result["confidence_level"] = "High"
                        if not is_full_mode:
                            return result
                        continue


                ldap_errors = [
                    'ldap', 'invalid dn', 'bad search filter', 'javax.naming',
                    'ldapexception', 'invalid filter', 'search filter',
                    'ldap_search', 'ldap_bind', 'ldap_connect', 'active directory',
                    'invalid syntax', 'filter error', 'ldap error'
                ]
                found_errors = [err for err in ldap_errors if err in response_text]

                if found_errors:
                    _emit(f"✓ LDAP error disclosure detected with {payload_name}")
                    logger.debug(f"[LDAP] [{idx}] ✓ ERROR DISCLOSURE: {found_errors}")
                    result["error_disclosures"].append(payload_name)
                    result["status"] = "Successful"
                    result["confidence_score"] = 90
                    result["confidence_level"] = "High"
                    if not is_full_mode:
                        return result

            except Exception as e:
                logger.debug(f"Error testing LDAP injection: {e}")
                continue

        if result["successful_payloads"] or result["error_disclosures"]:
            total_found = len(result["successful_payloads"]) + len(result["error_disclosures"])
            logger.info(f"✓ LDAP Injection: {total_found} vulnerable payload(s) found")
        if result.get("successful_payloads"):
            result["payload"] = result["successful_payloads"][0]
        elif result.get("error_disclosures"):
            result["payload"] = result["error_disclosures"][0]

        return result

    def _test_api_xpath_injection(self, endpoint: str, username_field: str,
                                  password_field: str, success_keywords: list,
                                  failure_keywords: list, original_content_length: int) -> dict:
        xpath_payloads = self._get_payloads_for_api_test("XPath Injection")

        result = {
            "status": "Failed",
            "successful_payloads": [],
            "error_disclosures": [],
            "confidence_score": 0,
            "confidence_level": "Low"
        }

        is_full_mode = self.config.scan_mode == 'full'
        _emit = logger.info if self.config.verbose else logger.debug

        logger.debug(f"[XPATH] Testing {len(xpath_payloads)} XPath injection payloads on {endpoint}")
        logger.debug(f"[XPATH] Mode: {'full (test all)' if is_full_mode else 'quick (stop at first success)'}")

        for idx, payload in enumerate(xpath_payloads, 1):
            try:
                data = {
                    username_field or 'email': payload,
                    password_field or 'password': payload
                }

                logger.debug(f"[XPATH] [{idx}/{len(xpath_payloads)}] Testing payload: {payload}")

                response = self._make_csrf_request(endpoint, data, use_json=True)

                if response is None:
                    logger.debug(f"[XPATH] [{idx}] No response received")
                    continue

                response_text = response.text.lower() if response.text else ""
                response_preview = response.text[:200] if response.text else "(empty)"

                logger.debug(f"[XPATH] [{idx}] Status: {response.status_code}, Length: {len(response.text) if response.text else 0}")
                logger.debug(f"[XPATH] [{idx}] Response preview: {response_preview}")

                if response.status_code in [200, 302]:
                    success_indicators = ['token', 'session', 'authentication', 'success', 'welcome']
                    found_success = [kw for kw in success_indicators if kw.lower() in response_text]
                    found_failure = [kw for kw in failure_keywords if kw.lower() in response_text]

                    logger.debug(f"[XPATH] [{idx}] Success indicators found: {found_success}")
                    logger.debug(f"[XPATH] [{idx}] Failure indicators found: {found_failure}")

                    if found_success and not found_failure:
                        _emit(f"✓ XPath Injection successful with payload: {payload[:30]}...")
                        logger.debug(f"[XPATH] [{idx}] ✓ AUTH BYPASS DETECTED!")
                        result["successful_payloads"].append(payload)
                        result["status"] = "Successful"
                        result["confidence_score"] = 100
                        result["confidence_level"] = "High"
                        if not is_full_mode:
                            return result
                        continue

                xpath_errors = [
                    'xpath', 'xpath exception', 'xpath syntax', 'invalid predicate',
                    'invalid expression', 'xml path', 'xpath evaluation', 'libxml',
                    'xml parser', 'xpathexpression', 'unknown function', 'invalid token'
                ]
                found_errors = [err for err in xpath_errors if err in response_text]

                if found_errors:
                    _emit(f"✓ XPath error disclosure detected with payload: {payload[:30]}...")
                    logger.debug(f"[XPATH] [{idx}] ✓ ERROR DISCLOSURE: {found_errors}")
                    result["error_disclosures"].append(payload)
                    result["status"] = "Successful"
                    result["confidence_score"] = 90
                    result["confidence_level"] = "High"
                    if not is_full_mode:
                        return result

            except Exception as e:
                logger.debug(f"Error testing XPath injection: {e}")
                continue

        if result["successful_payloads"] or result["error_disclosures"]:
            total_found = len(result["successful_payloads"]) + len(result["error_disclosures"])
            logger.info(f"✓ XPath Injection: {total_found} vulnerable payload(s) found")
        if result.get("successful_payloads"):
            result["payload"] = result["successful_payloads"][0]
        elif result.get("error_disclosures"):
            result["payload"] = result["error_disclosures"][0]

        return result

    def _test_api_rate_limit(self, endpoint: str, username_field: str,
                            password_field: str, num_requests: int) -> dict:
        import json as json_lib
        import time

        result = {
            "status": "Failed",
            "details": {}
        }

        test_data = {
            username_field or 'email': 'ratelimit_test@test.com',
            password_field or 'password': 'ratelimit_test_password'
        }

        rate_limited = False
        rate_limited_at = None
        response_times = []

        logger.debug(f"[RATE] Testing rate limiting with {num_requests} requests on {endpoint}")
        logger.debug(f"[RATE] Test credentials: {test_data}")

        for i in range(num_requests):
            try:
                start_time = time.time()


                response = self._make_csrf_request(endpoint, test_data, use_json=True)

                elapsed = time.time() - start_time
                response_times.append(elapsed)

                if response is not None:

                    logger.debug(f"[RATE] Request {i+1}/{num_requests}: Status={response.status_code}, Time={elapsed:.3f}s")


                    rate_headers_found = []
                    rate_headers = ['x-ratelimit-remaining', 'x-rate-limit-remaining',
                                   'ratelimit-remaining', 'retry-after', 'x-ratelimit-limit']
                    for header in rate_headers:
                        header_value = response.headers.get(header)
                        if header_value:
                            rate_headers_found.append(f"{header}={header_value}")

                    if rate_headers_found:
                        logger.debug(f"[RATE] Request {i+1}: Rate limit headers: {', '.join(rate_headers_found)}")
                        result["details"]["rate_limit_headers"] = True

                    if response.status_code == 429:
                        rate_limited = True
                        rate_limited_at = i + 1
                        logger.info(f"✓ Rate limiting detected at request {i + 1}")
                        logger.debug(f"[RATE] ✓ 429 Too Many Requests received!")
                        break
                else:
                    logger.debug(f"[RATE] Request {i+1}/{num_requests}: No response")

            except Exception as e:
                logger.debug(f"[RATE] Request {i + 1} error: {e}")

        if rate_limited:
            result["status"] = "Successful"
            result["details"]["rate_limited_at"] = rate_limited_at
            result["severity"] = "Low"
            result["confidence_score"] = 80
            result["confidence_level"] = "High"
            logger.debug(f"[RATE] ✓ Rate limiting IS implemented (triggered at request {rate_limited_at})")
        else:
            result["note"] = f"No rate limiting detected after {num_requests} requests"
            result["severity"] = "Medium"
            result["details"]["vulnerability"] = "Missing rate limiting"
            result["confidence_score"] = 70
            result["confidence_level"] = "Medium"
            logger.debug(f"[RATE] ✗ No rate limiting detected after {num_requests} requests - VULNERABILITY")
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            result["details"]["avg_response_time"] = avg_time
            result["details"]["min_response_time"] = min_time
            result["details"]["max_response_time"] = max_time
            result["details"]["total_requests_sent"] = len(response_times)
            logger.debug(f"[RATE] Response times - Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")

        return result

    def _perform_invalid_login_probe(self, form_data: FormData, url: str) -> None:
        import uuid
        username_field = form_data.username_input.get('name') or form_data.username_input.get('id')
        password_field = form_data.password_input.get('name') or form_data.password_input.get('id')

        if not username_field or not password_field:
            return

        random_suffix = uuid.uuid4().hex[:8]
        probe_user = f"htlogin_failed_probe_user_{random_suffix}@nonexistent.test"
        probe_pass = f"htlogin_failed_probe_pass_{random_suffix}"

        payload_data = {
            username_field: probe_user,
            password_field: probe_pass
        }

        if form_data.csrf_input:
            csrf_name = form_data.csrf_input.get('name')
            csrf_value = form_data.csrf_input.get('value')
            if csrf_name:
                # Avoid consuming a one-time token from the parsed form by refreshing it for probe traffic.
                refreshed_token = self._fetch_csrf_token(url)
                probe_csrf_value = refreshed_token or csrf_value
                if probe_csrf_value:
                    payload_data[csrf_name] = probe_csrf_value

        for other_input in form_data.other_inputs:
            other_name = other_input.get('name')
            other_value = other_input.get('value')
            if other_name:
                payload_data[other_name] = '' if other_value is None else other_value

        logger.debug(f"[PROBE] Sending failed login probe to action: {form_data.action}")

        if self.config.http_method == "POST":
            response = self.client.post(form_data.action, data=payload_data, allow_redirects=True)
        else:
            response = self.client.get(form_data.action, params=payload_data, allow_redirects=True)

        if response is not None:
            invalid_cookies = []
            if hasattr(response, 'cookies') and response.cookies is not None:
                for cookie_name in response.cookies.keys():
                    invalid_cookies.append(str(cookie_name).lower())

            if hasattr(response, 'headers') and response.headers:
                set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
                if not set_cookie_headers and 'set-cookie' in response.headers:
                    set_cookie_headers = [response.headers.get('set-cookie')]
                for header in set_cookie_headers:
                    if header and ';' in header:
                        cookie_parts = header.split(';')
                        if cookie_parts:
                            name_val = cookie_parts[0].strip()
                            if '=' in name_val:
                                c_name = name_val.split('=', 1)[0].strip()
                                if c_name.lower() not in invalid_cookies:
                                    invalid_cookies.append(c_name.lower())

            status_code = getattr(response, 'status_code', 0)
            text_content = getattr(response, 'text', '') or ''

            logger.debug(f"[PROBE] Invalid probe status: {status_code}, cookies found on failure: {invalid_cookies}")

            self.detector.set_invalid_probe_result(
                invalid_cookies=invalid_cookies,
                invalid_text=text_content,
                invalid_status=status_code
            )

