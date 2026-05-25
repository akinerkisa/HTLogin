import json
import re
from typing import List, Optional, Tuple, Dict, Any
from domain.http import HTTPClient
from detection.success import LoginSuccessDetector
from utils.logging import get_logger

logger = get_logger()


class APITester:

    USERNAME_FIELDS = ['username', 'user', 'email', 'login', 'account', 'userName', 'user_name']
    PASSWORD_FIELDS = ['password', 'pass', 'pwd', 'passwd', 'passWord', 'user_password']

    def __init__(self, client: HTTPClient, detector: LoginSuccessDetector):
        self.client = client
        self.detector = detector
        self._csrf_token = None
        self._csrf_cookies = {}

    def _prioritize_credentials(self, credentials_list: List[str], max_items: int) -> List[str]:
        common_first = [
            "admin:admin",
            "administrator:admin",
            "testuser:testpass123",
            "admin:password",
            "user:password",
        ]
        prioritized: List[str] = []
        seen = set()
        for cred in common_first + credentials_list:
            if cred in seen:
                continue
            seen.add(cred)
            prioritized.append(cred)
        return prioritized[:max_items]

    def _fetch_csrf_token(self, login_page_url: str) -> Optional[str]:
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
                r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']',
            ]

            for pattern in csrf_patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    logger.debug(f"[CSRF] Found CSRF token in HTML: {token[:20]}...")
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

    def _make_request_with_csrf(self, endpoint: str, payload: dict,
                                 http_method: str, login_page_url: str) -> Optional[Any]:


        headers = {'Content-Type': 'application/json'}

        if http_method == "POST":
            response = self.client.post(
                endpoint,
                data=json.dumps(payload),
                headers=headers,
                allow_redirects=False
            )
        else:
            response = self.client.get(
                endpoint,
                params=payload,
                headers=headers,
                allow_redirects=False
            )

        if response is None:
            return None


        if response.status_code in [419, 403]:
            csrf_indicators = ['page expired', 'csrf', 'token mismatch', 'forbidden']
            response_text = response.text.lower() if response.text else ""

            if response.status_code == 419 or any(ind in response_text for ind in csrf_indicators):
                logger.debug(f"[CSRF] Detected CSRF protection (status {response.status_code})")


                csrf_token = self._fetch_csrf_token(login_page_url)

                if csrf_token:
                    logger.debug(f"[CSRF] Retrying with CSRF token")


                    form_payload = payload.copy()
                    form_payload['_token'] = csrf_token


                    csrf_headers = {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'X-CSRF-TOKEN': csrf_token,
                        'X-XSRF-TOKEN': csrf_token,
                    }


                    if self._csrf_cookies:
                        cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                        csrf_headers['Cookie'] = cookie_str


                    if http_method == "POST":
                        response = self.client.post(
                            endpoint,
                            data=form_payload,
                            headers=csrf_headers,
                            allow_redirects=False
                        )

                    if response is not None:
                        logger.debug(f"[CSRF] Retry response status: {response.status_code}")

        return response

    def test_json_api(self, endpoint: str,
                     credentials_list: List[str],
                     success_keywords: List[str],
                     failure_keywords: List[str],
                     original_content_length: int,
                     http_method: str = "POST",
                     language_keywords: Optional[Dict[str, List[str]]] = None,
                     username_field: Optional[str] = None,
                     password_field: Optional[str] = None,
                     login_page_url: Optional[str] = None,
                     verbose: bool = False) -> Tuple[bool, Optional[str], Optional[Dict]]:
        if verbose:
            logger.info(f"Testing JSON API endpoint: {endpoint}")
        else:
            logger.debug(f"Testing JSON API endpoint: {endpoint}")


        self._csrf_token = None
        self._csrf_cookies = {}


        if not username_field or not password_field:
            detected_user, detected_pass = self._detect_api_fields(endpoint, http_method)
            username_field = username_field or detected_user
            password_field = password_field or detected_pass

        if not username_field or not password_field:
            logger.warning("Could not detect API field names, using defaults")
            username_field = username_field or 'email'
            password_field = password_field or 'password'

        logger.debug(f"[DEBUG] API fields: username={username_field}, password={password_field}")


        if not login_page_url:

            from urllib.parse import urlparse, urljoin
            parsed = urlparse(endpoint)
            login_page_url = f"{parsed.scheme}://{parsed.netloc}/login"

        successful_credential = None
        successful_details = None
        csrf_fetched = False

        for credential in self._prioritize_credentials(credentials_list, max_items=10):
            if ':' not in credential:
                continue

            username, password = credential.split(':', 1)

            payload = {
                username_field: username,
                password_field: password
            }

            logger.debug(f"[DEBUG] API payload: {json.dumps(payload)}")
            logger.debug(f"[DEBUG] API endpoint: {endpoint}")

            try:
                headers = {'Content-Type': 'application/json'}


                if self._csrf_token:
                    headers['X-CSRF-TOKEN'] = self._csrf_token
                    headers['X-XSRF-TOKEN'] = self._csrf_token


                if self._csrf_cookies:
                    cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                    headers['Cookie'] = cookie_str

                if http_method == "POST":
                    response = self.client.post(
                        endpoint,
                        data=json.dumps(payload),
                        headers=headers,
                        allow_redirects=False
                    )
                else:
                    response = self.client.get(
                        endpoint,
                        params=payload,
                        headers=headers,
                        allow_redirects=False
                    )

                if response is None:
                    logger.debug(f"[DEBUG] No response from API endpoint")
                    continue

                logger.debug(f"[DEBUG] API response status: {response.status_code}")
                try:
                    _hdr = dict(response.headers) if getattr(response, "headers", None) else {}
                except (TypeError, ValueError):
                    _hdr = {}
                logger.debug(f"[DEBUG] API response headers: {_hdr}")
                if response.text:
                    response_preview = response.text[:500] if len(response.text) > 500 else response.text
                    logger.debug(f"[DEBUG] API response body: {response_preview}")


                if response.status_code in [419, 403] and not csrf_fetched:
                    csrf_indicators = ['page expired', 'csrf', 'token mismatch', 'forbidden', 'verification']
                    response_text = response.text.lower() if response.text else ""

                    if response.status_code == 419 or any(ind in response_text for ind in csrf_indicators):
                        logger.debug(f"[CSRF] Detected CSRF protection (status {response.status_code}), fetching token...")
                        csrf_fetched = True


                        csrf_token = self._fetch_csrf_token(login_page_url)

                        if csrf_token:
                            logger.debug(f"[CSRF] Got token, retrying with form data...")


                            form_payload = payload.copy()
                            form_payload['_token'] = csrf_token

                            csrf_headers = {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-CSRF-TOKEN': csrf_token,
                                'X-XSRF-TOKEN': csrf_token,
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                                'Origin': f"{urlparse(endpoint).scheme}://{urlparse(endpoint).netloc}",
                                'Referer': login_page_url,
                            }

                            if self._csrf_cookies:
                                cookie_str = '; '.join([f"{k}={v}" for k, v in self._csrf_cookies.items()])
                                csrf_headers['Cookie'] = cookie_str

                            response = self.client.post(
                                endpoint,
                                data=form_payload,
                                headers=csrf_headers,
                                allow_redirects=False
                            )

                            if response is not None:
                                logger.debug(f"[CSRF] Retry response status: {response.status_code}")
                                logger.debug(f"[CSRF] Retry response headers: {dict(response.headers)}")
                                if response.text:
                                    response_preview = response.text[:300] if len(response.text) > 300 else response.text
                                    logger.debug(f"[CSRF] Retry response body: {response_preview}")


                json_success = self._detect_json_api_success(response)
                logger.debug(f"[DEBUG] JSON API detection result: {json_success}")


                redirect_success = False
                if response.status_code in [302, 301]:
                    location = response.headers.get('Location', '').lower()
                    success_redirects = ['dashboard', 'home', 'admin', 'profile', 'account', 'welcome']
                    if any(sr in location for sr in success_redirects):
                        redirect_success = True
                        logger.debug(f"[DEBUG] Redirect success detected: {location}")

                    elif 'login' not in location and 'error' not in location:
                        redirect_success = True
                        logger.debug(f"[DEBUG] Possible redirect success (not to login): {location}")

                if json_success or redirect_success:
                    successful_credential = credential
                    successful_details = {
                        "confidence_score": 100,
                        "confidence_level": "High",
                        "endpoint": endpoint,
                        "format": "json",
                        "response_status": response.status_code
                    }
                    logger.info(f"✓ JSON API login successful: {credential}")
                    return True, successful_credential, successful_details

            except Exception as e:
                logger.debug(f"Error testing JSON API with {credential}: {e}")
                continue

        return False, None, None

    def _detect_json_api_success(self, response) -> bool:
        if response is None:
            logger.debug("[DEBUG] _detect_json_api_success: response is None")
            return False

        logger.debug(f"[DEBUG] _detect_json_api_success: status={response.status_code}")


        if response.status_code >= 400:
            logger.debug(f"[DEBUG] _detect_json_api_success: status >= 400, returning False")
            return False


        try:
            response_text = response.text.strip() if response.text else ""
            logger.debug(f"[DEBUG] _detect_json_api_success: response_text[:100]={response_text[:100] if response_text else 'empty'}")


            if response_text.startswith('<!') or response_text.startswith('<html'):
                logger.debug("[DEBUG] _detect_json_api_success: Response is HTML, not JSON API")
                return False


            if response_text.startswith('{') or response_text.startswith('['):
                data = json.loads(response_text)
                logger.debug(f"[DEBUG] _detect_json_api_success: Parsed JSON data keys={list(data.keys()) if isinstance(data, dict) else 'list'}")


                success_keys = ['token', 'access_token', 'accessToken', 'jwt', 'authentication',
                              'auth', 'session', 'sessionId', 'session_id', 'user', 'userId',
                              'id_token', 'refresh_token', 'bearer']


                error_keys = ['error', 'errors', 'message', 'errorMessage', 'error_message']
                error_values = ['invalid', 'incorrect', 'failed', 'unauthorized', 'wrong',
                              'denied', 'not found', 'bad credentials', 'authentication failed']


                def has_key(obj, keys):
                    if isinstance(obj, dict):
                        for key in keys:
                            if key.lower() in [k.lower() for k in obj.keys()]:
                                return True
                        for value in obj.values():
                            if has_key(value, keys):
                                return True
                    elif isinstance(obj, list):
                        for item in obj:
                            if has_key(item, keys):
                                return True
                    return False

                def has_error_value(obj):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            if key.lower() in [ek.lower() for ek in error_keys]:
                                if isinstance(value, str):
                                    if any(ev.lower() in value.lower() for ev in error_values):
                                        return True
                                elif isinstance(value, list):
                                    for item in value:
                                        if isinstance(item, str) and any(ev.lower() in item.lower() for ev in error_values):
                                            return True
                                        if isinstance(item, dict) and has_error_value(item):
                                            return True
                            if has_error_value(value):
                                return True
                    elif isinstance(obj, list):
                        for item in obj:
                            if has_error_value(item):
                                return True
                    elif isinstance(obj, str):
                        if any(ev.lower() in obj.lower() for ev in error_values):
                            return True
                    return False


                has_success = has_key(data, success_keys)
                has_error = has_error_value(data)

                logger.debug(f"[DEBUG] _detect_json_api_success: has_success={has_success}, has_error={has_error}")


                # GraphQL responses often encode errors as "errors": [...]. Treat that as failure even with 2xx.
                if isinstance(data, dict) and "errors" in data and data.get("errors"):
                    logger.debug("[DEBUG] _detect_json_api_success: GraphQL-style errors detected")
                    return False

                if has_success and not has_error:
                    logger.debug("[DEBUG] _detect_json_api_success: SUCCESS - has success keys and no errors")
                    return True


                if response.status_code in [200, 201] and not has_error and data:

                    if isinstance(data, dict) and len(data) > 0:
                        logger.debug("[DEBUG] _detect_json_api_success: SUCCESS - 200/201 with data and no errors")
                        return True
            else:
                logger.debug(f"[DEBUG] _detect_json_api_success: Response doesn't start with {{ or [")

        except json.JSONDecodeError:
            logger.debug("[DEBUG] _detect_json_api_success: Response is not valid JSON")
            pass
        except Exception as e:
            logger.debug(f"[DEBUG] _detect_json_api_success: Error parsing JSON response: {e}")
            pass

        logger.debug("[DEBUG] _detect_json_api_success: returning False (end of function)")
        return False

    def _detect_graphql_success(self, response) -> bool:
        if response is None or getattr(response, "status_code", 0) >= 400:
            return False
        try:
            payload = json.loads(response.text or "{}")
        except Exception:
            return False
        if not isinstance(payload, dict):
            return False
        if payload.get("errors"):
            return False
        data = payload.get("data")
        if not isinstance(data, dict):
            return False
        for _, value in data.items():
            if isinstance(value, dict):
                if any(k in value for k in ("token", "access_token", "jwt", "session")):
                    return True
                user_obj = value.get("user")
                if isinstance(user_obj, dict) and user_obj:
                    return True
        return False

    def test_graphql(self, endpoint: str,
                    credentials_list: List[str],
                    success_keywords: List[str],
                    failure_keywords: List[str],
                    original_content_length: int,
                    language_keywords: Optional[Dict[str, List[str]]] = None,
                    verbose: bool = False) -> Tuple[bool, Optional[str], Optional[Dict]]:
        if verbose:
            logger.info(f"Testing GraphQL endpoint: {endpoint}")
        else:
            logger.debug(f"Testing GraphQL endpoint: {endpoint}")

        mutation_names = ['login', 'authenticate', 'signIn', 'signin', 'userLogin']

        for credential in self._prioritize_credentials(credentials_list, max_items=10):
            if ':' not in credential:
                continue

            username, password = credential.split(':', 1)

            for mutation_name in mutation_names:
                for user_field in ['username', 'email', 'user']:
                    for pass_field in ['password', 'pass']:
                        try:
                            mutation = f"""
                            mutation {{
                                {mutation_name}({user_field}: "{username}", {pass_field}: "{password}") {{
                                    token
                                    user {{
                                        id
                                        username
                                    }}
                                }}
                            }}
                            """

                            payload = {"query": mutation.strip()}

                            response = self.client.post(
                                endpoint,
                                data=json.dumps(payload),
                                headers={'Content-Type': 'application/json'},
                                allow_redirects=False
                            )

                            if not response:
                                continue

                            graphql_success = self._detect_graphql_success(response)
                            if graphql_success:
                                successful_details = {
                                    "confidence_score": 100,
                                    "confidence_level": "High",
                                    "endpoint": endpoint,
                                    "format": "graphql",
                                    "mutation": mutation_name
                                }
                                logger.info(f"✓ GraphQL login successful: {credential}")
                                return True, credential, successful_details

                        except Exception as e:
                            logger.debug(f"Error testing GraphQL: {e}")
                            continue

        return False, None, None

    def _detect_api_fields(self, endpoint: str, http_method: str) -> Tuple[Optional[str], Optional[str]]:
        test_payloads = [
            {'username': 'test', 'password': 'test'},
            {'user': 'test', 'password': 'test'},
            {'email': 'test', 'password': 'test'},
            {'login': 'test', 'password': 'test'},
            {'userName': 'test', 'password': 'test'},
            {'user_name': 'test', 'password': 'test'},
            {'userName': 'test', 'passWord': 'test'},
            {'email': 'test', 'pass': 'test'},
            {'email': 'test', 'pwd': 'test'},
            {'account': 'test', 'password': 'test'},
            {'account': 'test', 'pass': 'test'},
            {'login': 'test', 'pass': 'test'},
            {'user': 'test', 'passwd': 'test'},
            {'email': 'test', 'passwd': 'test'},
            {'username': 'test', 'user_password': 'test'},
        ]

        detected_fields = None

        for payload in test_payloads:
            try:
                headers = {'Content-Type': 'application/json'}
                if http_method == "POST":
                    response = self.client.post(
                        endpoint,
                        data=json.dumps(payload),
                        headers=headers,
                        allow_redirects=False
                    )
                else:
                    response = self.client.get(
                        endpoint,
                        params=payload,
                        headers=headers,
                        allow_redirects=False
                    )

                if response:
                    status = response.status_code if hasattr(response, 'status_code') else 0

                    if status in [400, 401, 422]:
                        username_field = list(payload.keys())[0]
                        password_field = list(payload.keys())[1]
                        detected_fields = (username_field, password_field)

                        if hasattr(response, 'text') and response.text:
                            try:
                                error_data = json.loads(response.text)
                                error_str = json.dumps(error_data).lower()

                                for field_name in ['username', 'user', 'email', 'login', 'account', 'password', 'pass', 'pwd']:
                                    if field_name in error_str:
                                        if 'username' in error_str or 'user' in error_str or 'email' in error_str:
                                            if username_field in ['username', 'user', 'email', 'login', 'account']:
                                                break
                                        elif 'password' in error_str or 'pass' in error_str or 'pwd' in error_str:
                                            if password_field in ['password', 'pass', 'pwd', 'passwd']:
                                                break
                            except (json.JSONDecodeError, AttributeError):
                                pass

                        return detected_fields

                    if hasattr(response, 'text') and response.text:
                        try:
                            response_data = json.loads(response.text)
                            response_str = json.dumps(response_data).lower()

                            field_patterns = {
                                'username': ['username', 'user', 'email', 'login', 'account'],
                                'password': ['password', 'pass', 'pwd', 'passwd']
                            }

                            for field_type, patterns in field_patterns.items():
                                for pattern in patterns:
                                    if pattern in response_str:
                                        if field_type == 'username':
                                            for key in payload.keys():
                                                if key.lower() in patterns:
                                                    detected_fields = (key, list(payload.keys())[1])
                                                    break
                                        elif field_type == 'password':
                                            for key in payload.keys():
                                                if key.lower() in ['password', 'pass', 'pwd', 'passwd']:
                                                    detected_fields = (list(payload.keys())[0], key)
                                                    break

                                        if detected_fields:
                                            return detected_fields
                        except (json.JSONDecodeError, AttributeError, KeyError):
                            pass
            except Exception as e:
                logger.debug(f"Error detecting API fields with payload {payload}: {e}")
                continue

        return detected_fields if detected_fields else (None, None)
