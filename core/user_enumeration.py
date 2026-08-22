import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from domain.http import HTTPClient
from core.form_parser import FormData
from utils.logging import get_logger

logger = get_logger()


class UsernameEnumerationTester:


    UNIFIED_LOGIN_ERROR_PHRASES = [
        "invalid email or password",
        "incorrect email or password",
        "wrong email or password",
        "invalid user or password",
        "invalid username or password",
        "incorrect username or password",
        "wrong username or password",
        "bad email or password",
        "wrong credentials",
        "invalid credentials",
    ]


    USERNAME_NOT_FOUND_INDICATORS = [
        'invalid username', 'username not found', 'user does not exist',
        'user not found', 'unknown user', 'no such user', 'user not registered',
        'invalid email', 'email not found', 'email does not exist',
        'unknown email', 'no account found', 'account not found',
        'user not recognized', 'invalid user', 'user unknown'
    ]

    PASSWORD_INVALID_INDICATORS = [
        'invalid password', 'incorrect password', 'wrong password',
        'password incorrect', 'password does not match', 'bad password'
    ]
    LIKELY_VALID_USERNAMES = ['admin', 'administrator', 'testuser', 'user', 'secure_user']

    def __init__(self, client: HTTPClient):
        self.client = client

    def _normalize_text(self, text: str) -> str:
        import re
        return re.sub(r'\s+', ' ', (text or '').strip().lower())

    def test(self, form_data: FormData, url: str,
             test_usernames: List[str],
             http_method: str = "POST",
             language_keywords: Optional[Dict[str, List[str]]] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        logger.info("Testing for username enumeration vulnerability")

        if not form_data.username_input or not form_data.password_input:
            logger.warning("Cannot test username enumeration: form inputs not found")
            return False, None, None

        username_field = form_data.username_input.get('name')
        if not username_field:
            username_field = form_data.username_input.get('id')

        password_field = form_data.password_input.get('name')
        if not password_field:
            password_field = form_data.password_input.get('id')

        if not username_field or not password_field:
            logger.warning("Cannot test username enumeration: field names not found")
            return False, None, None

        if not test_usernames:
            test_usernames = [
                'nonexistent_user_12345',
                'invalid_user_xyz789',
                'test_user_does_not_exist',
                'fake_user_abc123'
            ]

        username_not_found_keywords = self.USERNAME_NOT_FOUND_INDICATORS.copy()
        password_invalid_keywords = self.PASSWORD_INVALID_INDICATORS.copy()

        if language_keywords:
            if 'username_not_found' in language_keywords:
                username_not_found_keywords.extend(language_keywords['username_not_found'])
            if 'password_invalid' in language_keywords:
                password_invalid_keywords.extend(language_keywords['password_invalid'])

        vulnerable_username = None
        enumeration_details = {}
        invalid_user_response_text = None
        invalid_user_status_code = None

        for username in test_usernames[:5]:
            test_password = "test_password_123"

            payload_data = {
                username_field: username,
                password_field: test_password
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

            try:
                if http_method == "POST":
                    response = self.client.post(form_data.action, data=payload_data, allow_redirects=False)
                else:
                    response = self.client.get(form_data.action, params=payload_data, allow_redirects=False)

                if response and response.status_code in [403, 429]:
                    logger.warning(f"Rate limit detected during username enumeration test (status: {response.status_code}). Skipping remaining tests.")
                    break

                if not response or not hasattr(response, 'text') or not response.text:
                    continue

                response_text_lower = response.text.lower()

                username_not_found = any(
                    indicator in response_text_lower
                    for indicator in username_not_found_keywords
                )

                password_invalid = any(
                    indicator in response_text_lower
                    for indicator in password_invalid_keywords
                )

                if invalid_user_response_text is None and username_not_found:
                    invalid_user_response_text = response_text_lower
                    invalid_user_status_code = response.status_code if hasattr(response, 'status_code') else None

                if username_not_found and not password_invalid:
                    if any(p in response_text_lower for p in self.UNIFIED_LOGIN_ERROR_PHRASES):
                        continue
                    vulnerable_username = username
                    enumeration_details = {
                        "vulnerable": True,
                        "test_username": username,
                        "response_text": response.text[:200],
                        "status_code": response.status_code if hasattr(response, 'status_code') else 0,
                        "indicator_found": [ind for ind in username_not_found_keywords if ind in response_text_lower][:3]
                    }
                    logger.warning(f"⚠ Username enumeration vulnerability detected! "
                                 f"System distinguishes between invalid username and invalid password.")
                    break

            except Exception as e:
                error_str = str(e).lower()
                if '429' in error_str or 'too many' in error_str:
                    logger.warning(f"Rate limit detected during username enumeration test (429). Skipping remaining tests.")
                    break
                logger.debug(f"Error testing username enumeration with {username}: {e}")
                continue

        if vulnerable_username:
            return True, vulnerable_username, enumeration_details

        logger.info("No username enumeration vulnerability detected")
        return False, None, None

    def test_json_api(
        self,
        endpoint: str,
        username_field: str,
        password_field: str,
        language_keywords: Optional[Dict[str, List[str]]] = None,
        test_usernames: Optional[List[str]] = None,
        post_json: Optional[Callable[[str, dict], Any]] = None,
    ) -> Tuple[bool, Optional[str], Optional[Dict]]:
        logger.info("Testing for username enumeration vulnerability")

        if not username_field or not password_field:
            logger.warning("Cannot test API username enumeration: field names missing")
            return False, None, None

        if not test_usernames:
            test_usernames = [
                "nonexistent_user_12345",
                "invalid_user_xyz789",
                "test_user_does_not_exist",
                "fake_user_abc123",
            ]

        username_not_found_keywords = self.USERNAME_NOT_FOUND_INDICATORS.copy()
        password_invalid_keywords = self.PASSWORD_INVALID_INDICATORS.copy()

        if language_keywords:
            if "username_not_found" in language_keywords:
                username_not_found_keywords.extend(language_keywords["username_not_found"])
            if "password_invalid" in language_keywords:
                password_invalid_keywords.extend(language_keywords["password_invalid"])

        vulnerable_username = None
        enumeration_details: Dict = {}
        invalid_user_response_text = None
        invalid_user_status_code = None

        for username in test_usernames[:5]:
            test_password = "test_password_123"
            body = {username_field: username, password_field: test_password}

            try:
                if post_json:
                    response = post_json(endpoint, body)
                else:
                    response = self.client.post(
                        endpoint,
                        data=json.dumps(body),
                        headers={"Content-Type": "application/json"},
                        allow_redirects=False,
                    )

                if response and response.status_code in [403, 429]:
                    logger.warning(
                        "Rate limit detected during username enumeration test "
                        f"(status: {response.status_code}). Skipping remaining tests."
                    )
                    break

                if not response or not hasattr(response, "text") or not response.text:
                    continue

                response_text_lower = response.text.lower()

                username_not_found = any(
                    indicator in response_text_lower for indicator in username_not_found_keywords
                )
                password_invalid = any(
                    indicator in response_text_lower for indicator in password_invalid_keywords
                )

                if invalid_user_response_text is None and username_not_found:
                    invalid_user_response_text = response_text_lower
                    invalid_user_status_code = response.status_code if hasattr(response, 'status_code') else None

                if username_not_found and not password_invalid:
                    if any(p in response_text_lower for p in self.UNIFIED_LOGIN_ERROR_PHRASES):
                        continue
                    vulnerable_username = username
                    enumeration_details = {
                        "vulnerable": True,
                        "test_username": username,
                        "response_text": response.text[:200],
                        "status_code": response.status_code if hasattr(response, "status_code") else 0,
                        "indicator_found": [
                            ind for ind in username_not_found_keywords if ind in response_text_lower
                        ][:3],
                    }
                    logger.warning(
                        "⚠ Username enumeration vulnerability detected! "
                        "System distinguishes between invalid username and invalid password."
                    )
                    break

            except Exception as e:
                error_str = str(e).lower()
                if "429" in error_str or "too many" in error_str:
                    logger.warning(
                        "Rate limit detected during username enumeration test (429). Skipping remaining tests."
                    )
                    break
                logger.debug(f"Error testing API username enumeration with {username}: {e}")
                continue

        if not vulnerable_username and invalid_user_response_text:
            for candidate_username in self.LIKELY_VALID_USERNAMES:
                body = {username_field: candidate_username, password_field: "wrong_password_987654321"}
                try:
                    if post_json:
                        candidate_response = post_json(endpoint, body)
                    else:
                        candidate_response = self.client.post(
                            endpoint,
                            data=json.dumps(body),
                            headers={"Content-Type": "application/json"},
                            allow_redirects=False,
                        )
                    if not candidate_response or not getattr(candidate_response, "text", None):
                        continue
                    candidate_text = self._normalize_text(candidate_response.text)
                    baseline_text = self._normalize_text(invalid_user_response_text)
                    status_code = getattr(candidate_response, "status_code", None)
                    has_password_invalid = any(ind in candidate_text for ind in password_invalid_keywords)
                    has_username_not_found = any(ind in candidate_text for ind in username_not_found_keywords)
                    text_diff = candidate_text != baseline_text
                    status_diff = status_code != invalid_user_status_code
                    if has_password_invalid and not has_username_not_found and (text_diff or status_diff):
                        vulnerable_username = candidate_username
                        enumeration_details = {
                            "vulnerable": True,
                            "test_username": candidate_username,
                            "response_text": candidate_response.text[:200],
                            "status_code": status_code if status_code is not None else 0,
                            "detection_method": "differential_invalid_user_vs_invalid_password"
                        }
                        logger.warning("⚠ Username enumeration vulnerability detected via differential API responses.")
                        break
                except Exception as e:
                    logger.debug(f"Error during differential API enumeration check with {candidate_username}: {e}")

        if vulnerable_username:
            return True, vulnerable_username, enumeration_details

        logger.info("No username enumeration vulnerability detected")
        return False, None, None
