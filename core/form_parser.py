import re
from typing import Optional, List
from dataclasses import dataclass
from bs4 import BeautifulSoup

from utils.logging import get_logger
logger = get_logger()


@dataclass
class FormData:
    form: BeautifulSoup
    username_input: Optional[BeautifulSoup]
    password_input: Optional[BeautifulSoup]
    csrf_input: Optional[BeautifulSoup]
    captcha_input: Optional[BeautifulSoup] = None
    action: str = ""
    method: str = "POST"
    other_inputs: List[BeautifulSoup] = None


    action_is_implicit: bool = False

    def __post_init__(self):
        if self.other_inputs is None:
            self.other_inputs = []


class FormParser:
    CSRF_PATTERNS = [
        'csrf', '_csrf', 'csrftoken', 'csrf_token', 'csrf-token',
        'authenticity_token', '_token', 'token', 'security_token',
        '__RequestVerificationToken', 'csrfmiddlewaretoken'
    ]

    USERNAME_PATTERNS = [

        {'name': re.compile(r'user|login|email|account|username', re.I)},
        {'id': re.compile(r'user|login|email|account|username', re.I)},
        {'type': 'email'},
        {'type': 'text'},
        {'class': re.compile(r'user|login|email|account|username', re.I)},

        {'placeholder': re.compile(r'user|login|email|account|username', re.I)},
    ]

    PASSWORD_PATTERNS = [
        {'type': 'password'},
        {'name': re.compile(r'pass|pwd|password', re.I)},
        {'id': re.compile(r'pass|pwd|password', re.I)},
        {'placeholder': re.compile(r'pass|pwd|password', re.I)},
    ]

    CAPTCHA_PATTERNS = [
        {'name': re.compile(r'captcha|recaptcha|g-recaptcha|hcaptcha', re.I)},
        {'id': re.compile(r'captcha|recaptcha|g-recaptcha|hcaptcha', re.I)},
        {'class': re.compile(r'captcha|recaptcha|g-recaptcha|hcaptcha', re.I)},
    ]

    CAPTCHA_KEYWORDS = [
        'captcha', 'recaptcha', 'g-recaptcha', 'hcaptcha',
        'turnstile', 'cloudflare', 'verify you are human'
    ]

    def parse(self, html: str, url: str, use_selenium: bool = False, selenium_wait_time: int = 5, user_agent: Optional[str] = None) -> Optional[FormData]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            logger.warning(f"Failed to parse HTML: {e}")
            return None


        html_preview = html[:500] if html else "(empty)"
        logger.debug(f"[FORM] Parsing HTML (length={len(html) if html else 0})")
        logger.debug(f"[FORM] HTML preview: {html_preview}...")


        forms = soup.find_all('form')

        if forms:
            logger.debug(f"[FORM] Found {len(forms)} <form> tag(s)")

            for idx, form in enumerate(forms):
                action = form.get('action', '')
                logger.debug(f"[FORM] Checking form {idx+1}: action={action}, method={form.get('method')}")


                result = self._parse_form_tag(form, soup, url)
                if result:
                    logger.debug(f"[FORM] Login form found in form {idx+1} (action={action})")
                    return result
                else:
                    logger.debug(f"[FORM] Form {idx+1} is not a login form")
        else:
            logger.debug("[FORM] No <form> tags found, trying heuristic detection")


        result = self._parse_without_form_tag(soup, url)
        if not result:
            logger.debug("Trying to extract form fields from JavaScript (SPA detection)")
            result = self._parse_from_javascript(soup, url)
        if not result and use_selenium:
            logger.info("Form not found in static HTML. Attempting to render page with Selenium...")
            result = self._parse_with_selenium(url, selenium_wait_time, user_agent)
        return result

    def _parse_form_tag(self, form: BeautifulSoup, soup: BeautifulSoup,
                       url: str) -> Optional[FormData]:
        username_input = self._find_username_input(form, soup)
        password_input = self._find_password_input(form, soup)

        if not username_input or not password_input:
            logger.debug("Username or password input not found in form")
            return None

        csrf_input = self._find_csrf_token(form, soup)
        captcha_input = self._find_captcha(form, soup)

        raw_action = (form.get('action') or '').strip()
        action_is_implicit = raw_action == ''
        if action_is_implicit:
            action = url
        else:
            from urllib.parse import urljoin, urlparse
            action = urljoin(url, raw_action)
            try:
                parsed = urlparse(action)
                if not parsed.scheme or not parsed.netloc:
                    action = url
            except Exception:
                action = url

        method = form.get('method', 'POST').upper()
        other_inputs = form.find_all('input', {'type': ['hidden', 'checkbox', 'radio', 'submit']})
        other_inputs.extend(
            button for button in form.find_all('button')
            if button.get('name') and (button.get('type', 'submit').lower() == 'submit')
        )

        return FormData(
            form=form,
            username_input=username_input,
            password_input=password_input,
            csrf_input=csrf_input,
            captcha_input=captcha_input,
            action=action,
            method=method,
            other_inputs=other_inputs,
            action_is_implicit=action_is_implicit,
        )

    def _parse_without_form_tag(self, soup: BeautifulSoup, url: str) -> Optional[FormData]:
        username_input = self._find_username_input(None, soup)
        password_input = self._find_password_input(None, soup)

        if not username_input or not password_input:
            all_inputs = soup.find_all('input')
            password_inputs = [inp for inp in all_inputs if inp.get('type', '').lower() == 'password']
            text_inputs = [inp for inp in all_inputs if inp.get('type', '').lower() in ['text', 'email', ''] and inp.get('type', '').lower() != 'password']

            if password_inputs and text_inputs:
                password_input = password_inputs[0]
                username_input = text_inputs[0]
                logger.debug(f"Found form fields using aggressive search: username={username_input.get('name') or username_input.get('id')}, password={password_input.get('name') or password_input.get('id')}")

        if not username_input or not password_input:
            return None

        parent = username_input.find_parent(['div', 'section', 'form'])

        from bs4 import Tag
        dummy_form = Tag(name='form')
        if parent:
            dummy_form = parent

        csrf_input = self._find_csrf_token(None, soup)
        captcha_input = self._find_captcha(None, soup)

        return FormData(
            form=dummy_form,
            username_input=username_input,
            password_input=password_input,
            csrf_input=csrf_input,
            captcha_input=captcha_input,
            action=url,
            method="POST",
            other_inputs=[]
        )

    def _find_username_input(self, form: Optional[BeautifulSoup],
                            soup: BeautifulSoup) -> Optional[BeautifulSoup]:
        search_area = form if form else soup

        logger.debug(f"[FORM] Searching for username input in {'form' if form else 'full page'}")

        for pattern in self.USERNAME_PATTERNS:
            if 'type' in pattern:
                result = search_area.find('input', {'type': pattern['type']})
            elif 'name' in pattern:
                result = search_area.find('input', {'name': pattern['name']})
            elif 'id' in pattern:
                result = search_area.find('input', {'id': pattern['id']})
            elif 'class' in pattern:
                result = search_area.find('input', {'class': pattern['class']})
            elif 'placeholder' in pattern:
                result = search_area.find('input', {'placeholder': pattern['placeholder']})
            else:
                continue

            if result:
                logger.debug(f"[FORM] Found username input: name={result.get('name')}, id={result.get('id')}, type={result.get('type')}")
                return result

        logger.debug("[FORM] No username input found with patterns")
        return None

    def _find_password_input(self, form: Optional[BeautifulSoup],
                            soup: BeautifulSoup) -> Optional[BeautifulSoup]:
        search_area = form if form else soup

        logger.debug(f"[FORM] Searching for password input in {'form' if form else 'full page'}")

        for pattern in self.PASSWORD_PATTERNS:
            if 'type' in pattern:
                result = search_area.find('input', {'type': pattern['type']})
            elif 'name' in pattern:
                result = search_area.find('input', {'name': pattern['name']})
            elif 'id' in pattern:
                result = search_area.find('input', {'id': pattern['id']})
            elif 'placeholder' in pattern:
                result = search_area.find('input', {'placeholder': pattern['placeholder']})
            else:
                continue

            if result:
                logger.debug(f"[FORM] Found password input: name={result.get('name')}, id={result.get('id')}, type={result.get('type')}")
                return result

        logger.debug("[FORM] No password input found with patterns")
        return None

    def _find_csrf_token(self, form: Optional[BeautifulSoup],
                        soup: BeautifulSoup) -> Optional[BeautifulSoup]:
        search_area = form if form else soup

        for pattern in self.CSRF_PATTERNS:
            result = search_area.find('input', {'name': pattern})
            if result:
                logger.debug(f"CSRF token found by name: {pattern}")
                return result

        hidden_inputs = search_area.find_all('input', {'type': 'hidden'})
        for hidden in hidden_inputs:
            name = hidden.get('name', '').lower()
            if any(pattern in name for pattern in ['csrf', 'token', 'authenticity']):
                logger.debug(f"CSRF token found in hidden input: {name}")
                return hidden

        meta_tags = soup.find_all('meta', {'name': re.compile(r'csrf|token', re.I)})
        for meta in meta_tags:
            content = meta.get('content', '')
            if content:
                from bs4 import Tag
                dummy = Tag(name='input')
                dummy['name'] = meta.get('name', 'csrf_token')
                dummy['value'] = content
                logger.debug(f"CSRF token found in meta tag: {meta.get('name')}")
                return dummy

        logger.debug("No CSRF token found")
        return None

    def _find_captcha(self, form: Optional[BeautifulSoup],
                     soup: BeautifulSoup) -> Optional[BeautifulSoup]:
        search_area = form if form else soup

        for pattern in self.CAPTCHA_PATTERNS:
            if 'name' in pattern:
                result = search_area.find('input', {'name': pattern['name']})
            elif 'id' in pattern:
                result = search_area.find('input', {'id': pattern['id']})
            elif 'class' in pattern:
                result = search_area.find('input', {'class': pattern['class']})
            else:
                continue

            if result:
                logger.debug(f"CAPTCHA input found: {result.get('name') or result.get('id')}")
                return result

        captcha_divs = search_area.find_all(['div', 'iframe'],
                                           {'class': re.compile(r'captcha|recaptcha|g-recaptcha|hcaptcha', re.I)})
        if captcha_divs:
            logger.debug("CAPTCHA widget found (div/iframe)")
            return captcha_divs[0]

        page_text = soup.get_text().lower() if hasattr(soup, 'get_text') else ''
        if any(keyword in page_text for keyword in self.CAPTCHA_KEYWORDS):
            logger.debug("CAPTCHA keyword found in page text")
            from bs4 import Tag
            dummy = Tag(name='div')
            dummy['class'] = 'captcha-detected'
            return dummy

        logger.debug("No CAPTCHA found")
        return None

    def _parse_from_javascript(self, soup: BeautifulSoup, url: str) -> Optional[FormData]:
        try:
            scripts = soup.find_all('script')
            username_field = None
            password_field = None

            for script in scripts:
                script_text = script.string if script.string else ''
                if not script_text:
                    continue

                script_lower = script_text.lower()

                username_patterns = [
                    r'["\']?(?:username|email|user|login|account)["\']?\s*[:=]',
                    r'name\s*[:=]\s*["\'](?:username|email|user|login|account)["\']',
                    r'id\s*[:=]\s*["\'](?:username|email|user|login|account)["\']',
                    r'field\s*[:=]\s*["\'](?:username|email|user|login|account)["\']',
                ]

                password_patterns = [
                    r'["\']?(?:password|pass|pwd)["\']?\s*[:=]',
                    r'name\s*[:=]\s*["\'](?:password|pass|pwd)["\']',
                    r'id\s*[:=]\s*["\'](?:password|pass|pwd)["\']',
                    r'field\s*[:=]\s*["\'](?:password|pass|pwd)["\']',
                ]

                if not username_field:
                    for pattern in username_patterns:
                        matches = re.finditer(pattern, script_text, re.IGNORECASE)
                        for match in matches:
                            context = script_text[max(0, match.start()-50):match.end()+50]
                            field_match = re.search(r'["\']([^"\']*(?:username|email|user|login|account)[^"\']*)["\']', context, re.IGNORECASE)
                            if field_match:
                                username_field = field_match.group(1).strip()
                                break
                            var_match = re.search(r'(\w*(?:username|email|user|login|account)\w*)', context, re.IGNORECASE)
                            if var_match:
                                username_field = var_match.group(1).strip()
                                break
                        if username_field:
                            break

                if not password_field:
                    for pattern in password_patterns:
                        matches = re.finditer(pattern, script_text, re.IGNORECASE)
                        for match in matches:
                            context = script_text[max(0, match.start()-50):match.end()+50]
                            field_match = re.search(r'["\']([^"\']*(?:password|pass|pwd)[^"\']*)["\']', context, re.IGNORECASE)
                            if field_match:
                                password_field = field_match.group(1).strip()
                                break
                            var_match = re.search(r'(\w*(?:password|pass|pwd)\w*)', context, re.IGNORECASE)
                            if var_match:
                                password_field = var_match.group(1).strip()
                                break
                        if password_field:
                            break

                if 'useState' in script_text or 'useForm' in script_text or 'v-model' in script_text:
                    state_matches = re.findall(r'(?:useState|v-model)\s*\(["\']([^"\']+)["\']', script_text, re.IGNORECASE)
                    for state_field in state_matches:
                        if not username_field and any(x in state_field.lower() for x in ['user', 'email', 'login', 'account']):
                            username_field = state_field
                        if not password_field and any(x in state_field.lower() for x in ['pass', 'pwd']):
                            password_field = state_field

            if username_field and password_field:
                logger.info(f"Found form fields in JavaScript: username='{username_field}', password='{password_field}'")
                from bs4 import Tag
                dummy_form = Tag(name='form')
                dummy_username = Tag(name='input')
                dummy_username['name'] = username_field
                dummy_username['type'] = 'text'
                dummy_password = Tag(name='input')
                dummy_password['name'] = password_field
                dummy_password['type'] = 'password'

                csrf_input = self._find_csrf_token(None, soup)
                captcha_input = self._find_captcha(None, soup)

                return FormData(
                    form=dummy_form,
                    username_input=dummy_username,
                    password_input=dummy_password,
                    csrf_input=csrf_input,
                    captcha_input=captcha_input,
                    action=url,
                    method="POST",
                    other_inputs=[]
                )

            return None
        except Exception as e:
            logger.debug(f"Error parsing JavaScript for form fields: {e}")
            return None

    def _parse_with_selenium(self, url: str, wait_time: int = 5, user_agent: Optional[str] = None) -> Optional[FormData]:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.common.exceptions import TimeoutException, WebDriverException
        except ImportError:
            logger.warning("Selenium not installed. Install it with: pip install selenium")
            return None

        driver = None
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            default_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            chrome_options.add_argument(f'user-agent={user_agent or default_ua}')

            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(30)

            logger.debug(f"Loading page with Selenium: {url}")
            driver.get(url)

            WebDriverWait(driver, wait_time).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )

            import time
            time.sleep(2)

            rendered_html = driver.page_source
            soup = BeautifulSoup(rendered_html, 'html.parser')

            form = soup.find('form')
            if form:
                logger.info("Form found after Selenium rendering")
                return self._parse_form_tag(form, soup, url)

            result = self._parse_without_form_tag(soup, url)
            if result:
                logger.info("Form fields found after Selenium rendering")
                return result

            logger.debug("Form still not found after Selenium rendering")
            return None

        except TimeoutException:
            logger.warning("Selenium page load timeout")
            return None
        except WebDriverException as e:
            logger.warning(f"Selenium error: {e}")
            logger.warning("Make sure Chrome/Chromium and ChromeDriver are installed")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error with Selenium: {e}")
            return None
        finally:
            if driver:
                try:
                    import threading

                    def quit_with_timeout():
                        try:
                            driver.quit()
                        except Exception as e:
                            logger.debug(f"Error during driver.quit(): {e}")

                    quit_thread = threading.Thread(target=quit_with_timeout)
                    quit_thread.daemon = True
                    quit_thread.start()
                    quit_thread.join(timeout=5.0)

                    if quit_thread.is_alive():
                        logger.warning("Selenium driver.quit() timed out. Attempting force cleanup...")
                        try:
                            driver.window_handles
                            for handle in driver.window_handles:
                                try:
                                    driver.switch_to.window(handle)
                                    driver.close()
                                except:
                                    pass
                        except Exception as e:
                            logger.debug(f"Error during force cleanup: {e}")

                        try:
                            import psutil
                            import os
                            process = psutil.Process(driver.service.process.pid)
                            process.terminate()
                            process.wait(timeout=2)
                        except (ImportError, AttributeError, psutil.NoSuchProcess, psutil.TimeoutExpired):
                            pass
                        except Exception as e:
                            logger.debug(f"Error during process termination: {e}")

                except Exception as e:
                    logger.warning(f"Unexpected error during Selenium driver cleanup: {e}")

    def refresh_csrf_token(self, form_data: FormData,
                          client, url: str) -> Optional[str]:
        try:
            response = client.get(url)
            if not response or not hasattr(response, 'text') or not response.text:
                return None
            soup = BeautifulSoup(response.text, 'html.parser')

            new_csrf = self._find_csrf_token(soup.find('form'), soup)
            if new_csrf:
                return new_csrf.get('value', '')
        except Exception as e:
            logger.debug(f"Failed to refresh CSRF token: {e}")

        return None

