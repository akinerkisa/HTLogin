# HowToLogin (HTLogin)

> Authorized login security testing for web applications.

HTLogin inspects login forms and authentication APIs, then tests for common
authentication weaknesses such as default credentials, injection-based login
bypass, username enumeration, CAPTCHA handling gaps, and missing rate limits.
It supports traditional HTML forms, JSON/GraphQL APIs, and JavaScript-rendered
SPAs.

Only use HTLogin against systems you own or are explicitly authorized to test.
Active scans send authentication and security-test requests to the target.

## Why HTLogin?

- One CLI for HTML forms, API login endpoints, and SPA discovery
- Confidence-based detection with evidence in JSON and HTML reports
- Quick and full scan modes
- Built-in request budget and passive safe mode
- Proxy, Selenium, Burp Suite, multi-language, and batch URL support

## Quick start

```bash
git clone https://github.com/akinerkisa/HTLogin.git
cd HTLogin
python -m pip install -r requirements.txt

# Passive inspection: no credentials, injection, enumeration, or rate-limit probes
python main.py -u https://example.com/login --safe-mode

# Authorized active scan with a per-target request ceiling
python main.py -u https://example.com/login --max-requests 200 -o report.json -of json
```

For development:

```bash
python -m pip install -r requirements-dev.txt
pytest
pytest --cov=. --cov-report=term-missing
ruff check .
python -m build
```

`--max-requests 0` disables the main HTTP client's request budget. The rate
limit audit has its own `--rate-limit`/configuration limit. `--insecure` should
only be used for authorized environments with intentionally untrusted TLS.

## Current scope

| Area | Support |
| --- | --- |
| HTML login forms | Static parsing and CSRF/CAPTCHA detection |
| SPA applications | Optional Selenium rendering and API discovery |
| APIs | JSON and GraphQL login endpoint discovery/testing |
| Authentication checks | Default credentials, SQL/NoSQL/XPath/LDAP payloads |
| Modern auth detection | Passive MFA/2FA, OAuth/OIDC, SAML, and external IdP hints |
| Abuse controls | Username enumeration and rate-limit auditing |
| Reports | Text, JSON, and HTML |
| Integrations | HTTP proxy and Burp Suite extension |

## Safe operation

Use `--safe-mode` when you only need passive form and page inspection. Active
testing should be run inside an approved scope, preferably with a dedicated
test account and a conservative `--max-requests` value. HTLogin detects but
does not solve MFA, OAuth/OIDC, or CAPTCHA challenges and may require manual verification for high-impact
findings.

## Reporting and confidence

Reports include the target, test status, confidence score/level, request
context, evidence, and recommended manual verification. A positive result is
not a substitute for reproducing the behavior in the target environment;
redirects, cookies, and response text can produce false positives on custom
login flows.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and safe-use
guidance, [CONTRIBUTING.md](CONTRIBUTING.md) for development, and
[CHANGELOG.md](CHANGELOG.md) for unreleased changes.

## Quick Start And Usage

**Install:**
```bash
git clone https://github.com/akinerkisa/HTLogin
cd HTLogin
pip install -r requirements.txt
```

**Basic Usage:**
```bash
# Test a single URL
python main.py -u https://example.com/login

# Test multiple URLs from a file
python main.py -l urls.txt

# Save results to JSON
python main.py -u https://example.com/login -o results.json -of json

# Use custom credentials
python main.py -u https://example.com/login -cl credentials.txt

# Use proxy (Burp Suite, etc.)
python main.py -u https://example.com/login -p http://127.0.0.1:8080

# Use Selenium for SPA applications (JavaScript-rendered forms)
python main.py -u https://example.com/login --use-selenium

# Use custom User-Agent
python main.py -u https://example.com/login --user-agent "HTLogin/1.1.1"

```

**What it tests:**
- SQL/NoSQL/XPath/LDAP Injection bypass
- Default credentials (admin:admin, etc.)
- Username enumeration
- CAPTCHA detection
- Rate limiting (detects missing or weak rate limits)
- API endpoints (JSON/GraphQL) when forms not found

**Config file (optional):**
```json
{
  "test_account_username": "test@example.com",
  "test_account_password": "testpass123",
  "timeout": 15,
  "verbose": true
}
```
Use with: `python main.py -u https://example.com/login --config config.json`

> [!NOTE]
> You can try this tool with https://github.com/akinerkisa/renikApp login bypass page section.

> [!NOTE]
> You can install HTLogin Burp Suite extension from https://github.com/akinerkisa/HTLogin/burpsuite_extension page.

## Installation

### From Source
<code>git clone https://github.com/akinerkisa/HTLogin</code>
<p><code>cd HTLogin</code></p>
<p><code>pip install -r requirements.txt</code></p>

### Using setup.py (Optional)
<p><code>pip install .</code></p>
<p>After installation, you can use: <code>htlogin -u https://example.com/login</code></p>

## Usage
<code>python3 main.py -u https://www.example.com/login </code>

Flag | Short | Description | Example | Default | Required
--- | --- | --- | --- | --- | --- |
--url	| -u | Specify URL | python3 main.py -u https://www.example.com/login | N/A | Yes(One of them -u or -l) |
--list | -l | Specify URL List | python3 main.py -l list.txt | N/A | Yes(One of them -u or -l) |
--credential-list | -cl | Specify default credentials path for test | python3 main.py -cl credentials.txt | Defined in the program | No |
--rate-limit | -r | Number of requests for rate limit test | python3 main.py -r 20 | 10 | No |
--verbose | -v | Toggles showing all Valid/Invalid results | python3 main.py -v on/off | off | No |
--language | -lang | Language code for keyword detection | python3 main.py -lang tr | en | No |
--output | -o | Specify output file | python3 main.py -o output.txt | output.txt | No |
--output-format | -of | Output format (text, json, html) | python3 main.py -of json | text | No |
--proxy | -p | Proxy to use for requests | python3 main.py -p http://127.0.0.1:8080 | N/A | No |
--timeout | -t | Request timeout in seconds | python3 main.py -t 15 | 10 | No |
--http-method | -hm | HTTP method to use for testing | python3 main.py -hm GET | POST | No |
--log | | Path to log file (optional, auto-organized by domain if not specified) | python3 main.py --log custom.log | Auto: scans/domain/log_timestamp.txt | No |
--no-progress | | Disable progress bar | python3 main.py --no-progress | false | No |
--config | | Path to configuration file (JSON) | python3 main.py --config config.json | N/A | No |
--use-selenium | | Use Selenium to render JavaScript (for SPA applications) | python3 main.py --use-selenium | false | No |
--selenium-wait-time | | Selenium page load wait time in seconds | python3 main.py --selenium-wait-time 10 | 5 | No |
--user-agent | | Custom User-Agent string for HTTP requests | python3 main.py --user-agent "HTLogin/1.1.1" | Default browser UA | No |

## List File Example Format
```
http://127.0.0.1:5000/lp/insecure-login
http://127.0.0.1:5000/lp/secure-login
http://127.0.0.1:5000/lp/default-login
http://127.0.0.1:5000/lp/rate-limit-login
```
## Features
- SQL Injection login bypass testing
- NoSQL Injection login bypass testing (with progressive testing mode)
- XPath Injection login bypass testing
- LDAP Injection login bypass testing
- Default Credentials testing
- CAPTCHA detection - Automatically detects CAPTCHA protection
- Username enumeration testing** - Detects if system reveals valid usernames
- Test account support - Use known credentials for baseline analysis
- Automatic API detection - Automatically detects and tests JSON API and GraphQL endpoints when forms are not found
- Multi-lang support for keyword check
- URL list support
- Proxy support for requests
- HTTP method selection (GET or POST)
- Multiple output formats (Text, JSON, HTML)
- Enhanced JSON reporting with `executive_summary`, `security_context`, `finding_type`, `evidence`, and `actionability`
- Organized log files by domain
- Automatic login page discovery
- Confidence-based success detection system
- Configurable confidence thresholds
- Retry mechanism with exponential backoff
- CSRF token detection and handling
- WSTG-aligned NoSQL API testing phases (`syntax_injection` and `operator_injection`)
  
## How HTLogin Extracts Successful Login Attempts

HTLogin uses a **confidence-based scoring system** to detect successful login attempts. The system collects multiple signals from the HTTP response and calculates a confidence score.

### Signal Collection

HTLogin analyzes the following signals:

**Positive Signals (increase confidence):**
- **302 Redirect to non-login page** (+40): Redirect to a different page indicates successful authentication
- **Session Cookie** (+35): Presence of session/auth/token cookies
- **Short Success Message** (+30): Success keywords in short response (<200 bytes)
- **Success Keywords** (+20): Keywords like 'welcome', 'dashboard', 'profile', 'logged in', 'successful'
- **Content Significantly Shorter** (+25): Response much shorter than original (likely success message, not error)
- **Response Format Change** (+15): HTML to plain text conversion (when not an error message)
- **Content Length Changed** (+10): Significant content length difference (when not an error message)
- **High Response Time** (+5): Response time > 1s (possible processing)
- **Multiple Users Detected** (+20): Generic success message without specific user (NoSQL injection)

**Negative Signals (decrease confidence):**
- **Failure Keywords** (-30): Keywords like 'invalid', 'incorrect', 'failed', 'error'
- **Error Messages** (-20): Error patterns, exceptions, tracebacks
- **Still on Login Page** (-15 to -25): Login indicators still present with similar content length (higher confidence when content length is very similar, within 50 bytes)
- **Content Significantly Shorter (Error)** (-15): Response much shorter due to error message
- **Content Length Changed (Error)** (-10): Content length change due to error message
- **Response Format Change (Error)** (-5): Format change due to error message

### Confidence Score Calculation

```
Confidence Score = Sum of Positive Signals - Sum of Negative Signals
```

The final score is clamped between 0 and 100.

### Confidence Levels

- **High** (≥50): Very strong indicators of successful login
- **Medium** (≥30): Strong indicators, login likely successful
- **Low** (≥20): Some indicators present, manual verification recommended
- **Very Low** (<20): Weak or no indicators

### Success Detection

A login attempt is considered successful if:
- `confidence_score >= threshold_high` (default: 50)

This stricter threshold helps reduce false positives by requiring stronger evidence of successful authentication.

The system also recommends manual verification when:
- Confidence is between medium and high thresholds
- Both positive and negative signals are present
- Low confidence but positive signals exist

## NoSQL Injection Progressive Testing Mode

HTLogin includes an advanced progressive testing mode for NoSQL injection that tests in multiple phases:

1. **Basic Bypass Phase**: Tests fundamental NoSQL injection payloads
2. **Multiple User Phase**: Attempts to detect if multiple users are returned
3. **Admin Discovery Phase**: Uses regex patterns to discover admin users

The progressive mode can be configured via the config file:
- `nosql_progressive_mode`: Enable/disable progressive testing (default: true)
- `nosql_admin_patterns`: Custom regex patterns for admin discovery (default: ["admin.*", "administrator.*", "root.*", ".*admin.*", "adm.*"])

If basic bypass fails, the system automatically stops to avoid false positives.

## Multi-Language Support in Page Content Check
When checking the page content, it is checked in English by default. However, you can edit this with parameters. You can also add different languages and keywords by editing the `languages.json` file. Currently English and Turkish are defined.

Languages.json format:
```json
{
    "en": {
        "success": ["welcome", "dashboard", "profile", "logged in", "successful"],
        "failure": ["invalid", "incorrect", "failed", "error", "try again"],
        "login_keywords": ["login", "sign in", "signin", "sign-in", "authenticate", "auth", "administrator", "admin", "access", "account"],
        "error_indicators": ["missing parameter", "error", "invalid", "bad request", "unauthorized", "forbidden"],
        "login_indicators": ["login", "sign in", "authenticate"],
        "generic_indicators": ["welcome", "success", "logged in", "authenticated"],
        "specific_indicators": ["admin", "administrator", "user:", "username:", "account:"]
    }
}
```

**Field Descriptions:**
- `success`: Keywords that indicate successful login
- `failure`: Keywords that indicate failed login
- `login_keywords`: Keywords used to identify login pages during discovery
- `error_indicators`: Keywords that indicate error responses
- `login_indicators`: Keywords that indicate login-related content
- `generic_indicators`: Generic success indicators
- `specific_indicators`: Specific user/admin indicators
- `username_not_found`: Keywords indicating username doesn't exist (for enumeration testing) - optional
- `password_invalid`: Keywords indicating password is incorrect (for enumeration testing) - optional

## Configuration File

You can use a JSON configuration file to set default values for all options. Use `--config` parameter to specify the config file path.

You can copy `config.example.json` to `config.json` and modify it according to your needs.

Example configuration (`config.example.json`):
```json
{
  "timeout": 10,
  "max_retries": 2,
  "rate_limit_requests": 10,
  "rate_limit_threads": 10,
  "rate_limit_adaptive_delay": 1.0,
  "confidence_threshold_low": 20,
  "confidence_threshold_medium": 30,
  "confidence_threshold_high": 50,
  "show_progress": true,
  "verbose": false,
  "http_method": "POST",
  "language": "en",
  "output_format": "text",
  "output_file": null,
  "log_file": null,
  "proxy": null,
  "credential_list_file": null,
  "discovery_enabled": true,
  "discovery_verify_pages": true,
  "nosql_progressive_mode": true,
  "nosql_admin_patterns": ["admin.*", "administrator.*", "root.*", ".*admin.*", "adm.*"],
  "test_account_username": null,
  "test_account_password": null,
  "use_selenium": false,
  "selenium_headless": true,
  "selenium_wait_time": 5,
  "user_agent": null
}
```

**Configuration Options:**
- `timeout`: Request timeout in seconds (default: 10)
- `max_retries`: Maximum number of retry attempts for failed requests (default: 2)
- `rate_limit_requests`: Number of requests for rate limit testing (default: 10)
- `rate_limit_threads`: Number of threads for rate limit testing (default: 10)
- `rate_limit_adaptive_delay`: Adaptive delay between requests in seconds (default: 1.0)
- `confidence_threshold_low`: Low confidence threshold (default: 20)
- `confidence_threshold_medium`: Medium confidence threshold (default: 30)
- `confidence_threshold_high`: High confidence threshold (default: 50)
- `show_progress`: Show progress bar (default: true)
- `verbose`: Enable verbose logging (default: false)
- `http_method`: HTTP method for testing (default: "POST")
- `language`: Language code for keyword detection (default: "en")
- `output_format`: Output format - "text", "json", or "html" (default: "text")
- `discovery_enabled`: Enable automatic login page discovery (default: true)
- `discovery_verify_pages`: Verify discovered pages contain login forms (default: true)
- `nosql_progressive_mode`: Enable progressive NoSQL injection testing (default: true)
- `nosql_admin_patterns`: Regex patterns for admin user discovery in NoSQL injection (default: ["admin.*", "administrator.*", "root.*", ".*admin.*", "adm.*"])
- `test_account_username`: Test account username for baseline login analysis (default: null)
- `test_account_password`: Test account password for baseline login analysis (default: null)
- `use_selenium`: Use Selenium to render JavaScript for SPA applications (default: false)
- `selenium_headless`: Run Selenium in headless mode (default: true)
- `selenium_wait_time`: Selenium page load wait time in seconds (default: 5)
- `user_agent`: Custom User-Agent string for HTTP requests (default: null, uses default browser UA)

## CAPTCHA Detection

HTLogin automatically detects CAPTCHA protection on login forms. When CAPTCHA is detected:
- A warning is displayed in the console
- Username enumeration tests are automatically skipped (as they would fail)
- The detection is included in the scan results

CAPTCHA detection works by:
- Checking for CAPTCHA input fields (name/id/class patterns)
- Detecting CAPTCHA widgets (reCAPTCHA, hCaptcha, etc.)
- Searching for CAPTCHA-related keywords in page content

## Username Enumeration Testing

HTLogin tests for username enumeration vulnerabilities by analyzing error messages. The tool:
- Tests with non-existent usernames
- Compares error messages for "invalid username" vs "invalid password"
- Detects if the system reveals whether a username exists

**How it works:**
1. Sends login attempts with known invalid usernames
2. Analyzes response messages for username-specific errors
3. If system distinguishes between "username not found" and "password incorrect", vulnerability is detected

**Note:** Username enumeration testing is automatically skipped if CAPTCHA is detected.

## Test Account Support

You can provide a test account in the configuration file to improve accuracy:

```json
{
  "test_account_username": "test@example.com",
  "test_account_password": "testpass123"
}
```

**Benefits:**
- **Baseline Analysis**: Tool performs a successful login first to establish a baseline
- **Improved Confidence**: Confidence scores are calibrated based on actual successful login response
- **Better Detection**: Reduces false positives by comparing against known successful login patterns

When a test account is provided:
1. Tool first attempts login with test credentials
2. Analyzes the successful login response (redirects, cookies, content)
3. Uses this baseline to improve confidence scoring for other tests
4. If baseline login fails, continues with normal testing

**Security Note:** Only use test accounts that you own or have explicit permission to test.

## Selenium Support for SPA Applications

HTLogin supports Selenium for testing Single Page Applications (SPAs) where login forms are dynamically loaded via JavaScript. When enabled, HTLogin uses Chrome headless browser to render the page and extract form fields.

**Requirements:**
- Chrome/Chromium browser installed
- ChromeDriver installed and in PATH
- Selenium package: `pip install selenium`

**Usage:**
```bash
# Enable Selenium via CLI (SPA / JavaScript-rendered login forms)
python main.py -u https://example.com/login --use-selenium

# Configure wait time (default: 5 seconds)
python main.py -u https://example.com/login --use-selenium --selenium-wait-time 10

# Example: behind Cloudflare + SPA
python main.py -u https://play.picoctf.org/login --use-selenium -p http://127.0.0.1:8080
```

**Config file:**
```json
{
  "use_selenium": true,
  "selenium_headless": true,
  "selenium_wait_time": 5
}
```

**When to use:**
- Forms are loaded dynamically via JavaScript
- Static HTML parsing fails to find form fields
- SPA applications (React, Vue, Angular, etc.)

**Note:** Selenium is slower than static parsing but necessary for JavaScript-rendered forms. If Selenium is not installed, HTLogin will fall back to static parsing and API discovery.

## Automatic API Detection

HTLogin automatically detects and tests API endpoints when HTML forms are not found. This enables testing of modern Single Page Applications (SPAs) and API-based authentication.

Typical high-level flow:
- Try static HTML form parsing
- Try Selenium (if enabled / auto-triggered) for SPA pages
- If still no form: try API/JSON/GraphQL endpoint discovery

**How it works:**
1. Tool first attempts to find HTML login forms
2. If no forms are found, it searches for common API endpoints:
   - JSON API endpoints: `/api/login`, `/api/auth`, `/api/v1/login`, etc.
   - GraphQL endpoints: `/graphql`, `/api/graphql`, etc.
3. Tests discovered endpoints with default credentials
4. Automatically detects field names (username, password, etc.)

**Supported API Formats:**
- **JSON API**: Standard REST API endpoints with JSON payloads
- **GraphQL**: GraphQL mutations for authentication

**Example Flow:**
```
1. Try HTML form parsing → Not found
2. Try HTML page discovery → Not found
3. Discover API endpoints → Found /api/login
4. Test JSON API login → Success!
```

**Note:** API testing is only performed when HTML forms cannot be detected, ensuring backward compatibility with traditional form-based applications.

## Rate Limit Testing

HTLogin actively tests login endpoints for missing or weak rate limiting mechanisms. This helps identify vulnerabilities where brute-force attacks could be successful.

**How it works:**
1. Sends concurrent requests to the login endpoint (default: 10 requests)
2. Monitors for rate limiting indicators:
   - HTTP status codes (429 Too Many Requests, 403 Forbidden)
   - Rate limit headers (`X-RateLimit-Remaining`, `Retry-After`, etc.)
   - Response text indicators ("too many requests", "rate limit", "slow down", etc.)
3. Reports whether rate limiting is present and at which request it was triggered

**Configuration:**
- `rate_limit_requests`: Number of requests to send (default: 10)
- `rate_limit_threads`: Number of concurrent threads (default: 10)
- `rate_limit_adaptive_delay`: Delay between requests in seconds (default: 1.0)

**What it detects:**
- **No rate limit**: System accepts all requests without blocking
- **Rate limit present**: System blocks requests after a certain threshold
- **Rate limit threshold**: Identifies at which request number the limit is triggered

**Example output:**
```
✗ Rate Limit Test: No rate limit after 10 requests
✓ Rate Limit Test: Rate limited at request #5
```

**Security Note:** Rate limit testing sends multiple requests to the target. Only use on systems you own or have explicit permission to test.

## Log Organization

HTLogin automatically organizes log files by domain in `scans/domain_name/log_timestamp.txt` format. If you specify `--log custom.log`, the log file will be saved at the specified path.

## Output Formats

HTLogin supports multiple output formats:

- **Text** (default): Human-readable plain text format
- **JSON**: Structured JSON format for programmatic processing
- **HTML**: Beautiful HTML report with styling

### JSON Schema Highlights

JSON output includes:
- Top-level `executive_summary` (total targets, duration, requests, findings by severity)
- Per-target `security_context` (initial block, rate-limit position, WAF/CAPTCHA signals)
- Per-finding `finding_type`, `evidence`, and `actionability`

Example:
```bash
python3 main.py -u https://example.com/login -o report.json -of json
python3 main.py -u https://example.com/login -o report.html -of html
```

## Testing

HTLogin includes a comprehensive test suite. To run the tests:

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest

# Run tests with coverage report
pytest --cov=. --cov-report=html
```

For more information about the test suite, see [tests/README.md](tests/README.md).

> [!NOTE]
> In minimal environments where `pytest` is not available, you can still perform a quick syntax check with:
> ```bash
> python -m py_compile $(git ls-files '*.py')
> ```

## Known Limitations

- **Registration Pages**:
  - Registration/signup pages are automatically detected and skipped to avoid false positives. These pages use different authentication flows than login pages (account creation vs. authentication) and should be tested separately.
- **Cloudflare / WAF**:
  - HTLogin uses realistic headers and optional `cloudscraper` support to improve compatibility, but some advanced JavaScript challenges or custom WAF rules may still block automated scanners.
  - In such cases, Selenium may help to render the page, but full bypass is not guaranteed.
- **MFA / 2FA**:
  - Multi-factor authentication flows (email/SMS/OTP/authenticator apps) are not automatically solved; HTLogin only reports login behaviour and basic signals.
- **Very custom login flows**:
  - Highly customized or multi-step login flows (SAML/OIDC redirects, external IdPs, popups) may require manual analysis; HTLogin focuses on classic form- and API-based logins.

## Disclaimer

HTLogin is intended for educational purposes and authorized security testing only.
Do not use this tool against systems without explicit permission.
The author is not responsible for misuse or damage caused by this tool.
