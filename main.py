import argparse
import os
import sys
from typing import List, Optional

from config import Config, get_config, DEFAULT_CONFIG
from config.constants import BANNER
from utils.logging import setup_logging
from utils.language import load_language_keywords
from utils.colors import Colors
from domain.auth import CredentialProviderProtocol, DefaultCredentialProvider, CustomCredentialProvider
from core.scanner import LoginScanner
from core.runner import ScanRunner
from output.reporting import ReportGenerator, save_output
from output.cli import CLIOutput


def _configure_console_encoding() -> None:
    """Keep CLI output usable on Windows consoles with a legacy code page."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


_configure_console_encoding()

if not sys.stdout.isatty():
    Colors.disable()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find and test login form for various vulnerabilities")

    parser.add_argument("-u", "--url", help="URL to inspect and test")
    parser.add_argument("-l", "--list", help="Path to file containing list of URLs")
    parser.add_argument("-cl", "--credential-list", help="Path to custom credential list file")
    parser.add_argument("-r", "--rate-limit", type=int, default=DEFAULT_CONFIG['rate_limit_requests'],
                       help="Number of requests for rate limiting test (default: 10)")
    parser.add_argument("-v", "--verbose", choices=['on', 'off'], default='off',
                       help="Enable/disable verbose output (on/off)")
    parser.add_argument("-lang", "--language", default=DEFAULT_CONFIG['language'],
                       help="Language code for keyword detection (default: en)")
    parser.add_argument("-o", "--output", nargs='?', const='output.txt',
                       help="Save output to file")
    parser.add_argument("-of", "--output-format", choices=['text', 'json', 'html'],
                       default=DEFAULT_CONFIG['output_format'],
                       help="Output format (default: text)")
    parser.add_argument("-p", "--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_CONFIG['timeout'],
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("-hm", "--http-method", choices=['GET', 'POST'],
                       default=DEFAULT_CONFIG['http_method'],
                       help="HTTP method to use for testing (default: POST)")
    parser.add_argument("--log", help="Path to log file (optional)")
    parser.add_argument("--no-progress", action="store_true",
                       help="Disable progress bar")
    parser.add_argument("--config", help="Path to configuration file (JSON)")
    parser.add_argument("--use-selenium", action="store_true",
                       help="Use Selenium to render JavaScript (for SPA applications)")
    parser.add_argument("--selenium-wait-time", type=int, default=5,
                       help="Selenium page load wait time in seconds (default: 5)")
    parser.add_argument("--user-agent", type=str, default=None,
                       help="Custom User-Agent string for HTTP requests")
    parser.add_argument("-m", "--mode", choices=['quick', 'full'], default='quick',
                       help="Scan mode: quick (stop at first success) or full (test all payloads)")
    parser.add_argument("-k", "--insecure", action="store_true",
                       help="Allow insecure SSL connections (skip certificate verification)")
    parser.add_argument("--safe-mode", action="store_true",
                       help="Passive mode: inspect forms and endpoints without sending login/payload tests")
    parser.add_argument("--max-requests", type=int, default=DEFAULT_CONFIG.get('max_requests_per_target', 200),
                       help="Maximum HTTP requests per target (default: 200; 0 disables the budget)")

    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> int:
    if args.url and args.list:
        CLIOutput.print_error("Both -u/--url and -l/--list parameters were provided.")
        CLIOutput.print_error("Please use either -u/--url for a single URL or -l/--list for multiple URLs, not both.")
        return 1

    if not args.url and not args.list:
        CLIOutput.print_error("Either -u/--url or -l/--list is required")
        return 1

    if args.max_requests < 0:
        CLIOutput.print_error("--max-requests must be zero or greater")
        return 1

    if args.rate_limit < 0:
        CLIOutput.print_error("--rate-limit must be zero or greater")
        return 1

    return 0


def create_cli_config(args: argparse.Namespace) -> dict:
    verbose_mode = args.verbose.lower() == 'on'
    return {
        'timeout': args.timeout,
        'rate_limit_requests': args.rate_limit,
        'verbose': verbose_mode,
        'show_progress': not args.no_progress,
        'http_method': args.http_method,
        'language': args.language.lower(),
        'output_format': args.output_format,
        'output_file': args.output,
        'log_file': args.log,
        'proxy': args.proxy,
        'credential_list_file': args.credential_list,
        'use_selenium': args.use_selenium if hasattr(args, 'use_selenium') else False,
        'selenium_wait_time': args.selenium_wait_time if hasattr(args, 'selenium_wait_time') else 5,
        'user_agent': args.user_agent if hasattr(args, 'user_agent') else None,
        'scan_mode': args.mode if hasattr(args, 'mode') else 'quick',
        'verify_ssl': not args.insecure if hasattr(args, 'insecure') else True,
        'safe_mode': args.safe_mode,
        'max_requests_per_target': args.max_requests,
    }


def create_credential_provider(filepath: Optional[str]) -> CredentialProviderProtocol:
    if filepath:
        return CustomCredentialProvider(filepath)
    return DefaultCredentialProvider()


def load_urls_from_file(filepath: str) -> tuple[List[str], int]:
    try:
        from urllib.parse import urlparse
        from utils.logging import get_logger

        logger = get_logger()
        valid_urls = []
        invalid_urls = []

        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                url = line.strip()

                if not url:
                    continue

                url_normalized = url.rstrip('/')
                if url_normalized.lower().startswith('http://'):
                    url_normalized = 'http://' + url_normalized[7:]
                elif url_normalized.lower().startswith('https://'):
                    url_normalized = 'https://' + url_normalized[8:]

                try:
                    parsed = urlparse(url_normalized)

                    if parsed.scheme not in ['http', 'https']:
                        invalid_urls.append((line_num, url, f"Invalid scheme: {parsed.scheme}. Only http:// and https:// are supported."))
                        continue

                    if not parsed.netloc:
                        invalid_urls.append((line_num, url, "Missing domain/hostname"))
                        continue

                    if len(url_normalized) > 2048:
                        invalid_urls.append((line_num, url, "URL too long (max 2048 characters)"))
                        continue

                    valid_urls.append(url_normalized)

                except Exception as e:
                    invalid_urls.append((line_num, url, f"Invalid URL format: {str(e)}"))
                    continue

        if invalid_urls:
            for line_num, invalid_url, reason in invalid_urls:
                logger.warning(f"Line {line_num}: Skipping invalid URL '{invalid_url}': {reason}")

        if not valid_urls:
            CLIOutput.print_error("No valid URLs found in the list file. All URLs were invalid or empty.")
            return [], 1

        return valid_urls, 0

    except FileNotFoundError:
        CLIOutput.print_error(f"URL list file not found: {filepath}")
        return [], 1
    except Exception as e:
        CLIOutput.print_error(f"Error reading URL list file: {e}")
        return [], 1


def determine_output_format(output_file: Optional[str], format_arg: str) -> str:
    if output_file:
        if output_file.endswith('.json'):
            return 'json'
        elif output_file.endswith('.html'):
            return 'html'
    return format_arg


def _format_payload_for_summary(test_result: dict) -> Optional[str]:
    sp = test_result.get("successful_payloads") or []
    ed = test_result.get("error_disclosures") or []
    n = len(sp) + len(ed)
    base = test_result.get("payload")
    if base is None or base == "":
        if sp:
            base = sp[0]
        elif ed:
            base = ed[0]
        else:
            return None
    base = str(base)
    if n > 1:
        return f"{base} (+{n - 1} more)"
    return base


def main() -> int:
    args = parse_arguments()

    exit_code = validate_arguments(args)
    if exit_code != 0:
        return exit_code

    CLIOutput.print_banner(BANNER)

    verbose_mode = args.verbose.lower() == 'on'
    logger = setup_logging(log_file=args.log, verbose=verbose_mode)
    logger.info("HTLogin started")

    try:
        language_keywords = load_language_keywords(language_code=args.language.lower())
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        CLIOutput.print_error(str(e))
        logger.error(str(e))
        return 1

    cli_config = create_cli_config(args)
    config = get_config(cli_config, args.config)

    try:
        credential_provider = create_credential_provider(args.credential_list)
    except (FileNotFoundError, RuntimeError) as e:
        CLIOutput.print_error(str(e))
        logger.error(str(e))
        return 1

    scanner = LoginScanner(config, language_keywords, credential_provider)
    runner = ScanRunner(scanner, credential_provider)
    report_generator = ReportGenerator()
    cli_output = CLIOutput()

    urls: List[str] = []

    if args.list:
        urls, exit_code = load_urls_from_file(args.list)
        if exit_code != 0:
            return exit_code

        if not urls:
            CLIOutput.print_error("No valid URLs found in the list file. Please check the file and ensure it contains valid URLs (http:// or https://).")
            return 1

        logger.info(f"Loaded {len(urls)} URLs from list")
        CLIOutput.print_info(f"Total targets in list: {len(urls)}")
    else:
        from urllib.parse import urlparse
        parsed = urlparse(args.url)
        if parsed.scheme not in ['http', 'https']:
            CLIOutput.print_error(f"Invalid URL scheme: {parsed.scheme}. Only http:// and https:// are supported.")
            return 1
        if not parsed.netloc:
            CLIOutput.print_error("Invalid URL: Missing domain/hostname")
            return 1
        if len(args.url) > 2048:
            CLIOutput.print_error("URL too long (max 2048 characters)")
            return 1

        urls = [args.url]

    results: List = []

    for i, url in enumerate(urls, 1):
        cli_output.print_target_header(url, i, len(urls))

        result = runner.run_single(url)
        results.append(result)

        if result.error:
            CLIOutput.print_error(f"Error for {url}: {result.error}")
        elif result.discovered_pages:
            cli_output.print_discovery_attempt()
            cli_output.print_discovered_pages(result.discovered_pages)
            cli_output.print_discovered_pages_header(len(result.discovered_pages))
            for j, discovered_url in enumerate(result.discovered_pages, 1):
                cli_output.print_discovered_page(discovered_url, j, len(result.discovered_pages))
                discovered_result = runner.run_single(discovered_url)
                results.append(discovered_result)
                if discovered_result.error:
                    CLIOutput.print_error(f"Error for {discovered_url}: {discovered_result.error}")
                else:
                    cli_output.print_summary(discovered_result)
        else:
            if result.form_info:
                cli_output.print_form_info(
                    result.form_info.get("username_field", "N/A"),
                    result.form_info.get("password_field", "N/A"),
                    result.form_info.get("csrf_found", False),
                    result.form_info.get("captcha_found", False)
                )
            cli_output.print_summary(result)

    scanned_targets = [r for r in results if not r.error and not r.discovered_pages]
    if scanned_targets:
        total_targets = len(scanned_targets)
        total_duration = sum(r.duration_seconds for r in results if r.duration_seconds)
        total_requests = sum(
            r.summary.get("total_requests", 0)
            for r in results
            if r.summary and "total_requests" in r.summary
        )

        vulnerable_targets = []
        for target in scanned_targets:
            vulnerabilities = []

            if target.username_enumeration and target.username_enumeration.get("vulnerable"):
                vuln_info = {
                    "name": "Username Enumeration",
                    "type": "enumeration",
                    "details": target.username_enumeration.get("details", {})
                }
                vulnerabilities.append(vuln_info)

            if target.tests:
                for test_name, test_result in target.tests.items():
                    if test_result.get("status") == "Successful":
                        vuln_info = {
                            "name": test_name,
                            "type": "injection" if "Injection" in test_name else "credential",
                            "payload": _format_payload_for_summary(test_result),
                            "credential": test_result.get("credential"),
                            "details": test_result
                        }
                        vulnerabilities.append(vuln_info)

            additional_tests = {}

            if target.tests and "Rate Limit Test" in target.tests:
                rl_test = target.tests["Rate Limit Test"]
                rl_status = rl_test.get("status", "Unknown")
                additional_tests["Rate Limit"] = {
                    "status": rl_status
                }

            if target.captcha_detected is not None:
                additional_tests["CAPTCHA"] = {
                    "status": "Detected" if target.captcha_detected else "Not Detected"
                }

            if target.form_info and target.form_info.get("csrf_found") is not None:
                additional_tests["CSRF"] = {
                    "status": "Protected" if target.form_info.get("csrf_found") else "Vulnerable"
                }

            if vulnerabilities or additional_tests:
                vulnerable_targets.append({
                    "url": target.url,
                    "vulnerabilities": vulnerabilities,
                    "additional_tests": additional_tests
                })

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}Final Summary{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        print(f"{Colors.DIM}Total targets:{Colors.RESET} {Colors.BOLD}{total_targets}{Colors.RESET}")
        if scanned_targets:
            for target in scanned_targets:
                print(f"  {Colors.BRIGHT_CYAN}{target.url}{Colors.RESET}")

        if vulnerable_targets:
            total_vulnerabilities = 0
            for vuln_target in vulnerable_targets:
                total_vulnerabilities += len(vuln_target['vulnerabilities'])
                if vuln_target.get('additional_tests'):
                    for test_name, test_info in vuln_target['additional_tests'].items():
                        status = test_info.get("status", "Unknown")
                        if test_name == "CAPTCHA" and status == "Not Detected":
                            total_vulnerabilities += 1
                        elif test_name == "CSRF" and status == "Vulnerable":
                            total_vulnerabilities += 1
                        elif test_name == "Rate Limit" and status.startswith("No rate limit"):
                            total_vulnerabilities += 1

            print(f"\n{Colors.BOLD}{Colors.YELLOW}⚠ Total Vulnerabilities Found: {total_vulnerabilities}{Colors.RESET}\n")
            for vuln_target in vulnerable_targets:
                print(f"  {Colors.BRIGHT_CYAN}{vuln_target['url']}{Colors.RESET}")

                for vuln in vuln_target['vulnerabilities']:
                    status_text = "Vulnerable" if vuln['name'] == "Username Enumeration" else "Successful"
                    print(f"    {Colors.GREEN}✓{Colors.RESET} {Colors.YELLOW}{vuln['name']}{Colors.RESET}: {status_text}")

                    if vuln.get("payload"):
                        print(f"      {Colors.DIM}Payload:{Colors.RESET} {Colors.BRIGHT_CYAN}{vuln['payload']}{Colors.RESET}")

                    if vuln.get("credential"):
                        print(f"      {Colors.DIM}Credential:{Colors.RESET} {Colors.BRIGHT_CYAN}{vuln['credential']}{Colors.RESET}")

                    if vuln['name'] == "Username Enumeration" and vuln.get("details"):
                        details = vuln['details']
                        if details.get("test_username"):
                            print(f"      {Colors.DIM}Test Username:{Colors.RESET} {Colors.BRIGHT_CYAN}{details['test_username']}{Colors.RESET}")
                        if details.get("indicator_found"):
                            indicators = details['indicator_found']
                            if isinstance(indicators, list):
                                print(f"      {Colors.DIM}Indicators:{Colors.RESET} {Colors.BRIGHT_CYAN}{', '.join(indicators)}{Colors.RESET}")

                if vuln_target.get('additional_tests'):
                    for test_name, test_info in vuln_target['additional_tests'].items():
                        status = test_info.get("status", "Unknown")
                        if test_name == "Rate Limit":
                            if status.startswith("No rate limit"):
                                print(f"    {Colors.GREEN}✓{Colors.RESET} {Colors.YELLOW}{test_name}{Colors.RESET}: {Colors.RED}{status}{Colors.RESET}")
                            else:
                                print(f"    {Colors.RED}✗{Colors.RESET} {Colors.YELLOW}{test_name}{Colors.RESET}: {Colors.GREEN}{status}{Colors.RESET}")
                        elif test_name == "CAPTCHA":
                            if status == "Detected":
                                print(f"    {Colors.RED}✗{Colors.RESET} {Colors.YELLOW}{test_name}{Colors.RESET}: {Colors.GREEN}{status}{Colors.RESET} (Protected)")
                            else:
                                print(f"    {Colors.GREEN}✓{Colors.RESET} {Colors.YELLOW}{test_name}{Colors.RESET}: {Colors.RED}{status}{Colors.RESET}")
                        elif test_name == "CSRF":
                            if status == "Vulnerable":
                                print(f"    {Colors.GREEN}✓{Colors.RESET} {Colors.YELLOW}{test_name}{Colors.RESET}: {Colors.RED}{status}{Colors.RESET}")
                            else:
                                print(f"    {Colors.RED}✗{Colors.RESET} {Colors.YELLOW}{test_name}{Colors.RESET}: {Colors.GREEN}{status}{Colors.RESET}")
        else:
            print(f"\n{Colors.BOLD}{Colors.GREEN}✓ No vulnerabilities found across all targets.{Colors.RESET}\n")

        print(f"\n{Colors.DIM}Total duration:{Colors.RESET} {Colors.BOLD}{total_duration:.2f} seconds{Colors.RESET}")
        if total_requests > 0:
            print(f"{Colors.DIM}Total requests:{Colors.RESET} {Colors.BOLD}{total_requests}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*60}{Colors.RESET}\n")

    if args.output:
        output_format = determine_output_format(args.output, args.output_format)

        if output_format == 'json':
            json_output = report_generator.generate_json(results)
            save_output(json_output, args.output, 'json')
            cli_output.print_file_saved(args.output, 'JSON')
        elif output_format == 'html':
            html_output = report_generator.generate_html(results)
            save_output(html_output, args.output, 'html')
            cli_output.print_file_saved(args.output, 'HTML')
        else:
            output_text = ""
            for result in results:
                result_dict = result.to_dict() if hasattr(result, 'to_dict') else result
                if result_dict.get("error"):
                    output_text += f"Error for {result_dict.get('url', 'Unknown')}: {result_dict['error']}\n"
                else:
                    output_text += f"\nTarget: {result_dict.get('url', 'Unknown')}\n"
                    output_text += f"Duration: {result_dict.get('duration_seconds', 0):.2f} seconds\n"
                    output_text += "Results:\n"
                    for test_name, test_result in result_dict.get('tests', {}).items():
                        status = test_result.get('status', 'Unknown')
                        output_text += f"  {test_name}: {status}\n"
                        if 'confidence_score' in test_result:
                            output_text += f"    Confidence: {test_result['confidence_level']} ({test_result['confidence_score']})\n"
            save_output(output_text, args.output, 'text')
            cli_output.print_file_saved(args.output, 'Text')

    return 0


if __name__ == "__main__":
    sys.exit(main())
