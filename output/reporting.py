import json
import html as html_module
from datetime import datetime
from typing import List, Dict, Any, Optional

from core.results import ScanResult
from detection.success import DetectionResult, ConfidenceLevel


class ReportGenerator:
    def __init__(self):
        pass

    def generate_json(self, results_list: List[ScanResult]) -> Dict[str, Any]:
        total_duration = 0.0
        total_requests = 0
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        report = {
            "metadata": {
                "tool": "HTLogin",
                "version": "1.1.1",
                "generated_at": datetime.now().isoformat(),
                "total_targets": len(results_list)
            },
            "executive_summary": {
                "total_targets": len(results_list),
                "total_duration_seconds": 0.0,
                "total_requests": 0,
                "findings_by_severity": severity_counts.copy()
            },
            "targets": []
        }

        for result in results_list:
            result_dict = result.to_dict() if isinstance(result, ScanResult) else result
            target_summary = result_dict.get("summary", {})
            total_duration += float(result_dict.get("duration_seconds", 0) or 0)
            total_requests += int(target_summary.get("total_requests", 0) or 0)
            target_report = {
                "url": result_dict.get("url", "Unknown"),
                "start_time": result_dict.get("start_time"),
                "end_time": result_dict.get("end_time"),
                "duration_seconds": result_dict.get("duration_seconds", 0),
                "error": result_dict.get("error"),
                "summary": target_summary,
                "vulnerabilities": [],
                "tests": {},
                "security_context": {
                    "blocked_on_initial_request": bool(str(result_dict.get("error", "")).lower().find("rate limit detected (429) on initial request") >= 0),
                    "rate_limited_at": None,
                    "waf_detected": False,
                    "captcha_detected": bool(result_dict.get("captcha_detected", False)),
                }
            }

            for test_name, test_result in result_dict.get("tests", {}).items():
                test_report = {
                    "test_type": test_name,
                    "status": test_result.get("status", "Unknown"),
                    "confidence_score": test_result.get("confidence_score", 0),
                    "confidence_level": test_result.get("confidence_level", "Unknown"),
                    "manual_verification_recommended": test_result.get("manual_verification_recommended", False),
                    "details": test_result.get("details", {})
                }

                if test_name == "Rate Limit Test":
                    status_lower = (test_result.get("status") or "").lower()
                    if status_lower.startswith("rate limited at request #"):
                        try:
                            target_report["security_context"]["rate_limited_at"] = int(status_lower.split("#")[-1])
                        except ValueError:
                            target_report["security_context"]["rate_limited_at"] = None
                    rl_details = test_result.get("details", {}) if isinstance(test_result.get("details"), dict) else {}
                    rl_is_vulnerable = rl_details.get("is_vulnerable")
                    if rl_is_vulnerable is None and "vulnerability" in rl_details:
                        rl_is_vulnerable = bool(rl_details.get("vulnerability"))
                    if rl_is_vulnerable is None:
                        rl_is_vulnerable = status_lower.startswith("no rate limit")

                    if rl_is_vulnerable:
                        rl_confidence_level = test_result.get("confidence_level") or rl_details.get("confidence") or "Unknown"
                        rl_confidence_score = test_result.get("confidence_score")
                        if rl_confidence_score is None:
                            rl_confidence_score = rl_details.get("confidence_score")
                        if rl_confidence_score is None:
                            rl_confidence_score = {
                                "high": 80,
                                "medium": 70,
                                "low": 40,
                            }.get(str(rl_confidence_level).lower(), 0)
                        vulnerability = {
                            "type": test_name,
                            "finding_type": "rate_limit_missing_or_weak",
                            "severity": "Medium",
                            "confidence": rl_confidence_level,
                            "confidence_score": rl_confidence_score,
                            "payload": None,
                            "indicators": [],
                            "manual_verification_recommended": False,
                            "evidence": self._build_evidence(test_name, test_result),
                            "actionability": {
                                "auto_confidence": "medium",
                                "manual_verification_required": False,
                                "next_step": "Increase request volume and verify absence of blocking/challenge responses."
                            },
                        }
                        target_report["vulnerabilities"].append(vulnerability)
                        severity_counts["Medium"] = severity_counts.get("Medium", 0) + 1

                if test_name != "Rate Limit Test" and test_result.get("status") == "Successful":
                    confidence_level = test_result.get("confidence_level", "Unknown")
                    severity = self._determine_severity(confidence_level)
                    finding_type = self._map_finding_type(test_name)
                    evidence = self._build_evidence(test_name, test_result)
                    vulnerability = {
                        "type": test_name,
                        "finding_type": finding_type,
                        "severity": severity,
                        "confidence": confidence_level,
                        "confidence_score": test_result.get("confidence_score", 0),
                        "payload": test_result.get("payload") or test_result.get("credential"),
                        "indicators": test_result.get("details", {}).get("indicators", []),
                        "manual_verification_recommended": test_result.get("manual_verification_recommended", False),
                        "evidence": evidence,
                        "actionability": self._build_actionability(test_result),
                    }
                    target_report["vulnerabilities"].append(vulnerability)
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    if any("waf" in str(ind).lower() for ind in vulnerability.get("indicators", [])):
                        target_report["security_context"]["waf_detected"] = True

                target_report["tests"][test_name] = test_report

            enum_result = result_dict.get("username_enumeration")
            if isinstance(enum_result, dict) and enum_result.get("vulnerable"):
                enum_details = enum_result.get("details", {})
                enum_vuln = {
                    "type": "Username Enumeration",
                    "finding_type": "username_enumeration",
                    "severity": "Medium",
                    "confidence": "High",
                    "confidence_score": 80,
                    "payload": enum_details.get("test_username"),
                    "indicators": enum_details.get("indicator_found", []),
                    "manual_verification_recommended": False,
                    "evidence": {
                        "status_code": enum_details.get("status_code"),
                        "response_preview": enum_details.get("response_text"),
                    },
                    "actionability": {
                        "auto_confidence": "high",
                        "manual_verification_required": False,
                        "next_step": "Verify distinct error behavior for invalid username vs invalid password."
                    },
                }
                target_report["vulnerabilities"].append(enum_vuln)
                severity_counts["Medium"] = severity_counts.get("Medium", 0) + 1

            report["targets"].append(target_report)

        report["executive_summary"] = {
            "total_targets": len(results_list),
            "total_duration_seconds": round(total_duration, 3),
            "total_requests": total_requests,
            "findings_by_severity": severity_counts
        }

        return report

    def _map_finding_type(self, test_name: str) -> str:
        mapping = {
            "Default Credentials": "default_credential",
            "SQL Injection": "sqli_bypass",
            "NoSQL Injection": "nosqli_bypass",
            "XPath Injection": "xpath_bypass",
            "LDAP Injection": "ldap_bypass",
            "JSON API Login": "json_api_auth_bypass",
            "GraphQL Login": "graphql_auth_bypass",
            "Rate Limit Test": "rate_limit_missing_or_weak",
        }
        return mapping.get(test_name, test_name.lower().replace(" ", "_"))

    def _build_evidence(self, test_name: str, test_result: Dict[str, Any]) -> Dict[str, Any]:
        details = test_result.get("details", {}) if isinstance(test_result.get("details"), dict) else {}
        evidence = {
            "status_code": details.get("status_code") or details.get("response_status"),
            "endpoint": test_result.get("endpoint") or details.get("endpoint"),
            "indicators": details.get("indicators", []),
            "redirect_url": details.get("redirect_url"),
            "session_cookie_name": details.get("session_cookie_name"),
        }
        if test_name == "Rate Limit Test":
            evidence["rate_limit"] = {
                "blocked_at_request_count": details.get("blocked_at_request_count"),
                "detected_headers": details.get("detected_headers"),
                "status_codes": details.get("status_codes"),
            }
        return evidence

    def _build_actionability(self, test_result: Dict[str, Any]) -> Dict[str, Any]:
        conf_level = str(test_result.get("confidence_level", "Unknown")).lower()
        if conf_level == "high":
            auto_conf = "high"
        elif conf_level == "medium":
            auto_conf = "medium"
        else:
            auto_conf = "low"
        manual_required = bool(test_result.get("manual_verification_recommended", False))
        next_step = "Replay request and validate auth state transition (redirect/session/token)."
        return {
            "auto_confidence": auto_conf,
            "manual_verification_required": manual_required,
            "next_step": next_step
        }

    def generate_html(self, results_list: List[ScanResult]) -> str:
        html_content = self._get_html_template()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_content = html_content.replace("{timestamp}", timestamp)

        content = ""
        for result in results_list:
            result_dict = result.to_dict() if isinstance(result, ScanResult) else result
            content += self._generate_target_html(result_dict)

        html_content = html_content.replace("{content}", content)

        return html_content

    def _generate_target_html(self, result: Dict[str, Any]) -> str:
        if "error" in result:
            error_msg = html_module.escape(str(result.get('error', '')))
            url = html_module.escape(str(result.get('url', 'Unknown URL')))
            return f"""
        <div class="test-result failed">
            <div class="test-name">Error for {url}</div>
            <div class="test-details">{error_msg}</div>
        </div>
"""

        url_escaped = html_module.escape(str(result.get('url', 'Unknown')))
        html_content = f"""
        <h2>Target: {url_escaped}</h2>
        <div class="summary">
            <div class="summary-item"><strong>Total Tests:</strong> {result['summary'].get('total_tests', 0)}</div>
            <div class="summary-item"><strong>Successful:</strong> {result['summary'].get('successful', 0)}</div>
            <div class="summary-item"><strong>Failed:</strong> {result['summary'].get('failed', 0)}</div>
            <div class="summary-item"><strong>Duration:</strong> {result.get('duration_seconds', 0):.2f} seconds</div>
        </div>
"""

        for test_name, test_result in result.get("tests", {}).items():
            html_content += self._generate_test_html(test_name, test_result)

        return html_content

    def _generate_test_html(self, test_name: str, test_result: Dict[str, Any]) -> str:
        status = test_result.get("status", "Unknown")
        css_class = 'success' if status == 'Successful' else 'failed' if status == 'Failed' else 'rate-limited'

        html_content = f"""
        <div class="test-result {css_class}">
            <div class="test-name">
                {test_name}: {status}
"""

        if 'confidence_level' in test_result:
            conf_level = test_result['confidence_level'].lower()
            conf_class = self._get_confidence_class(conf_level)
            conf_score = test_result.get('confidence_score', 0)
            html_content += f'<span class="confidence {conf_class}">Confidence: {conf_level.title()} ({conf_score})</span>'

            if test_result.get('manual_verification_recommended'):
                html_content += '<span class="manual-verify">⚠ Manual Verification Recommended</span>'

        html_content += """
            </div>
            <div class="test-details">
"""

        if 'payload' in test_result and test_result['payload']:
            payload_escaped = html_module.escape(str(test_result["payload"]))
            html_content += f'<div><strong>Payload:</strong> <code>{payload_escaped}</code></div>'
        if 'credential' in test_result and test_result['credential']:
            credential_escaped = html_module.escape(str(test_result["credential"]))
            html_content += f'<div><strong>Credential:</strong> <code>{credential_escaped}</code></div>'
        if 'total_duration' in test_result:
            html_content += f'<div><strong>Test Duration:</strong> {test_result["total_duration"]:.2f} seconds</div>'

        indicators = test_result.get('details', {}).get('indicators', [])
        if indicators:
            indicators_escaped = [html_module.escape(str(ind)) for ind in indicators]
            html_content += f'<div><strong>Indicators:</strong> {", ".join(indicators_escaped)}</div>'

        if test_result.get('limitations'):
            limitations_escaped = html_module.escape(str(test_result["limitations"]))
            html_content += f'<div class="limitations"><strong>Limitations:</strong> {limitations_escaped}</div>'

        html_content += """
            </div>
        </div>
"""
        return html_content

    def _get_confidence_class(self, level: str) -> str:
        level_lower = level.lower()
        if level_lower == 'high':
            return 'confidence-high'
        elif level_lower == 'medium':
            return 'confidence-medium'
        else:
            return 'confidence-low'

    def _determine_severity(self, confidence_level: str) -> str:
        level_lower = confidence_level.lower()
        if level_lower == 'high':
            return 'High'
        elif level_lower == 'medium':
            return 'Medium'
        else:
            return 'Low'

    def _get_html_template(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTLogin Test Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
        }
        .test-result {
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #ddd;
            background-color: #f9f9f9;
        }
        .success {
            border-left-color: #4CAF50;
            background-color: #e8f5e9;
        }
        .failed {
            border-left-color: #f44336;
            background-color: #ffebee;
        }
        .rate-limited {
            border-left-color: #ff9800;
            background-color: #fff3e0;
        }
        .test-name {
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
        }
        .test-details {
            margin-top: 10px;
            color: #666;
        }
        .confidence {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
            margin-left: 10px;
        }
        .confidence-high {
            background-color: #4CAF50;
            color: white;
        }
        .confidence-medium {
            background-color: #ff9800;
            color: white;
        }
        .confidence-low {
            background-color: #f44336;
            color: white;
        }
        .manual-verify {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
            margin-left: 10px;
            background-color: #ff9800;
            color: white;
        }
        .summary {
            background-color: #e3f2fd;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .summary-item {
            margin: 10px 0;
        }
        .timestamp {
            color: #999;
            font-size: 0.9em;
        }
        .limitations {
            margin-top: 10px;
            padding: 10px;
            background-color: #fff3cd;
            border-left: 3px solid #ffc107;
            border-radius: 3px;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>HTLogin Security Test Report</h1>
        <div class="timestamp">Generated: {timestamp}</div>
        {content}
    </div>
</body>
</html>
"""


def save_output(output: Any, filename: str, format_type: str = 'text') -> None:
    if format_type == 'json':
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
    elif format_type == 'html':
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output)
    else:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(str(output))

