from unittest.mock import Mock

import responses

from config.settings import Config
from core.scanner import LoginScanner
from domain.http.request_sender import RequestSender
from domain.http.retry_policy import RetryPolicy


def test_config_defaults_include_safe_mode_and_request_budget():
    config = Config.from_dict({})

    assert config.safe_mode is False
    assert config.max_requests_per_target == 200


def test_request_sender_stops_after_budget_is_exhausted():
    session = Mock()
    response = Mock(status_code=200, text="ok", headers={})
    session.request.return_value = response
    sender = RequestSender(session, RetryPolicy(max_retries=0), max_requests=2)

    assert sender.get("https://example.test/one") is response
    assert sender.get("https://example.test/two") is response
    assert sender.get("https://example.test/three") is None
    assert sender.request_count == 2
    assert session.request.call_count == 2


@responses.activate
def test_safe_mode_does_not_send_active_probe_requests():
    url = "https://example.test/login"
    responses.add(
        responses.GET,
        url,
        body='<form action="/login" method="post"><input name="username"><input type="password" name="password"></form>',
        status=200,
        content_type="text/html",
    )

    config = Config(safe_mode=True, max_requests_per_target=10, show_progress=False)
    scanner = LoginScanner(config, {"success": [], "failure": [], "login_keywords": []})
    result = scanner.scan(url)

    assert result["tests"]["Passive Inspection"]["status"] == "Completed"
    assert all(call.request.method == "GET" for call in responses.calls)


def test_auth_feature_detection_is_passive():
    features = LoginScanner._detect_auth_features(
        "https://login.example.test/authorize",
        "Continue with OAuth. Enter your one-time password. SAMLResponse is accepted.",
    )

    assert features["mfa_or_2fa_detected"] is True
    assert features["oauth_or_oidc_detected"] is True
    assert features["saml_detected"] is True
