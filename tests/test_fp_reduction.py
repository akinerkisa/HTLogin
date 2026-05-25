from unittest.mock import Mock
from detection.success import LoginSuccessDetector
from detection.signals import SignalType


class TestFPReduction:
    def test_waf_detection_trigger(self):
        # 1. Test WAF status code (403 with cloudflare/waf keywords)
        response_waf = Mock()
        response_waf.status_code = 403
        response_waf.headers = {"Server": "cloudflare"}
        response_waf.text = "Error 1020: Access Denied. Your IP is blocked by Cloudflare WAF."
        response_waf.url = "http://example.com/login"
        response_waf.cookies = {}

        detector = LoginSuccessDetector()
        result = detector.detect(
            response=response_waf,
            original_url="http://example.com/login",
            original_content_length=500,
            success_keywords=["welcome"],
            failure_keywords=["error", "denied"]
        )

        # WAF blocked is a very strong negative signal. It should clamp the final score to 0.
        assert result.confidence_score == 0
        assert result.is_successful is False
        assert any(sig.name == "waf_blocked" for sig in result.signals)

    def test_jaccard_similarity_mitigation(self):
        # 2. Test similarity subtraction (Jaccard > 85% similar to invalid probe text)
        invalid_text = "<html><head><title>Login Page</title></head><body><h1>Login Failed</h1><p>Incorrect credentials</p><div class='footer'>Copyright 2026</div></body></html>"
        
        # Only a one-word difference (xyz instead of credentials) to yield high vocabulary similarity
        current_text = "<html><head><title>Login Page</title></head><body><h1>Login Failed</h1><p>Incorrect xyz</p><div class='footer'>Copyright 2026</div></body></html>"

        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.cookies = {}
        response.text = current_text
        response.url = "http://example.com/login"

        detector = LoginSuccessDetector()
        detector.set_invalid_probe_result(
            invalid_cookies=[],
            invalid_text=invalid_text,
            invalid_status=200
        )

        result = detector.detect(
            response=response,
            original_url="http://example.com/login",
            original_content_length=len(invalid_text),
            success_keywords=[],
            failure_keywords=[]
        )

        # It should trigger the similar_to_failed_probe negative signal
        assert any(sig.name == "similar_to_failed_probe" for sig in result.signals)
        # Check that it reduces the score
        sim_sig = next(sig for sig in result.signals if sig.name == "similar_to_failed_probe")
        assert sim_sig.confidence == 40
        assert sim_sig.signal_type == SignalType.NEGATIVE

    def test_failed_cookie_filtering(self):
        # 3. Test that session cookies set on a failed probe are ignored
        detector = LoginSuccessDetector()
        
        # Set invalid probe cookies (e.g., 'session_id' was generated on a failed login probe)
        detector.set_invalid_probe_result(
            invalid_cookies=['session_id'],
            invalid_text="failed",
            invalid_status=200
        )

        # Now mock a response that sets the same cookie
        response = Mock()
        response.status_code = 200
        response.headers = {"set-cookie": "session_id=12345; HttpOnly"}
        response.cookies = {"session_id": "12345"}
        response.text = "Welcome to dashboard!"
        response.url = "http://example.com/dashboard"

        result = detector.detect(
            response=response,
            original_url="http://example.com/login",
            original_content_length=100,
            success_keywords=["welcome", "dashboard"],
            failure_keywords=["error"]
        )

        # The 'session_id' cookie should be completely filtered out/ignored
        assert not any(sig.name == "session_cookie" for sig in result.signals)
