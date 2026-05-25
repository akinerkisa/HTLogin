from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from utils.logging import get_logger

from .signals import SignalCollector, SignalType, Signal

logger = get_logger()


class ConfidenceLevel(Enum):
    VERY_LOW = "Very Low"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class DetectionResult:
    is_successful: bool
    confidence_score: int
    confidence_level: ConfidenceLevel
    signals: List[Signal]
    details: Dict
    manual_verification_recommended: bool = False


class LoginSuccessDetector:
    def __init__(self,
                 threshold_low: int = 20,
                 threshold_medium: int = 30,
                 threshold_high: int = 50):
        self.threshold_low = threshold_low
        self.threshold_medium = threshold_medium
        self.threshold_high = threshold_high
        self.invalid_cookies = []
        self.invalid_text = ""
        self.invalid_status = 0

    def set_invalid_probe_result(self, invalid_cookies: List[str], invalid_text: str, invalid_status: int) -> None:
        self.invalid_cookies = invalid_cookies
        self.invalid_text = invalid_text
        self.invalid_status = invalid_status

    def detect(self, response, original_url: str, original_content_length: int,
               success_keywords: List[str], failure_keywords: List[str],
               client=None, language_keywords: Optional[Dict[str, List[str]]] = None,
               baseline_result: Optional[Dict[str, Any]] = None) -> DetectionResult:
        error_indicators = None
        login_indicators = None
        generic_indicators = None
        specific_indicators = None

        if language_keywords:
            error_indicators = language_keywords.get('error_indicators')
            login_indicators = language_keywords.get('login_indicators')
            generic_indicators = language_keywords.get('generic_indicators')
            specific_indicators = language_keywords.get('specific_indicators')

        collector = SignalCollector(
            response, original_url, original_content_length,
            success_keywords, failure_keywords, client,
            error_indicators=error_indicators,
            login_indicators=login_indicators,
            generic_indicators=generic_indicators,
            specific_indicators=specific_indicators,
            invalid_cookies=getattr(self, 'invalid_cookies', []),
            invalid_text=getattr(self, 'invalid_text', ""),
            invalid_status=getattr(self, 'invalid_status', 0)
        )
        signals = collector.collect_all()

        confidence_score = self._calculate_score(signals)


        if baseline_result:
            confidence_score = self._apply_baseline_normalization(
                confidence_score, signals, response, baseline_result
            )

        confidence_score = max(0, min(100, confidence_score))
        confidence_level = self._determine_level(confidence_score)
        is_successful = confidence_score >= self.threshold_high

        manual_verification = self._should_recommend_manual_verification(
            confidence_score, signals
        )

        status_code = response.status_code if response and hasattr(response, 'status_code') else 0
        details = {
            "status_code": status_code,
            "indicators": [s.description for s in signals],
            "positive_signals": len([s for s in signals if s.signal_type == SignalType.POSITIVE]),
            "negative_signals": len([s for s in signals if s.signal_type == SignalType.NEGATIVE]),
        }

        for signal in signals:
            if signal.name == "302_redirect_to_non_login":
                details["redirect_url"] = signal.value
            elif signal.name == "session_cookie":
                details["session_cookie_name"] = signal.value

        return DetectionResult(
            is_successful=is_successful,
            confidence_score=confidence_score,
            confidence_level=confidence_level,
            signals=signals,
            details=details,
            manual_verification_recommended=manual_verification
        )

    def _calculate_score(self, signals: List[Signal]) -> int:
        score = 0

        for signal in signals:
            if signal.signal_type == SignalType.POSITIVE:
                score += signal.confidence
            elif signal.signal_type == SignalType.NEGATIVE:
                score -= signal.confidence

        return score

    def _determine_level(self, score: int) -> ConfidenceLevel:
        if score >= self.threshold_high:
            return ConfidenceLevel.HIGH
        elif score >= self.threshold_medium:
            return ConfidenceLevel.MEDIUM
        elif score >= self.threshold_low:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def _should_recommend_manual_verification(self, score: int,
                                             signals: List[Signal]) -> bool:
        if self.threshold_medium <= score < self.threshold_high:
            return True

        positive_count = len([s for s in signals if s.signal_type == SignalType.POSITIVE])
        negative_count = len([s for s in signals if s.signal_type == SignalType.NEGATIVE])

        if positive_count > 0 and negative_count > 0:
            return True

        if score < self.threshold_medium and positive_count > 0:
            return True

        return False

    def _apply_baseline_normalization(self, current_score: int, signals: List[Signal],
                                     response, baseline_result: Dict[str, Any]) -> int:
        if not baseline_result:
            return current_score

        baseline_indicators = baseline_result.get("indicators", [])
        baseline_redirect = baseline_result.get("redirect_url")
        baseline_cookie = baseline_result.get("session_cookie")
        baseline_status = baseline_result.get("status_code", 0)


        current_redirect = None
        current_cookie = None
        current_status = response.status_code if response and hasattr(response, 'status_code') else 0

        for signal in signals:
            if signal.name == "302_redirect_to_non_login":
                current_redirect = signal.value
            elif signal.name == "session_cookie":
                current_cookie = signal.value

        similarity_bonus = 0


        if baseline_redirect and current_redirect:
            if str(baseline_redirect).lower() == str(current_redirect).lower():
                similarity_bonus += 15
            elif baseline_redirect and current_redirect:

                from urllib.parse import urlparse
                baseline_parsed = urlparse(str(baseline_redirect))
                current_parsed = urlparse(str(current_redirect))
                if baseline_parsed.netloc == current_parsed.netloc:
                    similarity_bonus += 10


        if baseline_cookie and current_cookie:
            if baseline_cookie == current_cookie:
                similarity_bonus += 10
            elif baseline_cookie and current_cookie:

                if any(keyword in str(baseline_cookie).lower() and keyword in str(current_cookie).lower()
                       for keyword in ['session', 'auth', 'token']):
                    similarity_bonus += 5


        if baseline_status and current_status == baseline_status:
            similarity_bonus += 5


        positive_signals = [s for s in signals if s.signal_type == SignalType.POSITIVE]
        if positive_signals and similarity_bonus > 0:

            baseline_positive_count = baseline_result.get("indicators", [])
            if len(positive_signals) > 0:
                similarity_bonus += min(10, len(positive_signals) * 2)


        normalized_score = current_score + min(similarity_bonus, 25)

        if similarity_bonus > 0:
            logger.info(f"✓ Baseline normalization applied: base_score={current_score}, bonus=+{similarity_bonus}, final_score={normalized_score}")
            logger.info(f"  Baseline redirect: {baseline_redirect}, Current redirect: {current_redirect}")
            logger.info(f"  Baseline cookie: {baseline_cookie}, Current cookie: {current_cookie}")
            logger.info(f"  Status match: {baseline_status == current_status if baseline_status else False}")
        elif baseline_result:
            logger.debug(f"Baseline available but no similarity bonus (base_score={current_score})")

        return normalized_score

