"""Risk score computation from detector results.

Implements Appendix B of the architecture design:
- token_injection: 25% weight
- hidden_injection: 20% weight
- instruction_override: 25% weight
- context_truncation: 15% weight
- data_exfiltration: 15% weight

Risk Levels:
- LOW: overall score 0-30
- MEDIUM: overall score 31-60
- HIGH: overall score 61-80
- CRITICAL: overall score 81-100
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from api_relay_audit.engine.result import RiskLevel

if TYPE_CHECKING:
    from api_relay_audit.engine.result import DetectorResult

logger = logging.getLogger(__name__)

WEIGHTS = {
    "token_injection": 0.25,
    "hidden_injection": 0.20,
    "instruction_override": 0.25,
    "context_truncation": 0.15,
    "data_exfiltration": 0.15,
}

RISK_THRESHOLDS = {
    RiskLevel.LOW: 30,
    RiskLevel.MEDIUM: 60,
    RiskLevel.HIGH: 80,
}


def _detector_raw_score(dr: DetectorResult) -> float:
    """Compute a 0-100 raw score from a DetectorResult.

    Uses per-detector scoring logic from Appendix B.
    """
    d_id = dr.detector_id
    raw_data = dr.raw_data or {}

    if d_id == "token_injection":
        # Score based on delta tokens
        delta = raw_data.get("delta_tokens", 0)
        if delta < 20:
            return 0
        elif delta <= 100:
            return 25 * delta / 100
        else:
            return min(50, 25 + 25 * (delta - 100) / 200)

    elif d_id == "hidden_injection":
        # Score based on excess tokens
        excess = raw_data.get("excess_tokens", 0)
        if excess < 10:
            return 0
        return min(40, 40 * excess / 200)

    elif d_id == "instruction_override":
        # 0 if no override, 50 if partial, 100 if complete
        overridden = raw_data.get("overridden_tests", [])
        if not overridden:
            return 0
        # Check if 422 was returned (complete override)
        if raw_data.get("rejected_422", False):
            return 100
        # Some tests failed
        tests = dr.findings
        if tests:
            failed = sum(1 for t in tests if not t.passed)
            return 50 if failed < len(tests) else 100
        return 50

    elif d_id == "context_truncation":
        # Score = (1 - actual/max_advertised) * 100
        actual = raw_data.get("max_working_tokens", raw_data.get("boundary_k", 0))
        advertised = raw_data.get("advertised_max_tokens", 200000)
        if actual >= advertised or advertised == 0:
            return 0
        return min(100, (1 - actual / advertised) * 100)

    elif d_id == "data_exfiltration":
        # 0 if clean, 50 if suspicious headers, 100 if confirmed leak
        if raw_data.get("cross_session_leak", False):
            return 100
        suspicious = raw_data.get("suspicious_headers", [])
        if suspicious:
            return 50
        return 0

    else:
        # Fallback: use risk level
        level_scores = {
            RiskLevel.LOW: 10,
            RiskLevel.MEDIUM: 45,
            RiskLevel.HIGH: 80,
            RiskLevel.CRITICAL: 100,
        }
        return level_scores.get(dr.risk_level, 0)


def compute_risk_score(detector_results: list[DetectorResult]) -> tuple[RiskLevel, int]:
    """Compute overall risk level and score from detector results.

    Returns:
        A tuple of (RiskLevel, overall_score_0_to_100).
    """
    if not detector_results:
        return RiskLevel.LOW, 0

    total_weight = 0.0
    weighted_score = 0.0

    for dr in detector_results:
        weight = WEIGHTS.get(dr.detector_id, 0.1)
        raw = _detector_raw_score(dr)
        weighted_score += weight * raw
        total_weight += weight

    # Normalize if we don't have all detectors
    if total_weight > 0:
        overall_score = weighted_score / total_weight * sum(WEIGHTS.values())
    else:
        overall_score = weighted_score

    overall_score = min(100, max(0, overall_score))

    # Map to risk level
    if overall_score <= RISK_THRESHOLDS[RiskLevel.LOW]:
        level = RiskLevel.LOW
    elif overall_score <= RISK_THRESHOLDS[RiskLevel.MEDIUM]:
        level = RiskLevel.MEDIUM
    elif overall_score <= RISK_THRESHOLDS[RiskLevel.HIGH]:
        level = RiskLevel.HIGH
    else:
        level = RiskLevel.CRITICAL

    logger.debug(f"Risk score: {overall_score:.1f} -> {level.value}")
    return level, round(overall_score)


class RiskCalculator:
    """Risk calculator with per-detector breakdown."""

    def __init__(self):
        self._scores: dict[str, float] = {}

    def compute(self, detector_results: list[DetectorResult]) -> tuple[RiskLevel, int]:
        """Compute overall risk with per-detector breakdown stored."""
        self._scores = {}
        for dr in detector_results:
            self._scores[dr.detector_id] = _detector_raw_score(dr)
        return compute_risk_score(detector_results)

    def breakdown(self) -> dict[str, float]:
        """Return per-detector raw scores."""
        return dict(self._scores)
