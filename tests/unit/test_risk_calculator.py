"""Unit tests for risk calculator."""

import pytest

from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase
from api_relay_audit.reports.risk_calculator import (
    compute_risk_score,
    _detector_raw_score,
    RiskCalculator,
)


class TestRiskCalculator:
    def test_low_risk_all_passed(self):
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.LOW,
            summary="No injection detected",
            findings=[TestCase(
                name="test1", description="", input_tokens=10, output_tokens=5,
                elapsed_ms=100, response_text="ok", passed=True,
            )],
            raw_data={"delta_tokens": 5},
        )
        level, score = compute_risk_score([dr])
        assert level == RiskLevel.LOW
        assert score <= 30

    def test_token_injection_high_delta(self):
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.HIGH,
            summary="High injection detected",
            findings=[],
            raw_data={"delta_tokens": 150},
        )
        level, score = compute_risk_score([dr])
        # delta=150: score = 25 + 25*(50)/200 = 25 + 6.25 = 31.25
        assert level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_instruction_override_complete(self):
        dr = DetectorResult(
            detector_id="instruction_override",
            risk_level=RiskLevel.HIGH,
            summary="System prompt overridden",
            findings=[
                TestCase("cat_test", "", 0, 0, 0, "", False),
                TestCase("identity_test", "", 0, 0, 0, "", False),
            ],
            raw_data={"overridden_tests": ["cat_test", "identity_test"], "rejected_422": False},
        )
        score = _detector_raw_score(dr)
        assert score == 100  # All tests failed

    def test_empty_results(self):
        level, score = compute_risk_score([])
        assert level == RiskLevel.LOW
        assert score == 0

    def test_risk_calculator_breakdown(self):
        calc = RiskCalculator()
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.LOW,
            summary="",
            findings=[],
            raw_data={"delta_tokens": 150},
        )
        level, score = calc.compute([dr])
        breakdown = calc.breakdown()
        assert "token_injection" in breakdown
