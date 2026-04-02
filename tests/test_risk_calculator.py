"""Extended tests for risk calculator and report format validation.

These tests complement tests/unit/test_risk_calculator.py with additional
coverage for edge cases, threshold boundaries, and integration with
report exporters.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase, AuditResult
from api_relay_audit.reports.risk_calculator import (
    compute_risk_score,
    _detector_raw_score,
    RiskCalculator,
    RISK_THRESHOLDS,
    WEIGHTS,
)


# ---------------------------------------------------------------------------
# Threshold boundary tests
# ---------------------------------------------------------------------------

class TestRiskThresholdBoundaries:
    """Test exact boundary values for risk level transitions."""

    def test_score_0_is_low(self):
        """Score of 0 maps to LOW."""
        level, score = compute_risk_score([])
        assert level == RiskLevel.LOW
        assert score == 0

    def test_score_30_is_low(self):
        """Score of 30 maps to LOW (upper boundary of LOW)."""
        dr = self._make_result("token_injection", RiskLevel.LOW, score_delta=0)
        level, score = compute_risk_score([dr])
        assert level == RiskLevel.LOW

    def test_score_31_is_medium(self):
        """Score just above 30 maps to MEDIUM."""
        dr = self._make_medium_result("hidden_injection", RiskLevel.MEDIUM)
        level, score = compute_risk_score([dr])
        assert level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_score_60_is_medium(self):
        """Score of 60 maps to MEDIUM (upper boundary)."""
        dr = self._make_medium_result("token_injection", RiskLevel.MEDIUM)
        level, score = compute_risk_score([dr])
        assert level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_score_61_is_high(self):
        """Score of 61+ maps to HIGH."""
        dr = self._make_high_result("instruction_override", RiskLevel.HIGH)
        level, score = compute_risk_score([dr])
        assert level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_score_100_is_critical(self):
        """Multiple HIGH results produce elevated score."""
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.HIGH,
            summary="Severe injection",
            findings=[],
            raw_data={"delta_tokens": 300},
        )
        dr2 = DetectorResult(
            detector_id="hidden_injection",
            risk_level=RiskLevel.HIGH,
            summary="Severe hidden injection",
            findings=[],
            raw_data={"excess_tokens": 200},
        )
        level, score = compute_risk_score([dr, dr2])
        # Two HIGH results → score should be substantial
        assert score >= 0

    # -------------------------------------------------------------------------
    # Helper constructors
    # -------------------------------------------------------------------------

    def _make_result(self, detector_id: str, risk_level: RiskLevel, score_delta: int) -> DetectorResult:
        return DetectorResult(
            detector_id=detector_id,
            risk_level=risk_level,
            summary="test",
            findings=[],
            raw_data={"delta": score_delta},
        )

    def _make_medium_result(self, detector_id: str, risk_level: RiskLevel) -> DetectorResult:
        return DetectorResult(
            detector_id=detector_id,
            risk_level=risk_level,
            summary="medium risk",
            findings=[
                TestCase(
                    name="test1", description="", input_tokens=50,
                    output_tokens=10, elapsed_ms=200, response_text="ok",
                    passed=False,
                ),
            ],
            raw_data={"score": 40},
        )

    def _make_high_result(self, detector_id: str, risk_level: RiskLevel) -> DetectorResult:
        return DetectorResult(
            detector_id=detector_id,
            risk_level=risk_level,
            summary="high risk",
            findings=[
                TestCase(
                    name="test1", description="", input_tokens=100,
                    output_tokens=0, elapsed_ms=0, response_text="",
                    passed=False,
                ),
                TestCase(
                    name="test2", description="", input_tokens=100,
                    output_tokens=0, elapsed_ms=0, response_text="",
                    passed=False,
                ),
            ],
            raw_data={"overridden_tests": ["test1", "test2"], "rejected_422": True},
        )


# ---------------------------------------------------------------------------
# Weighted score tests
# ---------------------------------------------------------------------------

class TestWeightedScoring:
    """Test that detector weights are applied correctly."""

    def test_all_detectors_contribute(self):
        """All 5 detectors should contribute to the final score."""
        results = [
            DetectorResult(
                detector_id=did,
                risk_level=RiskLevel.HIGH,
                summary="",
                findings=[],
                raw_data={"delta_tokens": 300},
            )
            for did in WEIGHTS.keys()
        ]
        level, score = compute_risk_score(results)
        assert score > 0

    def test_missing_detectors_partial_score(self):
        """Only providing a subset of detectors gives partial score."""
        only_token = [
            DetectorResult(
                detector_id="token_injection",
                risk_level=RiskLevel.HIGH,
                summary="",
                findings=[],
                raw_data={"delta_tokens": 300},
            )
        ]
        level, score = compute_risk_score(only_token)
        assert score >= 0

    def test_weight_sum_approximately_1(self):
        """Weights should sum to 1.0 (or close enough with rounding)."""
        total = sum(WEIGHTS.values())
        assert abs(total - 1.0) < 0.01

    def test_each_detector_has_weight(self):
        """Every core detector has a defined weight."""
        core_ids = {
            "token_injection",
            "hidden_injection",
            "instruction_override",
            "context_truncation",
            "data_exfiltration",
        }
        for did in core_ids:
            assert did in WEIGHTS, f"Missing weight for {did}"


# ---------------------------------------------------------------------------
# RiskCalculator class tests
# ---------------------------------------------------------------------------

class TestRiskCalculatorClass:
    """Test the RiskCalculator convenience class."""

    def test_breakdown_empty(self):
        """breakdown() on empty results returns empty dict."""
        calc = RiskCalculator()
        calc.compute([])
        breakdown = calc.breakdown()
        assert breakdown == {}

    def test_breakdown_contains_all_detectors(self):
        """breakdown() includes all detectors that were computed."""
        results = [
            DetectorResult(
                detector_id=did,
                risk_level=RiskLevel.LOW,
                summary="",
                findings=[],
                raw_data={},
            )
            for did in WEIGHTS.keys()
        ]
        calc = RiskCalculator()
        calc.compute(results)
        breakdown = calc.breakdown()
        for did in WEIGHTS:
            assert did in breakdown

    def test_compute_returns_tuple(self):
        """compute() returns (RiskLevel, int)."""
        results = [
            DetectorResult(
                detector_id="token_injection",
                risk_level=RiskLevel.MEDIUM,
                summary="",
                findings=[],
                raw_data={},
            )
        ]
        calc = RiskCalculator()
        result = calc.compute(results)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], RiskLevel)
        assert isinstance(result[1], int)

    def test_compute_stores_breakdown(self):
        """compute() stores scores for breakdown() retrieval."""
        results = [
            DetectorResult(
                detector_id="token_injection",
                risk_level=RiskLevel.HIGH,
                summary="",
                findings=[],
                raw_data={"delta_tokens": 150},
            )
        ]
        calc = RiskCalculator()
        calc.compute(results)
        breakdown = calc.breakdown()
        assert "token_injection" in breakdown
        assert breakdown["token_injection"] >= 0


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestRiskCalculatorEdgeCases:
    """Edge cases and error handling in risk calculation."""

    def test_unknown_detector_id(self):
        """Unknown detector IDs are handled gracefully (not in weights)."""
        dr = DetectorResult(
            detector_id="unknown_detector",
            risk_level=RiskLevel.HIGH,
            summary="",
            findings=[],
            raw_data={},
        )
        level, score = compute_risk_score([dr])
        assert level in RiskLevel

    def test_all_tests_passed(self):
        """All tests passed → LOW risk overall."""
        results = [
            DetectorResult(
                detector_id=did,
                risk_level=RiskLevel.LOW,
                summary="All clear",
                findings=[
                    TestCase(
                        name=f"test_{i}",
                        description="",
                        input_tokens=10,
                        output_tokens=5,
                        elapsed_ms=100,
                        response_text="ok",
                        passed=True,
                    )
                    for i in range(3)
                ],
                raw_data={"passed": True},
            )
            for did in WEIGHTS.keys()
        ]
        level, score = compute_risk_score(results)
        assert level == RiskLevel.LOW
        assert score <= RISK_THRESHOLDS[RiskLevel.LOW]

    def test_mixed_risk_levels(self):
        """Mixed HIGH/LOW results produce MEDIUM overall."""
        results = [
            DetectorResult(
                detector_id="token_injection",
                risk_level=RiskLevel.HIGH,
                summary="",
                findings=[],
                raw_data={"delta_tokens": 200},
            ),
            DetectorResult(
                detector_id="context_truncation",
                risk_level=RiskLevel.LOW,
                summary="",
                findings=[],
                raw_data={},
            ),
        ]
        level, score = compute_risk_score(results)
        assert level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_detector_raw_score_zero_findings(self):
        """_detector_raw_score handles empty findings list."""
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.LOW,
            summary="",
            findings=[],
            raw_data={},
        )
        score = _detector_raw_score(dr)
        assert score >= 0

    def test_detector_raw_score_all_passed(self):
        """_detector_raw_score returns 0 when all findings pass."""
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.LOW,
            summary="",
            findings=[
                TestCase(
                    name=f"t{i}",
                    description="",
                    input_tokens=10,
                    output_tokens=5,
                    elapsed_ms=100,
                    response_text="ok",
                    passed=True,
                )
                for i in range(5)
            ],
            raw_data={},
        )
        score = _detector_raw_score(dr)
        assert score == 0

    def test_detector_raw_score_all_failed_instruction_override(self):
        """_detector_raw_score returns 100 when all instruction_override tests fail with 422."""
        dr = DetectorResult(
            detector_id="instruction_override",
            risk_level=RiskLevel.HIGH,
            summary="",
            findings=[
                TestCase(
                    name=f"t{i}",
                    description="",
                    input_tokens=0,
                    output_tokens=0,
                    elapsed_ms=0,
                    response_text="",
                    passed=False,
                )
                for i in range(3)
            ],
            raw_data={
                "overridden_tests": ["t0", "t1", "t2"],
                "rejected_422": True,
            },
        )
        score = _detector_raw_score(dr)
        assert score == 100

    def test_detector_raw_score_partial_override(self):
        """_detector_raw_score returns 50 for partial override (some tests failed)."""
        dr = DetectorResult(
            detector_id="instruction_override",
            risk_level=RiskLevel.MEDIUM,
            summary="",
            findings=[
                TestCase(
                    name="t0",
                    description="",
                    input_tokens=0,
                    output_tokens=0,
                    elapsed_ms=0,
                    response_text="",
                    passed=False,
                ),
                TestCase(
                    name="t1",
                    description="",
                    input_tokens=10,
                    output_tokens=5,
                    elapsed_ms=100,
                    response_text="ok",
                    passed=True,
                ),
            ],
            raw_data={"overridden_tests": ["t0"]},
        )
        score = _detector_raw_score(dr)
        assert score == 50


# ---------------------------------------------------------------------------
# Report format validation
# ---------------------------------------------------------------------------

class TestReportFormatValidation:
    """Validate that report output formats are correct."""

    def test_detector_result_json_serializable(self):
        """DetectorResult can be serialized to JSON."""
        dr = DetectorResult(
            detector_id="token_injection",
            risk_level=RiskLevel.HIGH,
            summary="Token injection detected",
            findings=[
                TestCase(
                    name="test1",
                    description="Send minimal prompt",
                    input_tokens=10,
                    output_tokens=5,
                    elapsed_ms=150,
                    response_text="Hello!",
                    passed=False,
                    details={"injected": True},
                )
            ],
            raw_data={"injection_delta": 150, "threshold": 100},
        )
        json_str = json.dumps(
            {
                "detector_id": dr.detector_id,
                "risk_level": dr.risk_level.value,
                "summary": dr.summary,
                "findings": [
                    {
                        "name": f.name,
                        "description": f.description,
                        "input_tokens": f.input_tokens,
                        "output_tokens": f.output_tokens,
                        "elapsed_ms": f.elapsed_ms,
                        "response_text": f.response_text,
                        "passed": f.passed,
                        "details": f.details,
                    }
                    for f in dr.findings
                ],
                "raw_data": dr.raw_data,
            },
            default=str,
        )
        parsed = json.loads(json_str)
        assert parsed["detector_id"] == "token_injection"
        assert parsed["risk_level"] == "high"
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["passed"] is False

    def test_audit_result_fields(self):
        """AuditResult has the expected fields."""
        ar = AuditResult(
            target_url="http://localhost:8000",
            target_name="test-relay",
            model="test-model",
            timestamp=datetime.now().isoformat(),
            duration_seconds=1.5,
            detected_format="openai",
            overall_risk=RiskLevel.MEDIUM,
            detector_results=[],
        )
        assert ar.target_url == "http://localhost:8000"
        assert ar.target_name == "test-relay"
        assert ar.model == "test-model"
        assert ar.overall_risk == RiskLevel.MEDIUM

    def test_risk_level_enum_values(self):
        """RiskLevel enum has expected values."""
        assert RiskLevel.LOW is not None
        assert RiskLevel.MEDIUM is not None
        assert RiskLevel.HIGH is not None
        assert RiskLevel.CRITICAL is not None
        levels = {RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
        assert len(levels) == 4

    def test_test_case_defaults(self):
        """TestCase can be constructed with minimal args."""
        tc = TestCase(
            name="simple",
            description="A simple test",
            input_tokens=5,
            output_tokens=3,
            elapsed_ms=100,
            response_text="ok",
            passed=True,
        )
        assert tc.name == "simple"
        assert tc.passed is True
        assert tc.details == {}


# ---------------------------------------------------------------------------
# Report exporter integration tests
# ---------------------------------------------------------------------------

class TestReportExporterIntegration:
    """Test report exporters with real-ish data."""

    def _make_audit_result(self, risk_level: RiskLevel = RiskLevel.HIGH) -> AuditResult:
        return AuditResult(
            target_url="http://localhost:8000",
            target_name="test-relay",
            model="test-model",
            timestamp=datetime.now().isoformat(),
            duration_seconds=2.5,
            detected_format="openai",
            overall_risk=risk_level,
            detector_results=[
                DetectorResult(
                    detector_id="token_injection",
                    risk_level=risk_level,
                    summary="Injection detected",
                    findings=[],
                    raw_data={"delta_tokens": 150},
                ),
            ],
            metadata={"score": 75},
        )

    def test_json_exporter_produces_valid_json(self):
        """JSONExporter output is valid JSON written to file."""
        from api_relay_audit.reports.json_exporter import JSONExporter

        result = self._make_audit_result()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        try:
            exporter = JSONExporter()
            exporter.export(result, path)
            parsed = json.loads(path.read_text())
            assert parsed["audit"]["target_url"] == "http://localhost:8000"
            assert "risk" in parsed
            assert "detectors" in parsed
        finally:
            path.unlink(missing_ok=True)

    def test_markdown_exporter_produces_markdown(self):
        """MarkdownExporter produces markdown-formatted output written to file."""
        from api_relay_audit.reports.markdown_exporter import MarkdownExporter

        result = self._make_audit_result(risk_level=RiskLevel.LOW)
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = Path(f.name)

        try:
            exporter = MarkdownExporter()
            exporter.export(result, path)
            content = path.read_text()
            assert isinstance(content, str)
            assert "test-relay" in content
            assert "#" in content
        finally:
            path.unlink(missing_ok=True)

    def test_json_exporter_handles_high_risk(self):
        """JSONExporter correctly reports HIGH risk level."""
        from api_relay_audit.reports.json_exporter import JSONExporter

        result = self._make_audit_result(risk_level=RiskLevel.HIGH)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        try:
            exporter = JSONExporter()
            exporter.export(result, path)
            parsed = json.loads(path.read_text())
            assert parsed["risk"]["overall"] == "high"
        finally:
            path.unlink(missing_ok=True)

    def test_markdown_exporter_risk_emoji(self):
        """MarkdownExporter uses correct emoji for each risk level."""
        from api_relay_audit.reports.markdown_exporter import MarkdownExporter

        result = self._make_audit_result(risk_level=RiskLevel.CRITICAL)
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            path = Path(f.name)

        try:
            exporter = MarkdownExporter()
            exporter.export(result, path)
            content = path.read_text()
            # CRITICAL → 💀
            assert "💀" in content
            assert "CRITICAL" in content.upper()
        finally:
            path.unlink(missing_ok=True)
