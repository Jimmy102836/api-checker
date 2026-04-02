"""Unit tests for report exporters."""

import json
import tempfile
from pathlib import Path

import pytest

from api_relay_audit.engine.result import AuditResult, DetectorResult, RiskLevel, TestCase
from api_relay_audit.reports.json_exporter import JSONExporter
from api_relay_audit.reports.markdown_exporter import MarkdownExporter


def make_test_audit_result() -> AuditResult:
    return AuditResult(
        target_url="https://example.com/v1",
        target_name="Test Relay",
        model="claude-opus-4-6",
        timestamp="2026-04-02T10:00:00Z",
        duration_seconds=45.3,
        detected_format="openai",
        detector_results=[
            DetectorResult(
                detector_id="token_injection",
                risk_level=RiskLevel.MEDIUM,
                summary="Moderate injection detected (~50 tokens)",
                findings=[
                    TestCase(
                        name="hello_world",
                        description="Test with minimal prompt",
                        input_tokens=12,
                        output_tokens=5,
                        elapsed_ms=150,
                        response_text="Hi there!",
                        passed=False,
                        details={"delta": 4},
                    )
                ],
                raw_data={"delta_tokens": 50},
            )
        ],
        overall_risk=RiskLevel.MEDIUM,
        metadata={"score": 45},
    )


class TestJSONExporter:
    def test_export_creates_file(self):
        exporter = JSONExporter()
        result = make_test_audit_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            exporter.export(result, path)

            assert path.exists()
            data = json.loads(path.read_text())

            assert data["version"] == "1.0"
            assert data["audit"]["target_url"] == "https://example.com/v1"
            assert data["risk"]["overall"] == "medium"
            assert len(data["detectors"]) == 1
            assert data["detectors"][0]["id"] == "token_injection"

    def test_export_pretty_by_default(self):
        exporter = JSONExporter()
        result = make_test_audit_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.json"
            exporter.export(result, path)

            content = path.read_text()
            assert "\n" in content  # Pretty-printed


class TestMarkdownExporter:
    def test_export_creates_file(self):
        exporter = MarkdownExporter()
        result = make_test_audit_result()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "report.md"
            exporter.export(result, path)

            assert path.exists()
            content = path.read_text()

            assert "# API Relay Security Audit Report" in content
            assert "Test Relay" in content
            assert "token_injection" in content
            assert "MEDIUM" in content
            assert "45" in content  # Score
