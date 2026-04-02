"""JSON result tree exporter."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from api_relay_audit.engine.result import AuditResult, DetectorResult, RiskLevel

logger = logging.getLogger(__name__)


class JSONExporter:
    """Exports AuditResult to JSON format."""

    def export(self, audit_result: AuditResult, output_path: Path, pretty: bool = True) -> None:
        """Export an audit result to a JSON file.

        Args:
            audit_result: The audit result to export.
            output_path: Path to write the JSON file.
            pretty: Whether to pretty-print the JSON (default: True).
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = self._build_tree(audit_result)
        indent = 2 if pretty else None

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)

        logger.info(f"JSON report written to {output_path}")

    def _build_tree(self, result: AuditResult) -> dict[str, Any]:
        """Build the full JSON result tree."""
        risk_breakdown = {}
        for dr in result.detector_results:
            risk_breakdown[dr.detector_id] = {
                "level": dr.risk_level.value,
                "score": self._detector_score(dr),
            }

        score = result.metadata.get("score", 0)

        return {
            "version": "1.0",
            "audit": {
                "target_url": result.target_url,
                "target_name": result.target_name,
                "model": result.model,
                "detected_format": result.detected_format,
                "timestamp": result.timestamp,
                "duration_seconds": result.duration_seconds,
            },
            "risk": {
                "overall": result.overall_risk.value,
                "score": score,
                "breakdown": risk_breakdown,
            },
            "detectors": [
                self._detector_to_dict(dr) for dr in result.detector_results
            ],
            "metadata": {
                "tool_version": "1.0.0",
                "python_version": self._get_python_version(),
            },
        }

    def _detector_to_dict(self, dr: DetectorResult) -> dict[str, Any]:
        """Convert a DetectorResult to a dict."""
        return {
            "id": dr.detector_id,
            "status": "completed",
            "risk_level": dr.risk_level.value,
            "summary": dr.summary,
            "findings": [
                {
                    "test_name": tc.name,
                    "description": tc.description,
                    "input_tokens": tc.input_tokens,
                    "output_tokens": tc.output_tokens,
                    "elapsed_ms": tc.elapsed_ms,
                    "response_text": tc.response_text[:500] if tc.response_text else "",
                    "passed": tc.passed,
                    "details": tc.details,
                }
                for tc in dr.findings
            ],
            "raw_data": dr.raw_data,
        }

    def _detector_score(self, dr: DetectorResult) -> int:
        """Compute a 0-100 score from a DetectorResult."""
        if not dr.findings:
            return 0
        score_map = {
            RiskLevel.LOW: 10,
            RiskLevel.MEDIUM: 45,
            RiskLevel.HIGH: 80,
            RiskLevel.CRITICAL: 100,
        }
        return score_map.get(dr.risk_level, 0)

    def _get_python_version(self) -> str:
        import sys
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
