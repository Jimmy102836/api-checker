"""Result dataclasses for audit results and detector findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditTestCase:
    """Individual test case result from a detector."""
    name: str
    description: str
    input_tokens: int
    output_tokens: int
    elapsed_ms: float
    response_text: str
    passed: bool
    details: dict = field(default_factory=dict)


# Backward-compatible alias
TestCase = AuditTestCase


@dataclass
class DetectorResult:
    detector_id: str
    risk_level: RiskLevel
    summary: str
    findings: list[AuditTestCase]
    raw_data: dict = field(default_factory=dict)


@dataclass
class AuditResult:
    target_url: str
    target_name: Optional[str]
    model: str
    timestamp: str
    duration_seconds: float
    detected_format: str
    detector_results: list[DetectorResult]
    overall_risk: RiskLevel
    metadata: dict = field(default_factory=dict)

