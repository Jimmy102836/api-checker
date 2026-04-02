"""DetectorPlugin ABC and AuditContext for all detection algorithms."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase

if TYPE_CHECKING:
    from api_relay_audit.adapter.auto_adapter import AutoAdapter
    from api_relay_audit.config.schema import DetectorConfig, GlobalSettings
    from api_relay_audit.client.endpoint import Endpoint
    from api_relay_audit.utils.canary import CanaryGenerator
    from api_relay_audit.utils.token_estimator import TokenEstimator


@dataclass
class AuditContext:
    """Shared context passed to all detectors during an audit run."""
    endpoint: "Endpoint"
    adapter: "AutoAdapter"
    settings: "GlobalSettings"
    detector_config: "DetectorConfig"
    canary_generator: "CanaryGenerator"
    token_estimator: "TokenEstimator"
    model: str = "claude-opus-4-6"  # Default model for requests


class DetectorPlugin(ABC):
    """Abstract base class for all detection plugins."""

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique identifier, e.g. 'context_truncation', 'token_injection'."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name, e.g. 'Context Truncation Detection'."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-paragraph description of what this detector checks."""

    @abstractmethod
    def run(self, ctx: AuditContext) -> DetectorResult:
        """Execute the detection algorithm.

        Args:
            ctx: AuditContext containing the API client, config, and utilities.

        Returns:
            DetectorResult with findings and risk assessment.
        """
