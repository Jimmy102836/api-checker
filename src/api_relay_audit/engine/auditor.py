"""Main audit orchestration engine."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from api_relay_audit.engine.result import AuditResult, DetectorResult, RiskLevel
from api_relay_audit.reports.risk_calculator import compute_risk_score

if TYPE_CHECKING:
    from api_relay_audit.config.schema import AppConfig, EndpointConfig
    from api_relay_audit.adapter.auto_adapter import AutoAdapter

logger = logging.getLogger(__name__)

# All available detectors (hardcoded list since schema doesn't have per-detector config)
ALL_DETECTOR_IDS = [
    # Core T1-T5
    "token_injection",
    "hidden_injection",
    "instruction_override",
    "context_truncation",
    "data_exfiltration",
    # Extended T6-T11
    "semantic_truncation",
    "instruction_priority",
    "response_latency",
    "response_format",
    "conversation_memory",
    "http_header_deep",
]


class Auditor:
    """Orchestrates the full audit pipeline."""

    def __init__(self, config: AppConfig, output_dir: Path):
        self.config = config
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[AuditResult] = []

    def run(self, endpoint_name: str | None = None, skip_detectors: list[str] | None = None) -> list[AuditResult]:
        """Run the full audit suite.

        If endpoint_name is given, audit only that endpoint.
        Otherwise, audit all enabled endpoints.

        Args:
            endpoint_name: Filter to a specific endpoint by name/URL.
            skip_detectors: List of detector IDs to skip (e.g. ["context_truncation", "semantic_truncation"]).
        """
        endpoints = self._get_target_endpoints(endpoint_name)
        if not endpoints:
            logger.error(f"No endpoints found for: {endpoint_name or 'all'}")
            return []

        for ep in endpoints:
            logger.info(f"Starting audit for endpoint: {ep.name or ep.url}")
            result = self._audit_endpoint(ep, skip_detectors=skip_detectors)
            self.results.append(result)
            logger.info(
                f"Audit complete for {ep.name or ep.url}: "
                f"risk={result.overall_risk.value}, format={result.detected_format}"
            )

        return self.results

    def _get_target_endpoints(self, endpoint_name: str | None) -> list[EndpointConfig]:
        """Filter endpoints by name or return all enabled ones."""
        if not self.config.endpoints:
            return []

        if endpoint_name:
            for ep in self.config.endpoints:
                if ep.name == endpoint_name or str(ep.url) == endpoint_name:
                    return [ep] if ep.enabled else []
            return []
        else:
            return [ep for ep in self.config.endpoints if ep.enabled]

    def _get_model(self) -> str:
        """Get the model name from settings (where security engineer placed it)."""
        # Security engineer placed model in GlobalSettings
        return getattr(self.config.settings, "model", "claude-opus-4-6")

    def _audit_endpoint(self, endpoint: EndpointConfig, skip_detectors: list[str] | None = None) -> AuditResult:
        """Run all enabled detectors against a single endpoint."""
        from api_relay_audit.adapter.auto_adapter import AutoAdapter
        from api_relay_audit.utils.canary import CanaryGenerator
        from api_relay_audit.utils.token_estimator import TokenEstimator

        start_time = time.time()

        # Create the auto-detecting adapter
        adapter = AutoAdapter(
            base_url=str(endpoint.url),
            api_key=endpoint.token,
            timeout=endpoint.timeout,
        )

        # Utilities
        canary_gen = CanaryGenerator()
        token_est = TokenEstimator()

        # Probe to detect format
        detected_format = self._probe_format(adapter)

        # Run all detectors
        skip = set(skip_detectors or [])
        active_detectors = [d for d in ALL_DETECTOR_IDS if d not in skip]
        detector_results: list[DetectorResult] = []
        for detector_id in active_detectors:
            try:
                dr = self._run_detector(
                    detector_id, endpoint, adapter, canary_gen, token_est
                )
                detector_results.append(dr)
            except Exception as e:
                logger.error(f"Detector {detector_id} failed: {e}")
                detector_results.append(
                    DetectorResult(
                        detector_id=detector_id,
                        risk_level=RiskLevel.LOW,
                        summary=f"Detector failed: {e}",
                        findings=[],
                        raw_data={"error": str(e)},
                    )
                )

        duration = time.time() - start_time
        overall_risk, overall_score = compute_risk_score(detector_results)

        adapter.close_sync()

        return AuditResult(
            target_url=str(endpoint.url),
            target_name=endpoint.name,
            model=self._get_model(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(duration, 2),
            detected_format=detected_format,
            detector_results=detector_results,
            overall_risk=overall_risk,
            metadata={"score": overall_score},
        )

    def _probe_format(self, adapter: AutoAdapter) -> str:
        """Probe the relay to determine which API format it accepts."""
        from api_relay_audit.adapter.base import NormalizedRequest

        probe_req = NormalizedRequest(
            messages=[{"role": "user", "content": "hi"}],
            system=None,
            model=self._get_model(),
            max_tokens=5,
        )
        try:
            response = adapter.call(probe_req)
            if response.error:
                return "unknown"
            return adapter.format_name
        except Exception as e:
            logger.warning(f"Format probe failed: {e}")
            return "unknown"

    def _run_detector(
        self,
        detector_id: str,
        endpoint: EndpointConfig,
        adapter: AutoAdapter,
        canary_gen: CanaryGenerator,
        token_est: TokenEstimator,
    ) -> DetectorResult:
        """Load and run a specific detector."""
        from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
        from api_relay_audit.detectors.token_injection import TokenInjectionDetector
        from api_relay_audit.detectors.hidden_injection import HiddenInjectionDetector
        from api_relay_audit.detectors.instruction_override import InstructionOverrideDetector
        from api_relay_audit.detectors.context_truncation import ContextTruncationDetector
        from api_relay_audit.detectors.data_exfiltration import DataExfiltrationDetector
        from api_relay_audit.detectors.semantic_truncation import SemanticTruncationDetector
        from api_relay_audit.detectors.instruction_priority import InstructionPriorityDetector
        from api_relay_audit.detectors.response_latency import ResponseLatencyDetector
        from api_relay_audit.detectors.response_format import ResponseFormatFingerprintDetector
        from api_relay_audit.detectors.conversation_memory import ConversationMemoryChainDetector
        from api_relay_audit.detectors.http_header_deep import HTTPHeaderDeepDetector
        from api_relay_audit.client.endpoint import Endpoint

        DETECTOR_MAP: dict[str, type[DetectorPlugin]] = {
            # Core T1-T5
            "token_injection": TokenInjectionDetector,
            "hidden_injection": HiddenInjectionDetector,
            "instruction_override": InstructionOverrideDetector,
            "context_truncation": ContextTruncationDetector,
            "data_exfiltration": DataExfiltrationDetector,
            # Extended T6-T11
            "semantic_truncation": SemanticTruncationDetector,
            "instruction_priority": InstructionPriorityDetector,
            "response_latency": ResponseLatencyDetector,
            "response_format": ResponseFormatFingerprintDetector,
            "conversation_memory": ConversationMemoryChainDetector,
            "http_header_deep": HTTPHeaderDeepDetector,
        }

        detector_cls = DETECTOR_MAP.get(detector_id)
        if not detector_cls:
            logger.warning(f"Unknown detector: {detector_id}")
            return DetectorResult(
                detector_id=detector_id,
                risk_level=RiskLevel.LOW,
                summary=f"Unknown detector: {detector_id}",
                findings=[],
            )

        # Create Endpoint dataclass from schema EndpointConfig
        ep = Endpoint(
            url=str(endpoint.url),
            token=endpoint.token,
            name=endpoint.name,
            format=endpoint.format,
            timeout=endpoint.timeout,
            enabled=endpoint.enabled,
            tags=endpoint.tags,
        )

        # Create context (detector_config is None since schema doesn't have it)
        ctx = AuditContext(
            endpoint=ep,
            adapter=adapter,
            settings=self.config.settings,
            detector_config=None,
            canary_generator=canary_gen,
            token_estimator=token_est,
            model=self._get_model(),
        )

        detector = detector_cls()
        logger.info(f"Running detector: {detector_id}")
        return detector.run(ctx)
