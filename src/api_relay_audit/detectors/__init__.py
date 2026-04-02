"""Detector plugins for API relay security audits."""

from api_relay_audit.detectors.base import DetectorPlugin, AuditContext

# Core 5 detectors (T1-T5)
from api_relay_audit.detectors.token_injection import TokenInjectionDetector
from api_relay_audit.detectors.hidden_injection import HiddenInjectionDetector
from api_relay_audit.detectors.instruction_override import InstructionOverrideDetector
from api_relay_audit.detectors.context_truncation import ContextTruncationDetector
from api_relay_audit.detectors.data_exfiltration import DataExfiltrationDetector

# Extended 6 detectors
from api_relay_audit.detectors.semantic_truncation import SemanticTruncationDetector
from api_relay_audit.detectors.instruction_priority import InstructionPriorityDetector
from api_relay_audit.detectors.response_latency import ResponseLatencyDetector
from api_relay_audit.detectors.response_format import ResponseFormatFingerprintDetector
from api_relay_audit.detectors.conversation_memory import ConversationMemoryChainDetector
from api_relay_audit.detectors.http_header_deep import HTTPHeaderDeepDetector

__all__ = [
    # Base
    "DetectorPlugin",
    "AuditContext",
    # Core T1-T5
    "TokenInjectionDetector",
    "HiddenInjectionDetector",
    "InstructionOverrideDetector",
    "ContextTruncationDetector",
    "DataExfiltrationDetector",
    # Extended
    "SemanticTruncationDetector",
    "InstructionPriorityDetector",
    "ResponseLatencyDetector",
    "ResponseFormatFingerprintDetector",
    "ConversationMemoryChainDetector",
    "HTTPHeaderDeepDetector",
]
