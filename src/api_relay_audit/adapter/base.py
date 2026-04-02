"""Abstract interface for API format adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class NormalizedRequest:
    """Format-agnostic request representation."""
    messages: list[dict]  # [{"role": "user"|"system"|"assistant", "content": str}]
    system: Optional[str] = None  # Explicit system prompt (may also be in messages[0])
    model: str = "claude-opus-4-6"
    max_tokens: int = 512


@dataclass
class NormalizedResponse:
    """Format-agnostic response representation."""
    text: str  # Assistant's reply text
    input_tokens: int
    output_tokens: int
    raw: dict  # Full API response for debugging
    time_elapsed: float  # Wall-clock seconds
    error: Optional[str] = None


class RequestAdapter(ABC):
    """Abstract interface for API format adapters.

    Implement this for each API format (OpenAI, Anthropic, custom).
    The engine never calls the API directly — it always goes through an adapter.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format identifier: 'openai' | 'anthropic' | 'custom'."""

    @property
    @abstractmethod
    def endpoint_path(self) -> str:
        """Return the URL path, e.g. '/v1/chat/completions' or '/v1/messages'."""

    @abstractmethod
    def auth_headers(self) -> dict[str, str]:
        """Return the required authentication headers."""

    @abstractmethod
    def build_request_body(self, req: NormalizedRequest) -> dict[str, Any]:
        """Serialize a NormalizedRequest into the format-specific JSON body."""

    @abstractmethod
    def parse_response(self, raw: dict) -> NormalizedResponse:
        """Parse a format-specific JSON response into a NormalizedResponse."""

    @abstractmethod
    def detect_format(self, raw_response: dict) -> bool:
        """Return True if the raw response looks like this format's response.
        Used by AutoAdapter for format auto-detection."""
