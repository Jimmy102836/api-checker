"""Endpoint configuration dataclass."""

from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class Endpoint:
    """Endpoint configuration dataclass."""

    url: str
    token: str
    name: Optional[str] = None
    format: Literal["auto", "anthropic", "openai"] = "auto"
    timeout: int = 120
    enabled: bool = True
    tags: Optional[list[str]] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
