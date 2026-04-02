"""Output formatting helpers for console and report output."""

from __future__ import annotations

import json
import logging
from typing import Any

from api_relay_audit.engine.result import RiskLevel

logger = logging.getLogger(__name__)

RISK_EMOJI = {
    RiskLevel.LOW: "✅",
    RiskLevel.MEDIUM: "⚠️",
    RiskLevel.HIGH: "🔴",
    RiskLevel.CRITICAL: "💀",
}

RISK_COLOR = {
    RiskLevel.LOW: "\033[92m",      # green
    RiskLevel.MEDIUM: "\033[93m",   # yellow
    RiskLevel.HIGH: "\033[91m",     # red
    RiskLevel.CRITICAL: "\033[91m", # red
}
COLOR_RESET = "\033[0m"


def format_risk(level: RiskLevel, use_color: bool = False) -> str:
    """Format a risk level with optional color."""
    label = f"{level.value.upper()}"
    if use_color:
        color = RISK_COLOR.get(level, "")
        return f"{color}{label}{COLOR_RESET}"
    return label


def format_duration(seconds: float) -> str:
    """Format a duration in human-readable form."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.1f}s"


def format_token_count(n: int) -> str:
    """Format a token count with thousands separator."""
    return f"{n:,}"


def format_json(data: dict, pretty: bool = True) -> str:
    """Format data as JSON string."""
    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
    return json.dumps(data, ensure_ascii=False, default=str)


def print_audit_summary(results: list[Any]) -> None:
    """Print a brief summary of audit results to console."""
    if not results:
        print("No audit results to display.")
        return

    print("\n" + "=" * 60)
    print("API RELAY AUDIT SUMMARY")
    print("=" * 60)

    for result in results:
        print(f"\n  Target: {result.target_name or result.target_url}")
        print(f"  Format: {result.detected_format}")
        print(f"  Risk:   {format_risk(result.overall_risk, use_color=True)}")
        print(f"  Duration: {format_duration(result.duration_seconds)}")

        for dr in result.detector_results:
            emoji = RISK_EMOJI.get(dr.risk_level, "?")
            print(f"    {emoji} {dr.detector_id}: {format_risk(dr.risk_level)}")

    print("\n" + "=" * 60)
