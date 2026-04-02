"""Extended: HTTP Header Deep Detection.

Analyzes HTTP request/response headers for signs of injection,
forwarding, or logging by the relay.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


# Patterns of suspicious headers
SUSPICIOUS_HEADER_PATTERNS = {
    "logging": [
        "x-query-log", "x-request-log", "x-data-log", "x-api-log",
        "x-relay-log", "x-log-request", "x-snoop", "x-debug-query",
        "x-audit-request", "x-inspect-prompt",
    ],
    "forwarding": [
        "x-forwarded-query", "x-forwarded-prompt", "x-prompt-forward",
        "x-data-forward", "x-content-forward", "x-prompt-copy",
    ],
    "injection": [
        "x-inject-system", "x-add-prompt", "x-modify-request",
        "x-prompt-tamper", "x-request-alter",
    ],
    "storage": [
        "x-store-conversation", "x-persist-session", "x-session-store",
        "x-conversation-archive", "x-log-conversation",
    ],
}


@dataclass
class HeaderCheck:
    """A single header inspection test."""
    name: str
    description: str
    prompt: str
    expected_behavior: str


DEFAULT_HEADER_CHECKS = [
    HeaderCheck(
        name="baseline_headers",
        description="Capture baseline headers for comparison",
        prompt="Say hello in one word.",
        expected_behavior="baseline",
    ),
    HeaderCheck(
        name="long_prompt_headers",
        description="Check headers after sending a very long prompt",
        prompt="x" * 5000,  # Very long prompt
        expected_behavior="long_prompt",
    ),
    HeaderCheck(
        name="special_chars_headers",
        description="Check headers after sending special characters",
        prompt='{"json": "test", "special": "\u2022\u2022\u2022"}',
        expected_behavior="special_chars",
    ),
    HeaderCheck(
        name="api_key_in_prompt_headers",
        description="Check headers when API key pattern appears in prompt",
        prompt="My API key is sk_test_1234567890abcdef. Don't log it.",
        expected_behavior="api_key_pattern",
    ),
]


class HTTPHeaderDeepDetector(DetectorPlugin):
    """Detects relay header injection and suspicious forwarding.

    Algorithm:
    1. Send requests with varied content and capture response headers
    2. Check for unexpected headers indicating logging/forwarding/injection
    3. Compare headers across different prompt types to detect patterns
    4. Flag headers that reveal the relay is storing/modifying content
    """

    id = "http_header_deep"
    name = "HTTP Header Deep Detection"
    description = (
        "Detects relay header injection and suspicious forwarding by analyzing "
        "HTTP response headers for logging, data forwarding, prompt injection, "
        "and conversation storage indicators."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the HTTP header deep detection test suite."""
        findings: list[TestCase] = []
        raw_data: dict = {
            "all_headers": {},
            "suspicious_headers": [],
            "header_changes": [],
        }

        checks = DEFAULT_HEADER_CHECKS
        baseline_headers: dict = {}

        for check in checks:
            req = NormalizedRequest(
                messages=[{"role": "user", "content": check.prompt}],
                system=None,
                model=ctx.model,
                max_tokens=32,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                findings.append(
                    TestCase(
                        name=check.name,
                        description=check.description,
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=elapsed_ms,
                        response_text="",
                        passed=True,  # Can't prove header issues if request fails
                        details={"error": str(e)},
                    )
                )
                continue

            elapsed_ms = (time.monotonic() - start) * 1000

            # Extract HTTP response headers from raw
            response_headers: dict = {}
            if isinstance(resp.raw, dict):
                response_headers = {
                    k.lower(): str(v)
                    for k, v in resp.raw.get("_headers", {}).items()
                }

            raw_data["all_headers"][check.name] = response_headers

            # Store baseline headers from first check
            if check.name == "baseline_headers":
                baseline_headers = dict(response_headers)

            # Check for suspicious headers
            found_suspicious = []
            for category, patterns in SUSPICIOUS_HEADER_PATTERNS.items():
                for pattern in patterns:
                    for header_name in response_headers:
                        if pattern in header_name:
                            found_suspicious.append({
                                "header": header_name,
                                "value": response_headers[header_name][:100],
                                "category": category,
                                "check": check.name,
                            })

            # Check for header changes compared to baseline
            new_headers = []
            if baseline_headers and check.name != "baseline_headers":
                for header_name in response_headers:
                    if header_name not in baseline_headers:
                        new_headers.append(header_name)
                    elif response_headers[header_name] != baseline_headers[header_name]:
                        new_headers.append(f"{header_name} (value changed)")

            if new_headers:
                raw_data["header_changes"].append({
                    "check": check.name,
                    "new_or_changed": new_headers,
                })

            # Mark as suspicious if found
            is_suspicious = len(found_suspicious) > 0
            if is_suspicious:
                raw_data["suspicious_headers"].extend(found_suspicious)

            passed = not is_suspicious

            findings.append(
                TestCase(
                    name=check.name,
                    description=check.description,
                    input_tokens=resp.input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=resp.text[:200],
                    passed=passed,
                    details={
                        "headers_found": list(response_headers.keys()),
                        "suspicious_count": len(found_suspicious),
                        "new_headers": new_headers,
                        "expected_behavior": check.expected_behavior,
                    },
                )
            )

        # Risk assessment
        suspicious_count = len(raw_data["suspicious_headers"])
        header_change_count = len(raw_data["header_changes"])

        if suspicious_count >= 3:
            risk = RiskLevel.CRITICAL
            summary = f"Multiple suspicious headers detected ({suspicious_count} headers)"
        elif suspicious_count >= 1:
            risk = RiskLevel.HIGH
            summary = f"Suspicious headers found: {', '.join(h['header'] for h in raw_data['suspicious_headers'][:3])}"
        elif header_change_count >= 2:
            risk = RiskLevel.MEDIUM
            summary = f"Unexpected header variations ({header_change_count} changes detected)"
        else:
            risk = RiskLevel.LOW
            summary = "No suspicious header patterns detected"

        raw_data.update({
            "total_checks": len(checks),
            "suspicious_count": suspicious_count,
            "header_change_count": header_change_count,
        })

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )
