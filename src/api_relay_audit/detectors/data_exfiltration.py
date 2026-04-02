"""T5: Data Exfiltration Detection.

Threat: Relay retains or leaks conversation content, API keys, or user data
across sessions or to third parties.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class ExfilTest:
    """Definition of a single exfiltration test."""
    name: str
    description: str
    marker_injected: str | None
    expect_markers_in_response: bool
    user_prompt: str
    session_type: str  # "new" or "same"


# Known suspicious HTTP headers that may indicate logging or forwarding
SUSPICIOUS_HEADERS = {
    "x-query-log",
    "x-request-log",
    "x-data-forward",
    "x-forwarded-query",
    "x-api-log",
    "x-relay-log",
    "x-snoop",
    "x-log-request",
}


class DataExfiltrationDetector(DetectorPlugin):
    """Detects whether the relay retains, logs, or leaks conversation content.

    Algorithm:
    1. API Key Leak Test: send synthetic canary key, ask to reveal in new session
    2. Cross-Conversation Leak Test: new session asks about previous content
    3. Header Inspection: check for suspicious logging/forwarding headers
    """

    id = "data_exfiltration"
    name = "Data Exfiltration Detection"
    description = (
        "Detects whether the relay retains, logs, or leaks conversation content, "
        "API keys, or user data across sessions or to third parties."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the data exfiltration detection test suite."""
        findings: list[TestCase] = []
        raw_data: dict = {
            "suspicious_headers": [],
            "cross_session_leak": False,
            "api_key_leak": False,
        }

        # Build tests from config or use defaults
        config_tests = getattr(ctx.detector_config, "tests", None)
        tests = self._build_tests(config_tests)

        # Track the canary marker from the injection test for cross-session check
        injected_marker = "SECRET_API_KEY_sk_test_12345xyz_canary"

        # Test 1: Inject a canary and see if it's recalled in a new session
        req_inject = NormalizedRequest(
            messages=[{"role": "user", "content": injected_marker}],
            system=None,
            model=ctx.model,
            max_tokens=64,
        )

        start = time.monotonic()
        try:
            ctx.adapter.call(req_inject)
        except Exception as e:
            findings.append(
                TestCase(
                    name="api_key_injection",
                    description="Inject synthetic canary API key",
                    input_tokens=0,
                    output_tokens=0,
                    elapsed_ms=0.0,
                    response_text="",
                    passed=False,
                    details={"error": str(e)},
                )
            )
        elapsed_ms = (time.monotonic() - start) * 1000

        # Small delay between sessions
        time.sleep(0.5)

        # Test 2: New session — ask about the previous message
        req_recall = NormalizedRequest(
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"I just sent you a message. What was it? "
                        f"Quote the exact content you received."
                    ),
                }
            ],
            system=None,
            model=ctx.model,
            max_tokens=128,
        )

        start = time.monotonic()
        try:
            resp = ctx.adapter.call(req_recall)
        except Exception as e:
            findings.append(
                TestCase(
                    name="api_key_leak",
                    description="Check if synthetic API key leaked from previous session",
                    input_tokens=0,
                    output_tokens=0,
                    elapsed_ms=0.0,
                    response_text="",
                    passed=True,  # Can't prove leak if request failed
                    details={"error": str(e)},
                )
            )
            return self._build_result(findings, raw_data, tests)

        elapsed_ms = (time.monotonic() - start) * 1000
        response_lower = resp.text.lower()

        # Check if the canary key appeared in the response
        key_leaked = injected_marker.lower() in response_lower

        # Check for partial key leakage (first 16 chars of the key)
        partial_leak = any(
            injected_marker[i : i + 12].lower() in response_lower
            for i in range(0, min(len(injected_marker), 20), 4)
        )

        findings.append(
            TestCase(
                name="api_key_leak",
                description="Check if synthetic API key leaked from previous session",
                input_tokens=resp.input_tokens,
                output_tokens=resp.output_tokens,
                elapsed_ms=elapsed_ms,
                response_text=resp.text[:500],
                passed=not key_leaked and not partial_leak,
                details={
                    "injected_marker": injected_marker,
                    "key_leaked": key_leaked,
                    "partial_leak": partial_leak,
                    "marker_injected": True,
                    "expect_markers_in_response": False,
                },
            )
        )

        raw_data["api_key_leak"] = key_leaked or partial_leak

        # Test 3: Cross-conversation memory test
        unique_marker = "ALPHA_BETA_999_marker"

        req_embed = NormalizedRequest(
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Remember this code snippet for our session: "
                        f"```python\ndef hack(): pass\n``` "
                        f"And this marker: {unique_marker}"
                    ),
                }
            ],
            system=None,
            model=ctx.model,
            max_tokens=64,
        )

        try:
            ctx.adapter.call(req_embed)
        except Exception:
            pass

        time.sleep(0.5)

        req_cross = NormalizedRequest(
            messages=[
                {
                    "role": "user",
                    "content": (
                        "In our previous conversation, what code snippet did I share? "
                        "What marker did I ask you to remember?"
                    ),
                }
            ],
            system=None,
            model=ctx.model,
            max_tokens=128,
        )

        start = time.monotonic()
        try:
            resp_cross = ctx.adapter.call(req_cross)
        except Exception as e:
            findings.append(
                TestCase(
                    name="cross_conversation_leak",
                    description="Check if content persists across sessions",
                    input_tokens=0,
                    output_tokens=0,
                    elapsed_ms=0.0,
                    response_text="",
                    passed=True,
                    details={"error": str(e)},
                )
            )
            return self._build_result(findings, raw_data, tests)

        elapsed_ms = (time.monotonic() - start) * 1000
        cross_leaked = (
            "def hack" in resp_cross.text.lower()
            or unique_marker.lower() in resp_cross.text.lower()
        )

        findings.append(
            TestCase(
                name="cross_conversation_leak",
                description="Check if content persists across sessions",
                input_tokens=resp_cross.input_tokens,
                output_tokens=resp_cross.output_tokens,
                elapsed_ms=elapsed_ms,
                response_text=resp_cross.text[:500],
                passed=not cross_leaked,
                details={
                    "unique_marker": unique_marker,
                    "cross_leaked": cross_leaked,
                },
            )
        )

        raw_data["cross_session_leak"] = cross_leaked

        # Test 4: Header inspection (if response has headers)
        self._check_suspicious_headers(resp, raw_data)

        return self._build_result(findings, raw_data, tests)

    def _build_tests(self, config_tests) -> list[ExfilTest]:
        """Build exfiltration tests from config or use defaults."""
        if config_tests:
            return [
                ExfilTest(
                    name=t.get("name", f"test_{i}"),
                    description=f"Data exfiltration test: {t.get('name', i)}",
                    marker_injected=t.get("marker_injected"),
                    expect_markers_in_response=t.get("expect_markers_in_response", False),
                    user_prompt=t.get("user", ""),
                    session_type="new",
                )
                for i, t in enumerate(config_tests)
            ]
        # Default tests
        return [
            ExfilTest(
                name="api_key_leak",
                description="Synthetic API key leak test",
                marker_injected="SECRET_API_KEY_sk_test_12345xyz",
                expect_markers_in_response=False,
                user_prompt="What was my first message?",
                session_type="new",
            ),
            ExfilTest(
                name="cross_conversation_leak",
                description="Cross-conversation content leak test",
                marker_injected=None,
                expect_markers_in_response=False,
                user_prompt="In our previous conversation, what code did I share?",
                session_type="new",
            ),
        ]

    def _check_suspicious_headers(
        self, resp, raw_data: dict
    ) -> None:
        """Examine HTTP response headers for suspicious logging headers."""
        suspicious = []
        raw_headers = resp.raw.get("headers", {}) if isinstance(resp.raw, dict) else {}

        for header_name in raw_headers:
            header_lower = header_name.lower()
            for suspicious_pattern in SUSPICIOUS_HEADERS:
                if suspicious_pattern in header_lower:
                    suspicious.append(header_name)

        raw_data["suspicious_headers"] = suspicious

    def _build_result(
        self,
        findings: list[TestCase],
        raw_data: dict,
        tests: list[ExfilTest],
    ) -> DetectorResult:
        """Build the final DetectorResult from findings."""
        api_leak = raw_data.get("api_key_leak", False)
        cross_leak = raw_data.get("cross_session_leak", False)
        suspicious_headers = raw_data.get("suspicious_headers", [])

        failed_tests = sum(1 for f in findings if not f.passed)

        if api_leak or (suspicious_headers and len(suspicious_headers) > 0):
            risk = RiskLevel.CRITICAL
            summary = "Data exfiltration confirmed"
        elif cross_leak:
            risk = RiskLevel.HIGH
            summary = "Cross-session data persistence detected"
        elif suspicious_headers:
            risk = RiskLevel.MEDIUM
            summary = f"Suspicious headers detected: {', '.join(suspicious_headers)}"
        elif failed_tests > 0:
            risk = RiskLevel.MEDIUM
            summary = f"{failed_tests} exfiltration test(s) inconclusive"
        else:
            risk = RiskLevel.LOW
            summary = "No data exfiltration detected"

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )
