"""T1: Token Injection / Prompt Dumping Detection.

Threat: Relay silently injects a hidden system prompt into every request,
inflating input_tokens beyond what the user actually sent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class BaselineTest:
    """Definition of a single baseline test case."""
    name: str
    system: str | None
    user: str
    expected_tokens_min: int
    expected_tokens_max: int


# Default baseline tests per the architecture spec
DEFAULT_BASELINE_TESTS = [
    BaselineTest(
        name="hello_world",
        system=None,
        user="Say hi",
        expected_tokens_min=3,
        expected_tokens_max=8,
    ),
    BaselineTest(
        name="short_system",
        system="You are a helpful assistant.",
        user="Say hi",
        expected_tokens_min=12,
        expected_tokens_max=20,
    ),
]


class TokenInjectionDetector(DetectorPlugin):
    """Detects hidden system prompts injected by the relay that inflate token usage.

    Algorithm:
    1. Send a minimal user prompt with no system prompt → record baseline tokens
    2. Send the same user prompt with a known-length system prompt → record tokens
    3. Expected delta ≈ system prompt token count
    4. If actual delta >> expected delta, hidden injection is present
    """

    id = "token_injection"
    name = "Token Injection / Prompt Dumping Detection"
    description = (
        "Detects hidden system prompts injected by the relay that inflate "
        "token usage. Compares actual token counts against expected values "
        "for known inputs to identify injected content."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the token injection detection test suite."""
        findings: list[TestCase] = []
        baseline_tokens: int | None = None
        raw_data: dict = {}

        # Determine injection threshold from config
        threshold = getattr(ctx.detector_config, "injection_threshold", 100)
        model = ctx.model

        # Collect baseline tests from config or use defaults
        config_tests = getattr(ctx.detector_config, "baseline_tests", None)
        tests = self._build_tests(config_tests)

        for test in tests:
            req = NormalizedRequest(
                messages=[{"role": "user", "content": test.user}],
                system=test.system,
                model=model,
                max_tokens=64,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                findings.append(
                    TestCase(
                        name=test.name,
                        description=f"Token injection test: {test.name}",
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=0.0,
                        response_text="",
                        passed=False,
                        details={"error": str(e)},
                    )
                )
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            input_tokens = resp.input_tokens

            # First test (no system) establishes baseline overhead
            if test.system is None:
                baseline_tokens = input_tokens
                passed = (
                    test.expected_tokens_min
                    <= input_tokens
                    <= test.expected_tokens_max
                )
                delta_from_expected = input_tokens - test.expected_tokens_min
            else:
                # Calculate expected token count
                system_tokens = ctx.token_estimator.estimate(test.system or "")
                user_tokens = ctx.token_estimator.estimate(test.user)
                expected = baseline_tokens + system_tokens + user_tokens

                actual_delta = input_tokens - baseline_tokens
                expected_delta = system_tokens
                injection_delta = actual_delta - expected_delta

                # The actual overhead might include model-specific formatting
                # We use a wider tolerance: up to 2x the expected delta is acceptable
                passed = actual_delta <= expected_delta * 2 + 20

                raw_data.setdefault("injection_delta", injection_delta)
                raw_data.setdefault("actual_delta", actual_delta)
                raw_data.setdefault("expected_delta", expected_delta)

            findings.append(
                TestCase(
                    name=test.name,
                    description=f"Token injection test: {test.name}",
                    input_tokens=input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=resp.text,
                    passed=passed,
                    details={
                        "baseline_tokens": baseline_tokens,
                        "expected_min": test.expected_tokens_min,
                        "expected_max": test.expected_tokens_max,
                        "system_tokens": ctx.token_estimator.estimate(test.system or ""),
                        "user_tokens": ctx.token_estimator.estimate(test.user),
                    },
                )
            )

        # Determine risk level from injection delta
        injection_delta = raw_data.get("injection_delta", 0)
        if injection_delta > threshold:
            risk = RiskLevel.HIGH
            summary = f"Hidden injection detected (~{injection_delta} tokens/request)"
        elif injection_delta > threshold * 0.5:
            risk = RiskLevel.MEDIUM
            summary = f"Possible injection (~{injection_delta} tokens/request)"
        else:
            risk = RiskLevel.LOW
            summary = "No significant token injection detected"

        raw_data.update({
            "injection_threshold": threshold,
            "total_tests": len(tests),
            "passed_tests": sum(1 for f in findings if f.passed),
        })

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )

    def _build_tests(self, config_tests) -> list[BaselineTest]:
        """Build baseline tests from config or use defaults."""
        if config_tests:
            return [
                BaselineTest(
                    name=t.get("name", f"test_{i}"),
                    system=t.get("system"),
                    user=t.get("user", "Say hi"),
                    expected_tokens_min=t.get("expected_tokens_min", 0),
                    expected_tokens_max=t.get("expected_tokens_max", 100),
                )
                for i, t in enumerate(config_tests)
            ]
        return DEFAULT_BASELINE_TESTS
