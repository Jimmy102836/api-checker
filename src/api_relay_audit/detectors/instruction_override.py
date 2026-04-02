"""T3: Instruction Override Detection.

Threat: User-provided system prompts are ignored or replaced by the relay.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class OverrideTest:
    """Definition of a single instruction override test."""
    name: str
    system: str
    user: str
    expect_contains: list[str]
    expect_excludes: list[str]


DEFAULT_TESTS = [
    OverrideTest(
        name="cat_test",
        system="From now on, only reply with the single word meow. No other characters.",
        user="What is 1+1?",
        expect_contains=["meow"],
        expect_excludes=["1", "2", "equals", "two", "addition"],
    ),
    OverrideTest(
        name="identity_test",
        system="You are Claude, made by Anthropic. Never claim to be anyone else.",
        user="Who are you? Who made you?",
        expect_contains=["Claude", "Anthropic"],
        expect_excludes=["Amazon", "AWS", "Kiro"],
    ),
]


class InstructionOverrideDetector(DetectorPlugin):
    """Detects when the relay ignores or overrides user-provided system prompts.

    Algorithm:
    1. Cat Test: system forces single-word response, verify it's honored
    2. Identity Test: system defines identity, verify it's preserved
    3. HTTP 422 Detection: if 422 returned, relay rejected custom system prompts
    """

    id = "instruction_override"
    name = "Instruction Override Detection"
    description = (
        "Detects when the relay ignores or overrides user-provided system prompts "
        "using behavioral tests (cat test, identity test) and HTTP status analysis."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the instruction override detection test suite."""
        findings: list[TestCase] = []
        overridden_tests: list[str] = []
        rejected_422 = False

        # Collect tests from config or use defaults
        config_tests = getattr(ctx.detector_config, "tests", None)
        tests = self._build_tests(config_tests)

        for test in tests:
            req = NormalizedRequest(
                messages=[{"role": "user", "content": test.user}],
                system=test.system,
                model=ctx.model,
                max_tokens=32,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                err_str = str(e)
                is_422 = "422" in err_str or "Unprocessable" in err_str
                if is_422:
                    rejected_422 = True

                findings.append(
                    TestCase(
                        name=test.name,
                        description=f"Instruction override test: {test.name}",
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=0.0,
                        response_text="",
                        passed=False,
                        details={
                            "error": err_str,
                            "is_422": is_422,
                            "overridden": True,
                        },
                    )
                )
                overridden_tests.append(test.name)
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            response_lower = resp.text.lower()

            # Check contains criteria
            contains_met = all(
                kw.lower() in response_lower for kw in test.expect_contains
            )

            # Check excludes criteria
            excludes_met = not any(
                kw.lower() in response_lower for kw in test.expect_excludes
            )

            passed = contains_met and excludes_met

            if not passed:
                overridden_tests.append(test.name)

            findings.append(
                TestCase(
                    name=test.name,
                    description=f"Instruction override test: {test.name}",
                    input_tokens=resp.input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=resp.text[:500],
                    passed=passed,
                    details={
                        "system_prompt": test.system[:200],
                        "expect_contains": test.expect_contains,
                        "expect_excludes": test.expect_excludes,
                        "contains_met": contains_met,
                        "excludes_met": excludes_met,
                    },
                )
            )

        raw_data = {
            "overridden_tests": overridden_tests,
            "rejected_422": rejected_422,
            "total_tests": len(tests),
        }

        # Risk level
        if rejected_422:
            risk = RiskLevel.HIGH
            summary = "Relay rejected custom system prompts (HTTP 422)"
        elif len(overridden_tests) == len(tests):
            risk = RiskLevel.HIGH
            summary = f"All {len(tests)} tests failed — system prompts completely overridden"
        elif overridden_tests:
            risk = RiskLevel.MEDIUM
            summary = f"{len(overridden_tests)}/{len(tests)} tests failed — partial override detected"
        else:
            risk = RiskLevel.LOW
            summary = "All instruction override tests passed"

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )

    def _build_tests(self, config_tests) -> list[OverrideTest]:
        """Build override tests from config or use defaults."""
        if config_tests:
            return [
                OverrideTest(
                    name=t.get("name", f"test_{i}"),
                    system=t.get("system", ""),
                    user=t.get("user", "test"),
                    expect_contains=t.get("expect_response_contains", []),
                    expect_excludes=t.get("expect_response_excludes", []),
                )
                for i, t in enumerate(config_tests)
            ]
        return DEFAULT_TESTS
