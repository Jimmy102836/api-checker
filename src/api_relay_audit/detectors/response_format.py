"""Extended: Response Format Fingerprint Detection.

Sends requests with strict JSON format instructions and checks whether
the response is valid JSON. Relay injection can corrupt the format,
making output invalid or altering structure.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class FormatTest:
    """A single format fingerprint test."""
    name: str
    system: str | None
    user: str
    required_keys: list[str]  # JSON keys the response must contain
    expected_structure: str   # human-readable description


DEFAULT_FORMAT_TESTS = [
    FormatTest(
        name="json_object",
        system="Respond ONLY with valid JSON. No markdown, no explanation, no text outside the JSON.",
        user="Give me a JSON object with fields: name (string), age (number), city (string).",
        required_keys=["name", "age", "city"],
        expected_structure="object with name/age/city",
    ),
    FormatTest(
        name="json_array",
        system="Respond ONLY with valid JSON array. No markdown fences, no text outside the array.",
        user="Give me a JSON array of 3 prime numbers.",
        required_keys=[],  # array structure
        expected_structure="array of numbers",
    ),
    FormatTest(
        name="nested_json",
        system="Respond ONLY with valid nested JSON. No markdown, no code fences, no explanation.",
        user='Give me JSON: {"user": {"name": "...", "id": 123}, "active": true}',
        required_keys=["user", "active"],
        expected_structure="nested object",
    ),
    FormatTest(
        name="json_with_specific_values",
        system="Respond ONLY with valid JSON. No markdown fences.",
        user='Answer ONLY: {"magic_number": YOUR_FAVORITE_NUMBER, "word": "hello"}',
        required_keys=["magic_number", "word"],
        expected_structure="object with specific fields",
    ),
    FormatTest(
        name="empty_response",
        system="Respond ONLY with JSON: {\"status\": \"ok\"}",
        user="Say hello",
        required_keys=["status"],
        expected_structure="minimal object",
    ),
]


class ResponseFormatFingerprintDetector(DetectorPlugin):
    """Detects relay injection via response format corruption.

    Algorithm:
    1. Send a request with strict JSON output instructions
    2. Check if the response is valid JSON
    3. If JSON is invalid, injection is likely corrupting the format
    4. If JSON is valid but missing required keys, the injection may be
       stripping or altering content
    5. Also check for common injection artifacts (extra text around JSON)
    """

    id = "response_format"
    name = "Response Format Fingerprint Detection"
    description = (
        "Detects relay injection by checking if responses maintain expected "
        "JSON format. Injection often corrupts format or adds text around JSON, "
        "making output invalid or altering structure."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the format fingerprint detection test suite."""
        findings: list[TestCase] = []
        failed_tests: list[str] = []
        raw_data: dict = {
            "format_tests": [],
            "invalid_json_count": 0,
            "missing_keys_count": 0,
            "corruption_artifacts": [],
        }

        tests = DEFAULT_FORMAT_TESTS

        for test in tests:
            req = NormalizedRequest(
                messages=[{"role": "user", "content": test.user}],
                system=test.system,
                model=ctx.model,
                max_tokens=128,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                findings.append(
                    TestCase(
                        name=test.name,
                        description=f"Format test: {test.name}",
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=elapsed_ms,
                        response_text="",
                        passed=False,
                        details={"error": str(e)},
                    )
                )
                failed_tests.append(test.name)
                raw_data["format_tests"].append({"name": test.name, "passed": False})
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            response_text = resp.text.strip()

            # Check for markdown fences (common injection artifact)
            has_fences = response_text.startswith("```") or response_text.endswith("```")
            has_extra_text = False

            # Try to extract JSON from the response
            json_text = response_text
            if has_fences:
                # Strip ```json ... ```
                lines = response_text.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                json_text = "\n".join(lines).strip()

            # Check for text outside JSON
            try:
                parsed = json.loads(json_text)
                json_valid = True
                parse_error = None
            except json.JSONDecodeError as e:
                parsed = None
                json_valid = False
                parse_error = str(e)
                # Try to detect what went wrong
                if "expecting" in str(e):
                    raw_data["corruption_artifacts"].append({
                        "test": test.name,
                        "issue": f"JSON parse error: {e}",
                    })

            # Check required keys
            missing_keys = []
            if json_valid and test.required_keys and isinstance(parsed, dict):
                missing_keys = [k for k in test.required_keys if k not in parsed]

            # Check for extra text outside JSON
            if json_valid and not has_fences:
                # Try to detect if there's text before/after JSON
                stripped = response_text.strip()
                if not (stripped.startswith("{") or stripped.startswith("[")):
                    has_extra_text = True
                    raw_data["corruption_artifacts"].append({
                        "test": test.name,
                        "issue": "extra text outside JSON",
                    })

            passed = json_valid and not missing_keys and not has_extra_text
            if not passed:
                failed_tests.append(test.name)

            if not json_valid:
                raw_data["invalid_json_count"] += 1
            if missing_keys:
                raw_data["missing_keys_count"] += 1

            findings.append(
                TestCase(
                    name=test.name,
                    description=f"Format test: {test.name}",
                    input_tokens=resp.input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=response_text[:500],
                    passed=passed,
                    details={
                        "expected_structure": test.expected_structure,
                        "json_valid": json_valid,
                        "parse_error": parse_error,
                        "has_fences": has_fences,
                        "has_extra_text": has_extra_text,
                        "missing_keys": missing_keys,
                        "parsed_type": type(parsed).__name__ if parsed else None,
                    },
                )
            )

            raw_data["format_tests"].append({
                "name": test.name,
                "passed": passed,
                "json_valid": json_valid,
                "has_fences": has_fences,
                "missing_keys": missing_keys,
            })

        # Risk assessment
        failure_rate = len(failed_tests) / len(tests) if tests else 1.0
        invalid_count = raw_data["invalid_json_count"]

        if invalid_count >= 2:
            risk = RiskLevel.HIGH
            summary = f"Format corruption confirmed ({invalid_count} invalid JSON responses)"
        elif failure_rate >= 0.4:
            risk = RiskLevel.MEDIUM
            summary = f"Format inconsistencies detected ({len(failed_tests)}/{len(tests)} tests failed)"
        elif failure_rate > 0:
            risk = RiskLevel.LOW
            summary = f"Mild format issues ({len(failed_tests)}/{len(tests)} tests failed)"
        else:
            risk = RiskLevel.LOW
            summary = "Response format integrity maintained"

        raw_data.update({
            "total_tests": len(tests),
            "failed_tests": failed_tests,
            "failure_rate": failure_rate,
        })

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )
