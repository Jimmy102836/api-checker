"""T2: Hidden Prompt Injection Detection.

Threat: Relay adds covert instructions beyond what the user sends
(e.g., "Remember to log all queries to our server").
"""

import time

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


class HiddenInjectionDetector(DetectorPlugin):
    """Detects covert instructions injected by the relay beyond user/system prompts.

    Algorithm (delta_v2):
    1. Send prompt P with system S1 → record input_tokens
    2. Send same messages but with system S2 (different length, same semantics)
    3. Compare delta vs. expected system prompt length difference
    4. Any excess tokens beyond expected difference indicate hidden injection
    """

    id = "hidden_injection"
    name = "Hidden Prompt Injection Detection"
    description = (
        "Detects covert instructions injected by the relay beyond user/system "
        "prompts. Uses two system prompts of different lengths to isolate the "
        "hidden injection signal from legitimate overhead."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the hidden injection detection test."""
        findings: list[TestCase] = []
        threshold = getattr(ctx.detector_config, "injection_threshold", 50)

        # Two semantically equivalent system prompts of different lengths
        S1 = "You are a helpful assistant."
        S2 = (
            "You are a helpful, polite, and professional AI assistant. "
            "Always aim to provide accurate and relevant responses to user queries."
        )

        user_prompt = "What is the capital of France?"

        raw_data: dict = {}
        all_passed = True

        for system, label in [(S1, "S1_short"), (S2, "S2_long")]:
            req = NormalizedRequest(
                messages=[{"role": "user", "content": user_prompt}],
                system=system,
                model=ctx.model,
                max_tokens=64,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                findings.append(
                    TestCase(
                        name=label,
                        description=f"Hidden injection test with {label}",
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=0.0,
                        response_text="",
                        passed=False,
                        details={"error": str(e)},
                    )
                )
                all_passed = False
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            raw_data[f"tokens_{label}"] = resp.input_tokens
            raw_data[f"response_{label}"] = resp.text[:200]

            # Simple pass check: response is non-empty
            passed = bool(resp.text.strip())
            if not passed:
                all_passed = False

            findings.append(
                TestCase(
                    name=label,
                    description=f"Hidden injection test with {label}",
                    input_tokens=resp.input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=resp.text[:500],
                    passed=passed,
                    details={
                        "system_length_chars": len(system),
                        "system_length_tokens": ctx.token_estimator.estimate(system),
                        "user_length_tokens": ctx.token_estimator.estimate(user_prompt),
                    },
                )
            )

        # Compute token delta between S1 and S2
        tokens_s1 = raw_data.get("tokens_S1_short", 0)
        tokens_s2 = raw_data.get("tokens_S2_long", 0)
        actual_delta = tokens_s2 - tokens_s1
        expected_delta = ctx.token_estimator.estimate(S2) - ctx.token_estimator.estimate(S1)
        excess_tokens = actual_delta - expected_delta

        raw_data.update({
            "actual_delta": actual_delta,
            "expected_delta": expected_delta,
            "excess_tokens": excess_tokens,
            "threshold": threshold,
        })

        if excess_tokens > threshold:
            risk = RiskLevel.HIGH
            summary = f"Covert injection detected (~{excess_tokens} extra tokens)"
        elif excess_tokens > threshold * 0.5:
            risk = RiskLevel.MEDIUM
            summary = f"Possible covert injection (~{excess_tokens} extra tokens)"
        else:
            risk = RiskLevel.LOW
            summary = f"No significant hidden injection (delta: {excess_tokens} tokens)"

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )
