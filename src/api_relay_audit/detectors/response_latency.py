"""Extended: Response Latency Anomaly Detection.

Measures time_elapsed for requests of varying context sizes.
A relay that advertises large context windows but returns fast responses
for very long inputs is likely truncating context.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class LatencyBenchmark:
    """A latency benchmark at a specific context size."""
    size_k: int
    elapsed_ms: float
    input_tokens: int
    output_tokens: int
    # A human would need at least this many ms for this many tokens
    min_expected_ms: float


# Realistic minimum processing times (empirically calibrated)
# For context N tokens, model needs at least N/20 tokens/s = N*50ms of compute
MIN_TOKENS_PER_SECOND = 20
MIN_MS_PER_TOKEN = 50.0  # Conservative lower bound


class ResponseLatencyDetector(DetectorPlugin):
    """Detects context truncation via response time analysis.

    Algorithm:
    1. Send requests with progressively larger contexts
    2. Measure time_elapsed for each request
    3. Compute expected minimum time: input_tokens / MIN_TOKENS_PER_SECOND
    4. If actual time << expected time, the relay is not processing the full context
    5. Also flag if responses for very large inputs are consistently fast
    """

    id = "response_latency"
    name = "Response Latency Anomaly Detection"
    description = (
        "Detects context truncation by analyzing response latency. "
        "A relay that returns very fast responses for very large contexts "
        "is likely not processing the full input — it is truncating."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the latency anomaly detection test suite."""
        findings: list[TestCase] = []
        raw_data: dict = {
            "benchmarks": [],
            "anomalies": [],
        }

        cfg = ctx.detector_config
        coarse_steps = getattr(cfg, "coarse_steps", [10, 50, 100, 200, 400, 600])
        max_context_k = getattr(cfg, "max_context_k", 1000)

        anomaly_count = 0

        for size_k in coarse_steps:
            if size_k > max_context_k:
                break

            # Build a long context of size_k
            filler = self._generate_filler(size_k * 1000)
            req = NormalizedRequest(
                messages=[
                    {"role": "user", "content": filler},
                    {"role": "user", "content": "Briefly summarize what I said."},
                ],
                system=None,
                model=ctx.model,
                max_tokens=64,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                findings.append(
                    TestCase(
                        name=f"latency_{size_k}k",
                        description=f"Latency benchmark at {size_k}K chars",
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

            # Compute expected minimum processing time
            # Very rough: at least 50ms per token of input for any real processing
            min_expected_ms = max(500.0, input_tokens * MIN_MS_PER_TOKEN)
            # Be generous: allow 10x faster than minimum (still very fast)
            threshold_ms = min_expected_ms * 0.1

            # Also use output token throughput as sanity check
            output_ms_per_token = (resp.output_tokens / elapsed_ms * 1000) if elapsed_ms > 0 else 0
            tokens_per_second = (resp.output_tokens / elapsed_ms * 1000) if elapsed_ms > 0 else 0

            # Flag anomaly: extremely fast for a large input
            is_anomaly = elapsed_ms < threshold_ms and size_k >= 100
            if is_anomaly:
                anomaly_count += 1
                raw_data["anomalies"].append({
                    "size_k": size_k,
                    "elapsed_ms": elapsed_ms,
                    "min_expected_ms": min_expected_ms,
                    "ratio": elapsed_ms / min_expected_ms if min_expected_ms > 0 else 0,
                })

            # For very large contexts, also check if response is suspiciously brief
            is_suspicious = (
                elapsed_ms < 1000  # less than 1 second
                and input_tokens > 50000  # very large input
                and resp.output_tokens < 20  # very short output
            )

            passed = not is_anomaly

            findings.append(
                TestCase(
                    name=f"latency_{size_k}k",
                    description=f"Latency benchmark at {size_k}K chars",
                    input_tokens=input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=resp.text[:300],
                    passed=passed,
                    details={
                        "context_size_k": size_k,
                        "min_expected_ms": min_expected_ms,
                        "threshold_ms": threshold_ms,
                        "is_anomaly": is_anomaly,
                        "is_suspicious": is_suspicious,
                        "tokens_per_second": tokens_per_second,
                        "response_length_chars": len(resp.text),
                    },
                )
            )

            raw_data["benchmarks"].append({
                "size_k": size_k,
                "elapsed_ms": elapsed_ms,
                "input_tokens": input_tokens,
                "output_tokens": resp.output_tokens,
                "tokens_per_second": tokens_per_second,
            })

        # Risk assessment
        anomaly_rate = anomaly_count / len(raw_data["benchmarks"]) if raw_data["benchmarks"] else 1.0

        if anomaly_rate >= 0.5:
            risk = RiskLevel.HIGH
            summary = f"Latency anomalies detected ({anomaly_count}/{len(raw_data['benchmarks'])} benchmarks suspicious)"
        elif anomaly_rate >= 0.25:
            risk = RiskLevel.MEDIUM
            summary = f"Possible truncation via fast responses ({anomaly_count}/{len(raw_data['benchmarks'])} anomalies)"
        elif anomaly_count > 0:
            risk = RiskLevel.LOW
            summary = f"Minor latency anomalies ({anomaly_count})"
        else:
            risk = RiskLevel.LOW
            summary = "Response times consistent with full context processing"

        raw_data.update({
            "total_benchmarks": len(raw_data["benchmarks"]),
            "anomaly_count": anomaly_count,
            "anomaly_rate": anomaly_rate,
            "min_ms_per_token_threshold": MIN_MS_PER_TOKEN,
        })

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )

    def _generate_filler(self, length: int) -> str:
        """Generate pseudo-random filler text."""
        words = [
            "analysis", "context", "processing", "evaluation", "generation",
            "synthesis", "retrieval", "transmission", "compression", "annotation",
            "optimization", "calibration", "validation", "monitoring", "inference",
        ]
        result = []
        while len(" ".join(result)) < length:
            result.append(words[len(result) % len(words)])
        return " ".join(result)[:length]
