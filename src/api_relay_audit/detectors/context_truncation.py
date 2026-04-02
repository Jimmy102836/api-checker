"""T4: Context Truncation Detection.

Threat: Relay advertises a large context window but silently truncates
conversations beyond a smaller limit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class ScanResult:
    """Result of a single context size scan."""
    size_k: int
    input_tokens: int
    canaries_found: int
    canaries_total: int
    passed: bool
    elapsed_ms: float


class ContextTruncationDetector(DetectorPlugin):
    """Detects silent context window truncation using canary marker recall.

    Algorithm:
    1. Embed N unique canary markers at evenly spaced intervals in long text
    2. Ask the model to list all canary markers it can recall
    3. Coarse scan: test [50, 100, 200, 400, 600, 800]K chars
    4. Binary search: narrow boundary within binary_search_threshold
    5. Report truncation boundary and estimated max working context
    """

    id = "context_truncation"
    name = "Context Truncation Detection"
    description = (
        "Detects when the relay silently truncates context windows below "
        "the advertised limit using canary marker recall + binary search."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the context truncation detection."""
        findings: list[TestCase] = []
        scan_results: list[ScanResult] = []

        # Extract config parameters
        cfg = ctx.detector_config
        coarse_steps = getattr(cfg, "coarse_steps", [50, 100, 200, 400, 600, 800])
        binary_threshold = getattr(cfg, "binary_search_threshold", 20)
        canary_count = getattr(cfg, "canary_count", 5)
        max_context_k = getattr(cfg, "max_context_k", 1000)

        # Generate canary markers
        markers = ctx.canary_generator.generate_markers(canary_count)
        if not ctx.canary_generator.validate_markers(markers):
            return DetectorResult(
                detector_id=self.id,
                risk_level=RiskLevel.MEDIUM,
                summary="Canary marker generation/validation failed",
                findings=[],
                raw_data={"error": "Invalid canary markers"},
            )

        # Phase 1: Coarse scan
        last_passing_size_k = 0
        first_failing_size_k = None

        for size_k in coarse_steps:
            if size_k > max_context_k:
                break

            result = self._test_context_size(ctx, size_k, markers)
            scan_results.append(result)

            findings.append(
                TestCase(
                    name=f"coarse_{size_k}k",
                    description=f"Context size test: {size_k}K chars",
                    input_tokens=result.input_tokens,
                    output_tokens=0,
                    elapsed_ms=result.elapsed_ms,
                    response_text="",
                    passed=result.passed,
                    details={
                        "canaries_found": result.canaries_found,
                        "canaries_total": result.canaries_total,
                        "context_size_k": size_k,
                        "token_count": result.input_tokens,
                    },
                )
            )

            if result.passed:
                last_passing_size_k = size_k
            elif first_failing_size_k is None:
                first_failing_size_k = size_k
                # Stop after first failure, then binary search
                break

        # Determine boundary for binary search
        if first_failing_size_k is not None:
            # Binary search between last_passing and first_failing
            low_k = last_passing_size_k
            high_k = first_failing_size_k

            while high_k - low_k > binary_threshold:
                mid_k = (low_k + high_k) // 2
                result = self._test_context_size(ctx, mid_k, markers)

                findings.append(
                    TestCase(
                        name=f"binary_{mid_k}k",
                        description=f"Binary search context size: {mid_k}K chars",
                        input_tokens=result.input_tokens,
                        output_tokens=0,
                        elapsed_ms=result.elapsed_ms,
                        response_text="",
                        passed=result.passed,
                        details={
                            "canaries_found": result.canaries_found,
                            "canaries_total": result.canaries_total,
                            "context_size_k": mid_k,
                            "token_count": result.input_tokens,
                        },
                    )
                )

                if result.passed:
                    low_k = mid_k
                else:
                    high_k = mid_k

            boundary_range = f"{low_k}K ~ {high_k}K chars"
            max_context = low_k
        elif last_passing_size_k > 0:
            boundary_range = f">{last_passing_size_k}K chars (full range)"
            max_context = last_passing_size_k
        else:
            boundary_range = "unknown"
            max_context = 0

        # Determine risk level
        # HIGH if boundary < 80% of advertised max
        advertised_max = max_context_k
        if max_context > 0 and max_context < advertised_max * 0.8:
            risk = RiskLevel.HIGH
            summary = f"Context truncation detected at ~{boundary_range}"
        elif max_context > 0 and max_context < advertised_max:
            risk = RiskLevel.MEDIUM
            summary = f"Context smaller than max tested: {boundary_range}"
        else:
            risk = RiskLevel.LOW
            summary = f"Full context window intact: {boundary_range}"

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data={
                "boundary_range": boundary_range,
                "max_working_tokens": scan_results[-1].input_tokens if scan_results else 0,
                "scan_results": [
                    {
                        "size_k": r.size_k,
                        "canaries_found": r.canaries_found,
                        "canaries_total": r.canaries_total,
                        "passed": r.passed,
                    }
                    for r in scan_results
                ],
                "canary_markers": markers,
            },
        )

    def _test_context_size(
        self, ctx: AuditContext, size_k: int, markers: list[str]
    ) -> ScanResult:
        """Test a specific context size by sending a prompt with embedded canaries."""
        total_chars = size_k * 1000

        # Build filler text with embedded canary markers
        filler_text = ctx.canary_generator.build_filler_text(total_chars, markers)

        # Build the recall request
        recall_prompt = (
            "List all the CANARY markers you can recall from our conversation. "
            "Quote each marker exactly as it appears."
        )

        # Send: filler with markers + recall instruction
        req = NormalizedRequest(
            messages=[
                {"role": "user", "content": filler_text},
                {"role": "user", "content": recall_prompt},
            ],
            system=None,
            model=ctx.model,
            max_tokens=256,
        )

        start = time.monotonic()
        try:
            resp = ctx.adapter.call(req)
        except Exception:
            elapsed_ms = (time.monotonic() - start) * 1000
            return ScanResult(
                size_k=size_k,
                input_tokens=0,
                canaries_found=0,
                canaries_total=len(markers),
                passed=False,
                elapsed_ms=elapsed_ms,
            )

        elapsed_ms = (time.monotonic() - start) * 1000

        # Extract recalled markers
        found_markers = ctx.canary_generator.extract_markers_from_response(
            resp.text, markers
        )

        # Pass if all canaries are recalled (within the context limit)
        passed = len(found_markers) == len(markers)

        return ScanResult(
            size_k=size_k,
            input_tokens=resp.input_tokens,
            canaries_found=len(found_markers),
            canaries_total=len(markers),
            passed=passed,
            elapsed_ms=elapsed_ms,
        )
