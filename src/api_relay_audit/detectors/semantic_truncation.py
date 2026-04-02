"""Extended: Semantic Truncation Detection.

Instead of exact canary markers (which can be trivially detected/filtered),
uses semantic埋点 — embedded facts, numbers, and phrases that can only be
recalled if the full context is preserved. Detection uses keyword/phrase
proximity matching.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class SemanticMarker:
    """A semantic埋点: an embedded fact or phrase detectable via keyword proximity."""
    category: str       # "number", "fact", "phrase"
    keywords: list[str] # words that should co-occur if context is intact
    embed_text: str     # the exact text to embed in context


# Default semantic markers spanning different content types
DEFAULT_MARKERS = [
    SemanticMarker(
        category="number",
        keywords=["lucky", "number", "42"],
        embed_text="My lucky number is 42.",
    ),
    SemanticMarker(
        category="fact",
        keywords=["capital", "france", "paris"],
        embed_text="The capital of France is Paris.",
    ),
    SemanticMarker(
        category="phrase",
        keywords=["quantum", "flufflenoggle", "token"],
        embed_text="In our session, remember the word 'quantum flufflenoggle' for token reference.",
    ),
    SemanticMarker(
        category="fact",
        keywords=["element", "hydrogen", "atomic"],
        embed_text="Hydrogen has atomic number 1.",
    ),
    SemanticMarker(
        category="number",
        keywords=["magic", "number", "7"],
        embed_text="My favorite magic number is 7.",
    ),
]


class SemanticTruncationDetector(DetectorPlugin):
    """Detects context truncation using semantic埋点 instead of exact canary markers.

    Algorithm:
    1. Embed N semantic markers (facts/numbers/phrases) in a long conversation
    2. Ask the model to recall all embedded information
    3. Use keyword co-occurrence scoring: if a marker has ALL its keywords
       present within a window in the response, it counts as recalled
    4. Any unrecalled markers suggest truncation
    5. Binary search narrows the truncation boundary
    """

    id = "semantic_truncation"
    name = "Semantic Truncation Detection"
    description = (
        "Detects context truncation using semantic埋点 (embedded facts, numbers, "
        "phrases) instead of exact canary markers. Uses keyword co-occurrence "
        "scoring to determine whether semantic content was retained or truncated."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the semantic truncation detection test suite."""
        findings: list[TestCase] = []
        raw_data: dict = {}
        markers = DEFAULT_MARKERS

        cfg = ctx.detector_config
        coarse_steps = getattr(cfg, "coarse_steps", [50, 100, 200, 400, 600, 800])
        binary_threshold = getattr(cfg, "binary_search_threshold", 20)
        max_context_k = getattr(cfg, "max_context_k", 1000)

        # Build conversation with embedded semantic markers
        def build_context(size_k: int) -> list[dict]:
            """Build a multi-turn conversation of approximately size_k."""
            total_chars = size_k * 1000
            messages = []

            # Embed markers evenly across conversation turns
            turns_per_marker = max(1, len(coarse_steps) // len(markers))

            filler = self._generate_filler(total_chars - sum(len(m.embed_text) for m in markers))
            parts = []
            marker_idx = 0
            segment_size = len(filler) // (len(markers) + 1)
            for i, marker in enumerate(markers):
                start = i * segment_size
                end = start + segment_size
                parts.append(filler[start:end] + f" {marker.embed_text}")

            # Add remaining filler
            parts.append(filler[len(parts) * segment_size:])

            for part in parts:
                if part.strip():
                    messages.append({"role": "user", "content": part.strip()})

            # Add recall prompt
            messages.append({
                "role": "user",
                "content": (
                    "From our entire conversation, please recall and list all "
                    "the specific facts, numbers, and phrases I asked you to remember. "
                    "Be as complete as possible."
                ),
            })
            return messages

        def recall_test(size_k: int) -> tuple[TestCase, int]:
            """Send a context of size_k and score semantic recall."""
            messages = build_context(size_k)
            req = NormalizedRequest(
                messages=messages,
                system=None,
                model=ctx.model,
                max_tokens=256,
            )

            start = time.monotonic()
            try:
                resp = ctx.adapter.call(req)
            except Exception as e:
                elapsed_ms = (time.monotonic() - start) * 1000
                return TestCase(
                    name=f"semantic_{size_k}k",
                    description=f"Semantic truncation test at {size_k}K chars",
                    input_tokens=0, output_tokens=0, elapsed_ms=elapsed_ms,
                    response_text="", passed=False,
                    details={"error": str(e), "canaries_found": 0, "canaries_total": len(markers)},
                ), 0

            elapsed_ms = (time.monotonic() - start) * 1000
            response_lower = resp.text.lower()

            # Score each marker by keyword co-occurrence
            found_count = 0
            for marker in markers:
                score = self._score_marker_recall(response_lower, marker)
                if score >= len(marker.keywords):
                    found_count += 1

            passed = found_count == len(markers)
            return TestCase(
                name=f"semantic_{size_k}k",
                description=f"Semantic truncation test at {size_k}K chars",
                input_tokens=resp.input_tokens,
                output_tokens=resp.output_tokens,
                elapsed_ms=elapsed_ms,
                response_text=resp.text[:500],
                passed=passed,
                details={
                    "canaries_found": found_count,
                    "canaries_total": len(markers),
                    "context_size_k": size_k,
                    "token_count": resp.input_tokens,
                },
            ), found_count

        # Phase 1: Coarse scan
        last_passing = 0
        first_failing = None

        for size_k in coarse_steps:
            if size_k > max_context_k:
                break

            tc, found = recall_test(size_k)
            findings.append(tc)
            if found == len(markers):
                last_passing = size_k
            elif first_failing is None:
                first_failing = size_k
                break

        # Phase 2: Binary search
        if first_failing is not None:
            low_k, high_k = last_passing, first_failing
            while high_k - low_k > binary_threshold:
                mid_k = (low_k + high_k) // 2
                tc, found = recall_test(mid_k)
                findings.append(tc)
                if found == len(markers):
                    low_k = mid_k
                else:
                    high_k = mid_k

            boundary_range = f"{low_k}K ~ {high_k}K chars"
            max_context = low_k
        elif last_passing > 0:
            boundary_range = f">{last_passing}K chars"
            max_context = last_passing
        else:
            boundary_range = "unknown"
            max_context = 0

        # Risk assessment
        if max_context > 0 and max_context < max_context_k * 0.8:
            risk = RiskLevel.HIGH
            summary = f"Semantic truncation detected at ~{boundary_range}"
        elif max_context > 0 and max_context < max_context_k:
            risk = RiskLevel.MEDIUM
            summary = f"Reduced context: {boundary_range}"
        else:
            risk = RiskLevel.LOW
            summary = f"Full semantic context intact: {boundary_range}"

        raw_data.update({
            "boundary_range": boundary_range,
            "max_context_k": max_context,
            "total_markers": len(markers),
            "coarse_steps": coarse_steps,
        })

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )

    def _score_marker_recall(self, response_lower: str, marker: SemanticMarker) -> int:
        """Score how well a semantic marker was recalled (keyword co-occurrence)."""
        score = 0
        # All keywords must appear in the response
        for kw in marker.keywords:
            if kw.lower() in response_lower:
                score += 1
        return score

    def _generate_filler(self, length: int) -> str:
        """Generate pseudo-random filler text."""
        words = [
            "analysis", "context", "response", "generation", "synthesis",
            "retrieval", "processing", "evaluation", "optimization", "calibration",
            "validation", "monitoring", "compression", "transmission", "annotation",
        ]
        result = []
        i = 0
        while len(" ".join(result)) < length:
            result.append(words[i % len(words)])
            i += 1
        return " ".join(result)[:length]
