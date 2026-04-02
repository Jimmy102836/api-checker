"""Extended: Multi-round Conversation Memory Chain Detection.

Tests whether the relay maintains context across N conversation turns,
specifically checking whether information embedded in the 1st turn
can be correctly referenced in turn N.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from api_relay_audit.adapter.base import NormalizedRequest
from api_relay_audit.detectors.base import AuditContext, DetectorPlugin
from api_relay_audit.engine.result import DetectorResult, RiskLevel, TestCase


@dataclass
class MemoryMarker:
    """An embedded fact retrievable at any point in the conversation."""
    turn: int    # which turn to embed it
    marker: str  # the unique marker text
    keywords: list[str]  # keywords to check for in response


# Default: embed a marker in turn 1, then try to recall it in later turns
DEFAULT_MEMORY_CHAIN = [
    MemoryMarker(
        turn=1,
        marker="SESSION_CODE_ALPHA_7391",
        keywords=["SESSION_CODE_ALPHA_7391", "ALPHA", "7391"],
    ),
    MemoryMarker(
        turn=3,
        marker="MAGIC_WORD_ZEPHYR",
        keywords=["MAGIC_WORD_ZEPHYR", "ZEPHYR"],
    ),
    MemoryMarker(
        turn=5,
        marker="PIN_8822",
        keywords=["PIN_8822", "8822"],
    ),
]


class ConversationMemoryChainDetector(DetectorPlugin):
    """Detects context truncation via multi-turn memory chain testing.

    Algorithm:
    1. Conduct an N-turn conversation
    2. Embed unique markers at specific turns (1, 3, 5)
    3. In later turns, ask about markers from earlier turns
    4. If markers from early turns can't be recalled, context was truncated
    5. This is more robust than single new-session tests because it tests
       actual rolling context retention
    """

    id = "conversation_memory"
    name = "Multi-Round Conversation Memory Chain Detection"
    description = (
        "Detects context truncation by testing whether the relay maintains "
        "information across N conversation turns. Embeds unique markers at "
        "specific turns and tests recall from much later turns."
    )

    def run(self, ctx: AuditContext) -> DetectorResult:
        """Run the conversation memory chain test."""
        findings: list[TestCase] = []
        raw_data: dict = {
            "turns": [],
            "marker_recall": {},
        }

        # Build the multi-turn conversation
        conversation_turns = [
            {"role": "user", "content": "Hello, let's have a detailed conversation."},
            # Turn 2: User asks a question
            {"role": "user", "content": "What is machine learning?"},
            # Turn 3: Another question
            {"role": "user", "content": "Explain neural networks in one sentence."},
            # Turn 4: Another question
            {"role": "user", "content": "What are transformers used for?"},
            # Turn 5: Final question
            {"role": "user", "content": "What is retrieval-augmented generation?"},
        ]

        # Embed markers at specific turns
        markers = DEFAULT_MEMORY_CHAIN
        marker_by_turn = {m.turn: m for m in markers}

        # Build messages with markers injected
        all_messages = []
        for i, turn in enumerate(conversation_turns):
            turn_num = i + 1
            msg = dict(turn)

            # Inject marker at specified turn
            if turn_num in marker_by_turn:
                m = marker_by_turn[turn_num]
                msg["content"] += f" Remember this code: {m.marker}"

            all_messages.append(msg)

        # Phase 1: Send all turns in sequence (rolling context)
        # The adapter should maintain conversation context
        accumulated_messages = []
        responses = []

        for i, msg in enumerate(all_messages):
            turn_num = i + 1
            accumulated_messages.append(msg)

            req = NormalizedRequest(
                messages=list(accumulated_messages),
                system=None,
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
                        name=f"turn_{turn_num}",
                        description=f"Conversation turn {turn_num}",
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=elapsed_ms,
                        response_text="",
                        passed=False,
                        details={"error": str(e)},
                    )
                )
                accumulated_messages.append({"role": "assistant", "content": f"[error: {e}]"})
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            accumulated_messages.append({"role": "assistant", "content": resp.text})
            responses.append(resp)

            raw_data["turns"].append({
                "turn": turn_num,
                "input_tokens": resp.input_tokens,
                "output_tokens": resp.output_tokens,
                "elapsed_ms": elapsed_ms,
            })

        # Phase 2: Ask about markers from early turns in later turns
        recall_tests = [
            # In turn 5, ask about marker from turn 1
            {
                "name": "recall_turn1_in_turn5",
                "target_turn": 5,
                "marker_to_check": 1,
                "question": "What code did I ask you to remember in my very first message?",
            },
            # In turn 5, ask about marker from turn 3
            {
                "name": "recall_turn3_in_turn5",
                "target_turn": 5,
                "marker_to_check": 3,
                "question": "What magic word did I ask you to remember earlier?",
            },
            # In a fresh context, ask about everything (tests if anything was stored)
            {
                "name": "recall_all_markers",
                "target_turn": 6,
                "marker_to_check": None,
                "question": "List ALL the codes, words, and special markers I asked you to remember in this conversation.",
            },
        ]

        for recall in recall_tests:
            # Build context up to the target turn
            if recall["target_turn"] <= len(accumulated_messages):
                recall_messages = list(accumulated_messages[: recall["target_turn"]])
            else:
                recall_messages = list(accumulated_messages)

            recall_messages.append({"role": "user", "content": recall["question"]})

            req = NormalizedRequest(
                messages=recall_messages,
                system=None,
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
                        name=recall["name"],
                        description=f"Recall test: {recall['name']}",
                        input_tokens=0,
                        output_tokens=0,
                        elapsed_ms=elapsed_ms,
                        response_text="",
                        passed=False,
                        details={"error": str(e)},
                    )
                )
                continue

            elapsed_ms = (time.monotonic() - start) * 1000
            response_lower = resp.text.lower()

            # Check if markers were recalled
            marker_recalled = {}
            for marker in markers:
                if recall["marker_to_check"] is not None and marker.turn != recall["marker_to_check"]:
                    continue
                keywords_found = sum(1 for kw in marker.keywords if kw.lower() in response_lower)
                marker_recalled[marker.marker] = keywords_found == len(marker.keywords)

            all_recalled = all(marker_recalled.values()) if marker_recalled else False

            findings.append(
                TestCase(
                    name=recall["name"],
                    description=f"Recall test: {recall['name']}",
                    input_tokens=resp.input_tokens,
                    output_tokens=resp.output_tokens,
                    elapsed_ms=elapsed_ms,
                    response_text=resp.text[:500],
                    passed=all_recalled,
                    details={
                        "target_turn": recall["target_turn"],
                        "marker_to_check": recall["marker_to_check"],
                        "marker_recalled": marker_recalled,
                        "response_length": len(resp.text),
                    },
                )
            )

            raw_data["marker_recall"][recall["name"]] = marker_recalled

        # Risk assessment
        failed_recalls = sum(
            1 for tc in findings if not tc.passed and "recall" in tc.name
        )
        total_recalls = sum(1 for tc in findings if "recall" in tc.name)

        if failed_recalls >= 2:
            risk = RiskLevel.HIGH
            summary = f"Memory chain broken ({failed_recalls}/{total_recalls} recall tests failed)"
        elif failed_recalls == 1:
            risk = RiskLevel.MEDIUM
            summary = f"Partial memory loss ({failed_recalls}/{total_recalls} recall tests failed)"
        elif failed_recalls == 0:
            risk = RiskLevel.LOW
            summary = "Full memory chain intact across all turns"
        else:
            risk = RiskLevel.LOW
            summary = "Memory chain test completed"

        raw_data.update({
            "total_turns": len(conversation_turns),
            "total_markers": len(markers),
            "failed_recalls": failed_recalls,
            "total_recalls": total_recalls,
        })

        return DetectorResult(
            detector_id=self.id,
            risk_level=risk,
            summary=summary,
            findings=findings,
            raw_data=raw_data,
        )
