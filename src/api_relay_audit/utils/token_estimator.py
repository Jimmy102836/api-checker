"""Rough token count estimation utilities."""


class TokenEstimator:
    """Rough token estimator for text strings.

    Uses a simple heuristic: ~4 characters per token on average for English text.
    This is accurate enough for comparative delta detection.
    """

    def estimate(self, text: str) -> int:
        """Estimate token count for a text string."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def estimate_messages(self, messages: list[dict]) -> int:
        """Estimate total token count for a list of messages."""
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            role = msg.get("role", "")
            # Per-message overhead: ~4 tokens for role/content markers
            total += self.estimate(content) + 4
        return total
