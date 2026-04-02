"""Canary marker generation and validation for context truncation detection."""

import re
import secrets
import string


class CanaryGenerator:
    """Generates and validates canary markers for context truncation tests."""

    # Template for canary markers
    TEMPLATE = "CANARY_{index}_{random}"

    def generate_markers(self, count: int) -> list[str]:
        """Generate N unique canary strings.

        Returns:
            List of unique canary markers like ['CANARY_0_a1b2c3d4e5f6', ...]
        """
        markers = []
        for i in range(count):
            random_part = self._generate_random_hex(8)
            marker = self.TEMPLATE.format(index=i, random=random_part)
            markers.append(marker)
        return markers

    def _generate_random_hex(self, length: int = 8) -> str:
        """Generate a random hexadecimal string."""
        chars = string.hexdigits.lower()
        return "".join(secrets.choice(chars) for _ in range(length))

    def build_filler_text(
        self, total_chars: int, markers: list[str]
    ) -> str:
        """Build filler text with markers evenly distributed.

        Args:
            total_chars: Target total character count
            markers: List of canary marker strings to embed

        Returns:
            A string of total_chars length with markers embedded at equal intervals.
        """
        if not markers:
            return ""

        num_markers = len(markers)
        segment_size = total_chars // (num_markers + 1)

        parts = []
        for i, marker in enumerate(markers):
            # Position each marker at the end of its segment
            offset = (i + 1) * segment_size
            # Fill with lorem-style text before the marker
            filler_before = f"Paragraph segment {i+1}. "
            filler_len = max(0, segment_size - len(marker) - len(filler_before))
            filler = self._generate_filler(filler_len)
            parts.append(filler_before + filler + marker + " ")

        remaining = total_chars - sum(len(p) for p in parts)
        if remaining > 0:
            parts.append(self._generate_filler(remaining))

        return "".join(parts)[:total_chars]

    def _generate_filler(self, length: int) -> str:
        """Generate pseudo-random filler text of approximately the requested length."""
        words = [
            "analysis", "context", "response", "information", "processing",
            "evaluation", "generation", "synthesis", "retrieval", "storage",
            "transmission", "compression", "encryption", "annotation", "embedding",
            "inference", "optimization", "calibration", "validation", "monitoring",
        ]
        result = []
        current_len = 0
        word_idx = 0
        while current_len < length:
            word = words[word_idx % len(words)]
            if current_len + len(word) + 1 > length:
                word = word[: length - current_len]
            result.append(word)
            current_len += len(word) + 1
            word_idx += 1
            if current_len < length:
                result.append(" ")
                current_len += 1
        return "".join(result)

    def extract_markers_from_response(
        self, response: str, markers: list[str]
    ) -> list[str]:
        """Parse the model's response and extract which canary markers it recalled.

        Args:
            response: The model's response text
            markers: The list of all canary markers that were embedded

        Returns:
            List of markers that appear to have been recalled in the response.
        """
        found = []
        response_lower = response.lower()
        for marker in markers:
            marker_lower = marker.lower()
            # Check if the marker (or its key parts) appears in the response
            if marker_lower in response_lower:
                found.append(marker)
            else:
                # Try matching partial segments (index and random part)
                parts = marker.split("_")
                if len(parts) >= 3:
                    index_part = parts[1]
                    random_part = parts[2]
                    if index_part in response and random_part[:6] in response:
                        found.append(marker)
        return found

    def validate_markers(self, markers: list[str]) -> bool:
        """Ensure all markers are well-formed and unique."""
        if not markers:
            return False
        if len(markers) != len(set(markers)):
            return False
        pattern = re.compile(r"^CANARY_\d+_[0-9a-f]+$")
        return all(pattern.match(m) for m in markers)
