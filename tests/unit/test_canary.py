"""Unit tests for canary generator utility."""

import pytest

from api_relay_audit.utils.canary import CanaryGenerator


class TestCanaryGenerator:
    def test_generate_markers(self):
        gen = CanaryGenerator()
        markers = gen.generate_markers(5)
        assert len(markers) == 5
        assert all(markers[i] != markers[j] for i in range(5) for j in range(i + 1, 5))

    def test_validate_markers_valid(self):
        gen = CanaryGenerator()
        markers = gen.generate_markers(3)
        assert gen.validate_markers(markers) is True

    def test_validate_markers_empty(self):
        gen = CanaryGenerator()
        assert gen.validate_markers([]) is False

    def test_validate_markers_duplicate(self):
        gen = CanaryGenerator()
        assert gen.validate_markers(["CANARY_0_abc123", "CANARY_0_abc123"]) is False

    def test_build_filler_text(self):
        gen = CanaryGenerator()
        markers = gen.generate_markers(3)
        text = gen.build_filler_text(500, markers)
        assert len(text) <= 500
        for marker in markers:
            assert marker in text

    def test_build_filler_text_empty_markers(self):
        gen = CanaryGenerator()
        text = gen.build_filler_text(100, [])
        assert text == ""

    def test_extract_markers_found(self):
        gen = CanaryGenerator()
        markers = gen.generate_markers(2)
        response = f"Here are the markers: {markers[0]} and {markers[1]}"
        found = gen.extract_markers_from_response(response, markers)
        assert len(found) == 2

    def test_extract_markers_partial(self):
        gen = CanaryGenerator()
        markers = gen.generate_markers(2)
        # Full marker in response should always be found
        response = f"Here are the markers: {markers[0]}"
        found = gen.extract_markers_from_response(response, markers)
        assert len(found) >= 1


class TestTokenEstimator:
    def test_estimate_basic(self):
        from api_relay_audit.utils.token_estimator import TokenEstimator
        est = TokenEstimator()
        assert est.estimate("hello world") == 2  # 11 chars / 4 = 2
        assert est.estimate("") == 0

    def test_estimate_messages(self):
        from api_relay_audit.utils.token_estimator import TokenEstimator
        est = TokenEstimator()
        messages = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ]
        count = est.estimate_messages(messages)
        assert count > 0
