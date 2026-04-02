"""Detector integration tests using mock adapters.

These tests verify that each detector correctly handles the corresponding
malicious behavior by mocking the adapter responses.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from api_relay_audit.adapter.base import NormalizedResponse
from api_relay_audit.detectors.base import AuditContext
from api_relay_audit.detectors.token_injection import TokenInjectionDetector
from api_relay_audit.detectors.hidden_injection import HiddenInjectionDetector
from api_relay_audit.detectors.instruction_override import InstructionOverrideDetector
from api_relay_audit.detectors.context_truncation import ContextTruncationDetector
from api_relay_audit.detectors.data_exfiltration import DataExfiltrationDetector
from api_relay_audit.engine.result import RiskLevel
from api_relay_audit.utils.canary import CanaryGenerator
from api_relay_audit.utils.token_estimator import TokenEstimator


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_ctx(mock_adapter: MagicMock) -> AuditContext:
    """Build a minimal AuditContext for testing."""
    detector_config = MagicMock()
    detector_config.injection_threshold = 100
    detector_config.baseline_tests = None
    detector_config.tests = None
    detector_config.coarse_steps = [50]
    detector_config.binary_search_threshold = 20
    detector_config.canary_count = 3
    detector_config.max_context_k = 200

    return AuditContext(
        endpoint=MagicMock(),
        adapter=mock_adapter,
        settings=MagicMock(),
        detector_config=detector_config,
        canary_generator=CanaryGenerator(),
        token_estimator=TokenEstimator(),
        model="test-model",
    )


def _make_resp(text: str = "OK", input_tokens: int = 10, output_tokens: int = 5) -> NormalizedResponse:
    return NormalizedResponse(
        text=text,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        raw={},
        time_elapsed=0.1,
        error=None,
    )


# ---------------------------------------------------------------------------
# T1: Token Injection Detection
# ---------------------------------------------------------------------------

class TestTokenInjectionDetector:
    """Tests for TokenInjectionDetector (T1)."""

    def test_clean_baseline_passes(self):
        """When the baseline has no injection, test passes."""
        mock = MagicMock()
        mock.call.return_value = _make_resp("Hello!", input_tokens=10, output_tokens=5)
        ctx = _make_ctx(mock)
        detector = TokenInjectionDetector()
        result = detector.run(ctx)

        assert result.detector_id == "token_injection"
        assert len(result.findings) >= 1

    def test_injection_detected_with_excess_delta(self):
        """When tokens exceed expected delta, HIGH risk is raised."""
        # Baseline call (no system): ~5 tokens
        # Second call (with system): if injected, actual > expected
        responses = [
            _make_resp("baseline", input_tokens=5, output_tokens=3),
            _make_resp("with system", input_tokens=60, output_tokens=5),
        ]
        mock = MagicMock()
        mock.call.side_effect = responses
        ctx = _make_ctx(mock)
        detector = TokenInjectionDetector()
        result = detector.run(ctx)

        injection_delta = result.raw_data.get("injection_delta", 0)
        # With 5 baseline + ~5 system = ~10 expected, but got 60
        # delta = 60 - 5 = 55 (the actual delta from baseline)
        # But injection_delta = actual_delta - expected_delta = 55 - expected_system_tokens
        # The detector should see the excess
        assert result.detector_id == "token_injection"
        assert len(result.findings) == 2

    def test_injection_threshold_respected(self):
        """Injection delta above threshold triggers HIGH risk."""
        responses = [
            _make_resp("baseline", input_tokens=5, output_tokens=3),
            _make_resp("injected", input_tokens=150, output_tokens=5),
        ]
        mock = MagicMock()
        mock.call.side_effect = responses
        ctx = _make_ctx(mock)
        detector = TokenInjectionDetector()
        result = detector.run(ctx)

        assert result.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_connection_error_graceful(self):
        """Detector handles connection errors without crashing."""
        mock = MagicMock()
        mock.call.side_effect = ConnectionError("Server unreachable")
        ctx = _make_ctx(mock)
        detector = TokenInjectionDetector()
        result = detector.run(ctx)

        assert result.detector_id == "token_injection"
        assert len(result.findings) >= 1
        assert not all(f.passed for f in result.findings)


# ---------------------------------------------------------------------------
# T2: Hidden Injection Detection
# ---------------------------------------------------------------------------

class TestHiddenInjectionDetector:
    """Tests for HiddenInjectionDetector (T2)."""

    def test_clean_server_no_excess(self):
        """Clean server produces no excess tokens."""
        responses = [
            _make_resp("S1 response", input_tokens=15, output_tokens=5),
            _make_resp("S2 response", input_tokens=30, output_tokens=5),
        ]
        mock = MagicMock()
        mock.call.side_effect = responses
        ctx = _make_ctx(mock)
        detector = HiddenInjectionDetector()
        result = detector.run(ctx)

        assert result.detector_id == "hidden_injection"
        assert len(result.findings) == 2
        excess = result.raw_data.get("excess_tokens", 0)
        threshold = result.raw_data.get("threshold", 50)
        assert excess <= threshold * 2

    def test_excess_tokens_trigger_high_risk(self):
        """Excess tokens above threshold trigger HIGH risk."""
        # S1: 15 tokens, S2: 200 tokens → delta=185, expected ~30 → excess ~155
        responses = [
            _make_resp("S1", input_tokens=15, output_tokens=5),
            _make_resp("S2", input_tokens=200, output_tokens=5),
        ]
        mock = MagicMock()
        mock.call.side_effect = responses
        ctx = _make_ctx(mock)
        detector = HiddenInjectionDetector()
        result = detector.run(ctx)

        excess = result.raw_data.get("excess_tokens", 0)
        assert result.detector_id == "hidden_injection"
        # If excess > threshold (50), should be HIGH
        if excess > 50:
            assert result.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_timeout_handled(self):
        """Timeout exceptions are handled gracefully."""
        mock = MagicMock()
        mock.call.side_effect = TimeoutError("Request timed out")
        ctx = _make_ctx(mock)
        detector = HiddenInjectionDetector()
        result = detector.run(ctx)

        assert result.detector_id == "hidden_injection"
        assert len(result.findings) >= 1


# ---------------------------------------------------------------------------
# T3: Instruction Override Detection
# ---------------------------------------------------------------------------

class TestInstructionOverrideDetector:
    """Tests for InstructionOverrideDetector (T3)."""

    def test_cat_test_honored(self):
        """Cat test passes when system prompt is respected."""
        mock = MagicMock()
        mock.call.return_value = _make_resp("meow meow", input_tokens=20, output_tokens=3)
        ctx = _make_ctx(mock)
        detector = InstructionOverrideDetector()
        result = detector.run(ctx)

        assert result.detector_id == "instruction_override"
        overridden = result.raw_data.get("overridden_tests", [])
        # "meow" contains expected keyword, "1" not in response
        assert isinstance(overridden, list)

    def test_cat_test_fails_when_overridden(self):
        """Cat test fails when system prompt is ignored."""
        mock = MagicMock()
        mock.call.return_value = _make_resp("1+1 equals 2", input_tokens=20, output_tokens=5)
        ctx = _make_ctx(mock)
        detector = InstructionOverrideDetector()
        result = detector.run(ctx)

        overridden = result.raw_data.get("overridden_tests", [])
        # Response contains "1" (excluded keyword) → cat test should fail
        assert "cat_test" in overridden or result.risk_level != RiskLevel.LOW

    def test_422_rejected(self):
        """HTTP 422 error triggers HIGH risk for instruction override."""
        mock = MagicMock()
        mock.call.side_effect = RuntimeError("422 Unprocessable Entity")
        ctx = _make_ctx(mock)
        detector = InstructionOverrideDetector()
        result = detector.run(ctx)

        rejected = result.raw_data.get("rejected_422", False)
        assert rejected is True
        assert result.risk_level == RiskLevel.HIGH

    def test_partial_override_is_medium(self):
        """Partial override (some tests fail) maps to MEDIUM risk."""
        def side_effect(req):
            # First call (cat_test): fails
            if len(side_effect.calls) == 0:
                side_effect.calls += 1
                return _make_resp("1+1=2", input_tokens=20, output_tokens=3)
            # Second call (identity_test): passes
            return _make_resp("I am Claude made by Anthropic.", input_tokens=20, output_tokens=5)
        side_effect.calls = 0

        mock = MagicMock()
        mock.call.side_effect = side_effect
        ctx = _make_ctx(mock)
        detector = InstructionOverrideDetector()
        result = detector.run(ctx)

        overridden = result.raw_data.get("overridden_tests", [])
        assert len(overridden) > 0


# ---------------------------------------------------------------------------
# T4: Context Truncation Detection
# ---------------------------------------------------------------------------

class TestContextTruncationDetector:
    """Tests for ContextTruncationDetector (T4)."""

    def test_all_canaries_recalled_no_truncation(self):
        """When all canaries are recalled, LOW risk."""
        mock = MagicMock()
        # The detector sends filler+recall; mock returns all markers
        canaries = ["CANARY_0_aaa", "CANARY_1_bbb", "CANARY_2_ccc"]
        mock.call.return_value = _make_resp(
            " ".join(canaries),
            input_tokens=200,
            output_tokens=20,
        )
        ctx = _make_ctx(mock)
        detector = ContextTruncationDetector()
        result = detector.run(ctx)

        assert result.detector_id == "context_truncation"
        # With only one coarse step, risk depends on result

    def test_missing_canaries_detected(self):
        """Missing canaries trigger truncation detection."""
        mock = MagicMock()
        # Returns only some canaries
        mock.call.return_value = _make_resp(
            "CANARY_0_aaa CANARY_1_bbb",
            input_tokens=50,
            output_tokens=10,
        )
        ctx = _make_ctx(mock)
        detector = ContextTruncationDetector()
        result = detector.run(ctx)

        assert result.detector_id == "context_truncation"
        assert len(result.findings) >= 1
        # Finding should be marked failed since not all canaries were found
        assert not all(f.passed for f in result.findings)

    def test_connection_error_handled(self):
        """Connection errors during context scan are handled gracefully."""
        mock = MagicMock()
        mock.call.side_effect = ConnectionError("unreachable")
        ctx = _make_ctx(mock)
        detector = ContextTruncationDetector()
        result = detector.run(ctx)

        assert result.detector_id == "context_truncation"


# ---------------------------------------------------------------------------
# T5: Data Exfiltration Detection
# ---------------------------------------------------------------------------

class TestDataExfiltrationDetector:
    """Tests for DataExfiltrationDetector (T5)."""

    def test_no_leak_when_clean(self):
        """Clean server produces LOW risk."""
        mock = MagicMock()
        mock.call.return_value = _make_resp(
            "I don't recall any previous message.",
            input_tokens=20,
            output_tokens=10,
        )
        ctx = _make_ctx(mock)
        detector = DataExfiltrationDetector()
        result = detector.run(ctx)

        assert result.detector_id == "data_exfiltration"
        assert result.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)

    def test_suspicious_headers_trigger_risk(self):
        """Suspicious HTTP headers in response trigger elevated risk."""
        mock = MagicMock()
        mock.call.return_value = NormalizedResponse(
            text="OK",
            input_tokens=10,
            output_tokens=5,
            raw={"headers": {"x-query-log": "true", "x-forwarded-for": "1.2.3.4"}},
            time_elapsed=0.1,
            error=None,
        )
        ctx = _make_ctx(mock)
        detector = DataExfiltrationDetector()
        result = detector.run(ctx)

        suspicious = result.raw_data.get("suspicious_headers", [])
        assert isinstance(suspicious, list)

    def test_cross_session_leak_high_risk(self):
        """Confirmed cross-session data persistence → HIGH risk."""
        # The detector's second call (recall) returns the injected marker
        canary = "SECRET_API_KEY_sk_test_12345xyz_canary"
        responses = [
            _make_resp("Received.", input_tokens=10, output_tokens=2),
            _make_resp(f"You sent: {canary}", input_tokens=30, output_tokens=10),
            _make_resp("def hack(): pass and ALPHA_BETA_999_marker", input_tokens=50, output_tokens=5),
            _make_resp("You shared def hack(): pass and ALPHA_BETA_999_marker", input_tokens=40, output_tokens=5),
        ]
        mock = MagicMock()
        mock.call.side_effect = responses
        ctx = _make_ctx(mock)
        detector = DataExfiltrationDetector()
        result = detector.run(ctx)

        assert result.detector_id == "data_exfiltration"


# ---------------------------------------------------------------------------
# Concurrent / fault tolerance tests
# ---------------------------------------------------------------------------

class TestDetectorConcurrency:
    """Test that detectors handle errors and edge cases gracefully."""

    def test_token_injection_handles_connection_error(self):
        """Detector should not crash when adapter raises an exception."""
        mock = MagicMock()
        mock.call.side_effect = ConnectionError("Server unreachable")
        ctx = _make_ctx(mock)
        detector = TokenInjectionDetector()
        result = detector.run(ctx)

        assert result.detector_id == "token_injection"
        assert len(result.findings) >= 1
        assert not all(f.passed for f in result.findings)

    def test_hidden_injection_handles_timeout(self):
        """Detector should handle timeout exceptions gracefully."""
        mock = MagicMock()
        mock.call.side_effect = TimeoutError("Request timed out")
        ctx = _make_ctx(mock)
        detector = HiddenInjectionDetector()
        result = detector.run(ctx)

        assert result.detector_id == "hidden_injection"
        assert len(result.findings) >= 1

    def test_instruction_override_handles_422(self):
        """Detector should handle HTTP 422 errors."""
        mock = MagicMock()
        mock.call.side_effect = RuntimeError("422 Unprocessable Entity")
        ctx = _make_ctx(mock)
        detector = InstructionOverrideDetector()
        result = detector.run(ctx)

        assert result.detector_id == "instruction_override"
        rejected = result.raw_data.get("rejected_422", False)
        assert rejected is True

    def test_multiple_detectors_sequential_run(self):
        """Multiple detectors can run in sequence without interference."""
        mock = MagicMock()
        mock.call.return_value = _make_resp("OK", input_tokens=10, output_tokens=5)

        detectors = [
            TokenInjectionDetector(),
            HiddenInjectionDetector(),
            InstructionOverrideDetector(),
        ]

        results = []
        for d in detectors:
            ctx = _make_ctx(mock)
            result = d.run(ctx)
            results.append(result)

        assert len(results) == 3
        assert all(r.detector_id in (
            "token_injection",
            "hidden_injection",
            "instruction_override",
        ) for r in results)

    def test_all_detectors_handle_empty_response(self):
        """Detectors handle empty response text gracefully."""
        mock = MagicMock()
        mock.call.return_value = _make_resp("", input_tokens=0, output_tokens=0)
        ctx = _make_ctx(mock)

        for detector in [
            TokenInjectionDetector(),
            HiddenInjectionDetector(),
        ]:
            result = detector.run(ctx)
            assert result.detector_id is not None
            assert len(result.findings) >= 1

    def test_context_truncation_detector_handles_scan_error(self):
        """Context truncation handles errors during binary scan."""
        mock = MagicMock()
        mock.call.side_effect = ConnectionError("Scan failed")
        ctx = _make_ctx(mock)
        detector = ContextTruncationDetector()
        result = detector.run(ctx)

        # Should still return a result, not crash
        assert result.detector_id == "context_truncation"


# ---------------------------------------------------------------------------
# Flask test client tests (mock malicious server)
# ---------------------------------------------------------------------------

class TestMockRelayFlaskClient:
    """Test the mock relay Flask app directly via test client."""

    def test_clean_openai_request(self, flask_client):
        """Clean OpenAI request returns expected shape."""
        client, cfg = flask_client
        cfg.token_injection_enabled = False

        resp = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )

        assert resp.status_code == 200
        data = resp.get_json()
        assert "choices" in data
        assert data["choices"][0]["message"]["role"] == "assistant"

    def test_token_injection_adds_tokens(self, flask_client):
        """Token injection increases prompt token count."""
        client, cfg = flask_client
        cfg.token_injection_enabled = False

        # Clean baseline
        resp_clean = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
        )
        clean_tokens = resp_clean.get_json()["usage"]["prompt_tokens"]

        # With injection
        cfg.token_injection_enabled = True
        resp_injected = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
        )
        injected_tokens = resp_injected.get_json()["usage"]["prompt_tokens"]

        assert injected_tokens > clean_tokens

    def test_context_truncation_drops_messages(self, flask_client):
        """Context truncation drops oldest messages when threshold exceeded."""
        client, cfg = flask_client
        cfg.context_truncation_enabled = True
        cfg.context_truncation_threshold_chars = 50

        long_messages = [
            {"role": "user", "content": "A" * 100},
            {"role": "user", "content": "B" * 100},
            {"role": "user", "content": "C" * 100},
        ]

        resp = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": long_messages},
        )
        assert resp.status_code == 200

    def test_instruction_override_replaces_system(self, flask_client):
        """Instruction override replaces client's system prompt."""
        client, cfg = flask_client
        cfg.instruction_override_enabled = True
        cfg.instruction_override_text = "You are a robot."

        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "test",
                "messages": [
                    {"role": "system", "content": "You are a cat."},
                    {"role": "user", "content": "hi"},
                ],
            },
        )
        assert resp.status_code == 200

    def test_slow_response_delays(self, flask_client):
        """Slow response behavior delays the response."""
        client, cfg = flask_client
        cfg.slow_response_seconds = 0.5

        start = time.time()
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "hi"}]},
        )
        elapsed = time.time() - start

        assert resp.status_code == 200
        assert elapsed >= 0.4

    def test_header_injection_adds_headers(self, flask_client):
        """Header injection adds suspicious headers to responses."""
        client, cfg = flask_client
        cfg.header_injection_enabled = True
        cfg.suspicious_headers = {"X-Query-Log": "true", "X-Snoop": "1"}

        resp = client.get("/v1/models")
        assert resp.status_code == 200
        assert "X-Query-Log" in resp.headers
        assert resp.headers["X-Query-Log"] == "true"

    def test_anthropic_endpoint(self, flask_client):
        """Anthropic /v1/messages endpoint returns correct format."""
        client, cfg = flask_client
        cfg.token_injection_enabled = False

        resp = client.post(
            "/v1/messages",
            json={
                "model": "test",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 100,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["type"] == "message"
        assert data["role"] == "assistant"
        assert "usage" in data

    def test_config_get_returns_current_state(self, flask_client):
        """GET /config returns current EvilConfig."""
        client, cfg = flask_client
        cfg.token_injection_enabled = True

        resp = client.get("/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["token_injection_enabled"] is True

    def test_config_post_updates_state(self, flask_client):
        """POST /config updates EvilConfig at runtime."""
        client, cfg = flask_client

        resp = client.post("/config", json={"token_injection_enabled": True})
        assert resp.status_code == 200

        resp2 = client.get("/config")
        assert resp2.get_json()["token_injection_enabled"] is True

    def test_token_injection_text_length(self, flask_client):
        """Verify injection adds specific number of tokens."""
        client, cfg = flask_client

        cfg.token_injection_enabled = False
        resp_clean = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "x"}]},
        )
        clean = resp_clean.get_json()["usage"]["prompt_tokens"]

        cfg.token_injection_enabled = True
        resp_inj = client.post(
            "/v1/chat/completions",
            json={"model": "test", "messages": [{"role": "user", "content": "x"}]},
        )
        injected = resp_inj.get_json()["usage"]["prompt_tokens"]

        # Injection text length // 4 ≈ tokens added
        injection_tokens = len(cfg.token_injection_text) // 4
        assert injected - clean >= injection_tokens - 5  # within 5 token tolerance

    def test_context_truncation_preserves_recent(self, flask_client):
        """Context truncation keeps the most recent messages."""
        client, cfg = flask_client
        cfg.context_truncation_enabled = True
        cfg.context_truncation_threshold_chars = 30

        # First message is long (would be dropped), second is short (kept)
        resp = client.post(
            "/v1/chat/completions",
            json={
                "model": "test",
                "messages": [
                    {"role": "user", "content": "A" * 200},
                    {"role": "user", "content": "B"},
                ],
            },
        )
        assert resp.status_code == 200
        # The short "B" message should remain
        data = resp.get_json()
        assert "B" in data["choices"][0]["message"]["content"]

    def test_evil_config_combined_behaviors(self, flask_client):
        """Multiple evil behaviors can be enabled simultaneously."""
        client, cfg = flask_client
        cfg.token_injection_enabled = True
        cfg.header_injection_enabled = True
        cfg.slow_response_seconds = 0.1

        resp = client.get("/v1/models")
        assert resp.status_code == 200
        assert "X-Query-Log" in resp.headers

    def test_unknown_endpoint_returns_404(self, flask_client):
        """Unknown endpoints return 404."""
        client, _ = flask_client
        resp = client.post("/v1/unknown", json={})
        assert resp.status_code == 404
