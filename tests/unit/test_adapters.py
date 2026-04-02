"""Unit tests for API format adapters."""

import pytest

from api_relay_audit.adapter.base import NormalizedRequest, NormalizedResponse
from api_relay_audit.adapter.anthropic_adapter import AnthropicAdapter
from api_relay_audit.adapter.openai_adapter import OpenAIAdapter
from api_relay_audit.adapter.auto_adapter import AutoAdapter


class TestAnthropicAdapter:
    def test_format_name(self):
        a = AnthropicAdapter()
        assert a.format_name == "anthropic"

    def test_endpoint_path(self):
        a = AnthropicAdapter()
        assert a.endpoint_path == "/v1/messages"

    def test_auth_headers(self):
        a = AnthropicAdapter()
        headers = a.auth_headers()
        assert "x-api-key" in headers
        assert headers["anthropic-version"] == "2023-06-01"

    def test_build_request_body(self):
        a = AnthropicAdapter()
        req = NormalizedRequest(
            messages=[{"role": "user", "content": "Hello"}],
            system="You are a helpful assistant.",
            model="claude-opus-4-6",
            max_tokens=100,
        )
        body = a.build_request_body(req)
        assert body["model"] == "claude-opus-4-6"
        assert body["max_tokens"] == 100
        assert body["system"] == "You are a helpful assistant."
        assert len(body["messages"]) == 1
        assert body["messages"][0]["content"] == "Hello"

    def test_build_request_body_no_system(self):
        a = AnthropicAdapter()
        req = NormalizedRequest(
            messages=[{"role": "user", "content": "Hi"}],
            system=None,
            model="claude-3",
            max_tokens=50,
        )
        body = a.build_request_body(req)
        assert "system" not in body

    def test_parse_response(self):
        a = AnthropicAdapter()
        raw = {
            "type": "message",
            "content": [{"type": "text", "text": "Hello, world!"}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        resp = a.parse_response(raw)
        assert resp.text == "Hello, world!"
        assert resp.input_tokens == 10
        assert resp.output_tokens == 5

    def test_detect_format_anthropic(self):
        a = AnthropicAdapter()
        assert a.detect_format({"type": "message", "content": []})
        assert a.detect_format({"id": "msg_abc123", "content": []})


class TestOpenAIAdapter:
    def test_format_name(self):
        a = OpenAIAdapter()
        assert a.format_name == "openai"

    def test_endpoint_path(self):
        a = OpenAIAdapter()
        assert a.endpoint_path == "/v1/chat/completions"

    def test_build_request_body(self):
        a = OpenAIAdapter()
        req = NormalizedRequest(
            messages=[{"role": "user", "content": "Hello"}],
            system="You are a helpful assistant.",
            model="gpt-4",
            max_tokens=100,
        )
        body = a.build_request_body(req)
        assert body["model"] == "gpt-4"
        assert body["max_tokens"] == 100
        # System prompt should be prepended
        assert body["messages"][0]["role"] == "system"
        assert body["messages"][0]["content"] == "You are a helpful assistant."
        assert body["messages"][1]["role"] == "user"

    def test_parse_response(self):
        a = OpenAIAdapter()
        raw = {
            "choices": [
                {"message": {"role": "assistant", "content": "Hello!"}}
            ],
            "usage": {"prompt_tokens": 8, "completion_tokens": 3},
        }
        resp = a.parse_response(raw)
        assert resp.text == "Hello!"
        assert resp.input_tokens == 8
        assert resp.output_tokens == 3

    def test_detect_format_openai(self):
        a = OpenAIAdapter()
        assert a.detect_format({"choices": [{"message": {}}]})
        assert a.detect_format({"choices": [{"finish_reason": "stop"}]})
        assert not a.detect_format({"type": "message", "content": []})
