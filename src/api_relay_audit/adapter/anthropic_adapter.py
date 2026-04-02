"""Anthropic /messages format adapter."""

from typing import Any

from api_relay_audit.adapter.base import (
    NormalizedRequest,
    NormalizedResponse,
    RequestAdapter,
)


class AnthropicAdapter(RequestAdapter):
    """Adapter for Anthropic's /v1/messages API format."""

    @property
    def format_name(self) -> str:
        return "anthropic"

    @property
    def endpoint_path(self) -> str:
        return "/v1/messages"

    def auth_headers(self) -> dict[str, str]:
        return {
            "x-api-key": "",  # Will be filled by AutoAdapter
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def build_request_body(self, req: NormalizedRequest) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": list(req.messages),
        }
        if req.system:
            body["system"] = req.system
        return body

    def parse_response(self, raw: dict) -> NormalizedResponse:
        usage = raw.get("usage", {})
        # Extract text from content blocks
        text = ""
        content = raw.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    break
                elif isinstance(block, str):
                    text = block
                    break

        return NormalizedResponse(
            text=text,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            raw=raw,
            time_elapsed=0.0,  # Set by caller
        )

    def detect_format(self, raw_response: dict) -> bool:
        # Anthropic responses have "type": "message" or "id" starting with "msg_"
        return (
            raw_response.get("type") == "message"
            or (raw_response.get("id") or "").startswith("msg_")
            or "content" in raw_response
            and isinstance(raw_response.get("content"), list)
        )
