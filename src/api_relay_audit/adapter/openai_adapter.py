"""OpenAI /chat/completions format adapter."""

from typing import Any

from api_relay_audit.adapter.base import (
    NormalizedRequest,
    NormalizedResponse,
    RequestAdapter,
)


class OpenAIAdapter(RequestAdapter):
    """Adapter for OpenAI's /v1/chat/completions API format."""

    @property
    def format_name(self) -> str:
        return "openai"

    @property
    def endpoint_path(self) -> str:
        return "/v1/chat/completions"

    def auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer ",  # Will be filled by AutoAdapter
            "content-type": "application/json",
        }

    def build_request_body(self, req: NormalizedRequest) -> dict[str, Any]:
        # Build messages list, combining system if provided
        messages = []
        if req.system:
            messages.append({"role": "system", "content": req.system})
        messages.extend(req.messages)

        return {
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": messages,
        }

    def parse_response(self, raw: dict) -> NormalizedResponse:
        usage = raw.get("usage", {})
        choices = raw.get("choices", [])
        text = ""
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message", {})
            text = message.get("content", "")

        return NormalizedResponse(
            text=text or "",
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            raw=raw,
            time_elapsed=0.0,  # Set by caller
        )

    def detect_format(self, raw_response: dict) -> bool:
        # OpenAI responses have "choices" as a list with "message" objects
        choices = raw_response.get("choices", [])
        if isinstance(choices, list) and len(choices) > 0:
            first = choices[0]
            if isinstance(first, dict):
                return "message" in first or "finish_reason" in first
        return False
