"""Auto-detecting adapter that probes the relay and selects the correct format."""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from typing import Any

import httpx

from api_relay_audit.adapter.base import (
    NormalizedRequest,
    NormalizedResponse,
    RequestAdapter,
)
from api_relay_audit.adapter.anthropic_adapter import AnthropicAdapter
from api_relay_audit.adapter.openai_adapter import OpenAIAdapter

logger = logging.getLogger(__name__)


class AutoAdapter(RequestAdapter):
    """Wraps multiple adapters and auto-detects which one the relay supports."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        adapters: list[RequestAdapter] | None = None,
        timeout: int = 120,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._adapters = adapters or [AnthropicAdapter(), OpenAIAdapter()]
        self._detected_format: str | None = None
        self._detected_adapter: RequestAdapter | None = None
        self._client: httpx.AsyncClient | None = None

    @property
    def format_name(self) -> str:
        return self._detected_format or "auto"

    @property
    def endpoint_path(self) -> str:
        if self._detected_adapter:
            return self._detected_adapter.endpoint_path
        return "/v1/chat/completions"

    def auth_headers(self) -> dict[str, str]:
        if self._detected_adapter:
            return self._detected_adapter.auth_headers()
        return {}

    def build_request_body(self, req: NormalizedRequest) -> dict[str, Any]:
        if self._detected_adapter:
            return self._detected_adapter.build_request_body(req)
        raise RuntimeError("Format not yet detected, call call_async() first")

    def parse_response(self, raw: dict) -> NormalizedResponse:
        if self._detected_adapter:
            return self._detected_adapter.parse_response(raw)
        raise RuntimeError("Format not yet detected")

    def detect_format(self, raw_response: dict) -> bool:
        if self._detected_adapter:
            return self._detected_adapter.detect_format(raw_response)
        for adapter in self._adapters:
            if adapter.detect_format(raw_response):
                return True
        return False

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def _probe(self, req: NormalizedRequest) -> tuple[str, NormalizedResponse]:
        """Try each adapter sequentially and return the first successful one."""
        for adapter in self._adapters:
            start = time.time()
            headers = adapter.auth_headers().copy()
            if adapter.format_name == "anthropic":
                headers["x-api-key"] = self.api_key
            elif adapter.format_name == "openai":
                headers["Authorization"] = f"Bearer {self.api_key}"

            body = adapter.build_request_body(req)
            path = adapter.endpoint_path
            url = f"{self.base_url}{path}"

            try:
                client = await self._get_client()
                resp = await client.post(url, json=body, headers=headers)
                elapsed = time.time() - start

                if resp.status_code == 200:
                    raw = resp.json()
                    # Inject HTTP response headers into raw for header analysis
                    raw["_headers"] = {k.lower(): v for k, v in resp.headers.items()}
                    nr = adapter.parse_response(raw)
                    nr.time_elapsed = elapsed
                    nr.raw = raw  # ensure raw includes headers
                    logger.info(f"Format detected: {adapter.format_name}")
                    self._detected_format = adapter.format_name
                    self._detected_adapter = adapter
                    return adapter.format_name, nr

                if resp.status_code in (400, 422):
                    logger.debug(f"{adapter.format_name} format rejected: {resp.status_code}")
                    continue

                if resp.status_code in (429, 500, 502, 503, 504):
                    logger.warning(f"Retryable error from {adapter.format_name}: {resp.status_code}")
                    continue

            except httpx.TimeoutException:
                logger.debug(f"Timeout on {adapter.format_name} probe")
                continue
            except ssl.SSLError as e:
                logger.warning(f"SSL error on {adapter.format_name}: {e}")
                continue
            except Exception as e:
                logger.debug(f"{adapter.format_name} probe failed: {e}")
                continue

        raise RuntimeError("All format probes failed. Check endpoint URL and API key.")

    async def call_async(self, req: NormalizedRequest) -> NormalizedResponse:
        """Send a request, auto-detecting format on first call."""
        if self._detected_adapter:
            start = time.time()
            headers = self._detected_adapter.auth_headers().copy()
            if self._detected_format == "anthropic":
                headers["x-api-key"] = self.api_key
            elif self._detected_format == "openai":
                headers["Authorization"] = f"Bearer {self.api_key}"

            body = self._detected_adapter.build_request_body(req)
            url = f"{self.base_url}{self._detected_adapter.endpoint_path}"

            client = await self._get_client()
            resp = await client.post(url, json=body, headers=headers)
            elapsed = time.time() - start

            if resp.status_code == 200:
                raw = resp.json()
                # Inject HTTP response headers into raw for header analysis
                raw["_headers"] = {k.lower(): v for k, v in resp.headers.items()}
                nr = self._detected_adapter.parse_response(raw)
                nr.time_elapsed = elapsed
                nr.raw = raw  # ensure raw includes headers
                return nr
            return NormalizedResponse(
                text="",
                input_tokens=0,
                output_tokens=0,
                raw={"_headers": {k.lower(): v for k, v in resp.headers.items()}},
                time_elapsed=elapsed,
                error=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )

        return (await self._probe(req))[1]

    def call(self, req: NormalizedRequest) -> NormalizedResponse:
        """Synchronous wrapper — runs the async call in an event loop."""
        try:
            loop = asyncio.get_running_loop()
            return loop.run_until_complete(self.call_async(req))
        except RuntimeError:
            return asyncio.run(self.call_async(req))

    def set_api_key(self, api_key: str) -> None:
        """Update the API key (useful when token is overridden via CLI)."""
        self.api_key = api_key

    def close_sync(self) -> None:
        """Synchronous close — cancels the event loop if needed."""
        try:
            loop = asyncio.get_running_loop()
            loop.run_until_complete(self.close())
        except RuntimeError:
            asyncio.run(self.close())

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
