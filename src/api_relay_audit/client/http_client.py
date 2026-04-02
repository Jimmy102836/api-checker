"""HTTP transport layer with retry logic and curl fallback."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from api_relay_audit.config.schema import AdvancedConfig, EndpointConfig, GlobalSettings

logger = logging.getLogger(__name__)

RETRY_CODES = {429, 500, 502, 503, 504}


class HTTPClient:
    """Low-level HTTP transport with retry logic and curl fallback."""

    def __init__(
        self,
        endpoint: EndpointConfig,
        settings: GlobalSettings,
        advanced: AdvancedConfig,
    ):
        self.endpoint = endpoint
        self.settings = settings
        self.advanced = advanced
        self._client: httpx.AsyncClient | None = None
        self.use_curl = False

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            timeout = httpx.Timeout(
                timeout=self.endpoint.timeout,
                connect=30.0,
            )
            self._client = httpx.AsyncClient(
                timeout=timeout,
                verify=self.advanced.verify_ssl,
                proxy=self.advanced.proxy or None,
            )
        return self._client

    async def post(self, path: str, body: dict, headers: dict) -> dict:
        """POST JSON to the endpoint URL+path with retry logic.

        Returns a dict with 'body' (the parsed JSON response) and 'headers'
        (lowercase response headers) for header-level analysis.
        """
        url = f"{self.endpoint.url.rstrip('/')}{path}"
        max_retries = self.settings.max_retries

        for attempt in range(max_retries + 1):
            try:
                client = await self._get_client()
                resp = await client.post(url, json=body, headers=headers)

                if resp.status_code == 200:
                    return {
                        "body": resp.json(),
                        "headers": {k.lower(): v for k, v in resp.headers.items()},
                    }

                if resp.status_code in RETRY_CODES and attempt < max_retries:
                    delay = self.settings.retry_delay * (2**attempt)
                    logger.warning(
                        f"Retryable HTTP {resp.status_code} on {url}, "
                        f"retrying in {delay}s (attempt {attempt + 1}/{max_retries + 1})"
                    )
                    await asyncio.sleep(delay)
                    continue

                # Non-retryable error
                raise HTTPError(
                    f"HTTP {resp.status_code}: {resp.text[:500]}",
                    status_code=resp.status_code,
                    response=resp.text,
                )

            except httpx.TimeoutException as e:
                if attempt < max_retries:
                    delay = self.settings.retry_delay * (2**attempt)
                    logger.warning(
                        f"Timeout on {url}, retrying in {delay}s "
                        f"(attempt {attempt + 1}/{max_retries + 1})"
                    )
                    await asyncio.sleep(delay)
                    continue
                raise HTTPError(f"Request timeout after {max_retries + 1} attempts") from e

            except httpx.SSLError as e:
                if not self.advanced.use_curl_fallback:
                    raise HTTPError(f"SSL error (curl fallback disabled): {e}") from e

                logger.warning(f"SSL error, falling back to curl: {e}")
                self.use_curl = True
                return self._curl_post(url, body, headers)

            except Exception as e:
                if attempt < max_retries:
                    delay = self.settings.retry_delay * (2**attempt)
                    logger.warning(
                        f"Error on {url}: {e}, retrying in {delay}s "
                        f"(attempt {attempt + 1}/{max_retries + 1})"
                    )
                    await asyncio.sleep(delay)
                    continue
                raise HTTPError(f"Request failed after {max_retries + 1} attempts: {e}") from e

        raise HTTPError("Max retries exceeded")

    def post_sync(self, path: str, body: dict, headers: dict) -> dict:
        """Synchronous POST fallback."""
        import asyncio

        return asyncio.run(self.post(path, body, headers))

    def _curl_post(self, url: str, body: dict, headers: dict) -> dict:
        """Fallback to curl subprocess for SSL issues."""
        import json
        import subprocess

        curl_path = self.advanced.curl_path or "curl"
        cmd = [curl_path, "-s", "-D", "-", "-X", "POST", url]

        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]

        cmd += [
            "-H",
            f"Content-Type: application/json",
            "-d",
            json.dumps(body),
        ]

        if not self.advanced.verify_ssl:
            cmd.append("-k")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.endpoint.timeout,
            )
            if result.returncode != 0:
                raise HTTPError(f"curl failed: {result.stderr}")

            # Parse headers from stdout (curl -D prints headers to stdout)
            stdout = result.stdout
            header_end = stdout.find("\r\n\r\n")
            if header_end == -1:
                header_end = stdout.find("\n\n")
            if header_end != -1:
                header_lines = stdout[:header_end].strip().split("\n")
                curl_headers = {}
                for line in header_lines:
                    if ":" in line:
                        key, val = line.split(":", 1)
                        curl_headers[key.strip().lower()] = val.strip()
                body = json.loads(stdout[header_end + (4 if "\r\n" in stdout[:header_end] else 2):])
                return {"body": body, "headers": curl_headers}
            else:
                return {"body": json.loads(stdout), "headers": {}}
        except subprocess.TimeoutExpired:
            raise HTTPError("curl request timeout")
        except json.JSONDecodeError as e:
            raise HTTPError(f"Invalid JSON from curl: {result.stdout[:200]}") from e

    async def get(self, path: str, headers: dict) -> dict:
        """GET JSON from the endpoint URL+path.

        Returns a dict with 'body' and 'headers' keys.
        """
        url = f"{self.endpoint.url.rstrip('/')}{path}"
        client = await self._get_client()
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            return {
                "body": resp.json(),
                "headers": {k.lower(): v for k, v in resp.headers.items()},
            }
        raise HTTPError(f"GET {url} returned {resp.status_code}: {resp.text[:200]}")

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


import asyncio


class HTTPError(Exception):
    """HTTP-related error with status code and response body."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response: str | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response = response
