"""Curl subprocess fallback for SSL errors."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class CurlFallback:
    """Fallback HTTP client using curl subprocess."""

    def __init__(self, curl_path: str = "curl", verify_ssl: bool = True, timeout: int = 120):
        self.curl_path = curl_path
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def post(self, url: str, body: dict, headers: dict) -> dict:
        """Execute a POST request via curl and return JSON."""
        cmd = [self.curl_path, "-s", "-X", "POST", url]

        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]

        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]

        if not self.verify_ssl:
            cmd.append("-k")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode != 0:
                logger.error(f"curl failed: {result.stderr}")
                raise CurlError(f"curl exited with {result.returncode}: {result.stderr}")

            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise CurlError(f"curl returned non-JSON: {result.stdout[:200]}") from e

        except subprocess.TimeoutExpired:
            raise CurlError(f"curl request timeout after {self.timeout}s")

    def get(self, url: str, headers: dict) -> dict:
        """Execute a GET request via curl and return JSON."""
        cmd = [self.curl_path, "-s", "-X", "GET", url]

        for key, value in headers.items():
            cmd += ["-H", f"{key}: {value}"]

        if not self.verify_ssl:
            cmd.append("-k")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode != 0:
                raise CurlError(f"curl exited with {result.returncode}: {result.stderr}")

            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError as e:
                raise CurlError(f"curl returned non-JSON: {result.stdout[:200]}") from e

        except subprocess.TimeoutExpired:
            raise CurlError(f"curl request timeout after {self.timeout}s")


class CurlError(Exception):
    """Error from curl subprocess."""
