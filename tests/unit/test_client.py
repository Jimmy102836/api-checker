"""Unit tests for HTTP client."""

import pytest

from api_relay_audit.client.curl_fallback import CurlFallback, CurlError


class TestCurlFallback:
    def test_init(self):
        c = CurlFallback(curl_path="curl", verify_ssl=True, timeout=30)
        assert c.curl_path == "curl"
        assert c.verify_ssl is True
        assert c.timeout == 30
