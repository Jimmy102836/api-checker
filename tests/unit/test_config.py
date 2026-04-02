"""Unit tests for configuration loading."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from api_relay_audit.config.loader import load_config, _expand_env_vars


class TestEnvVarExpansion:
    def test_expand_single_var(self):
        os.environ["TEST_API_KEY"] = "secret123"
        result = _expand_env_vars({"token": "${TEST_API_KEY}"})
        assert result["token"] == "secret123"
        del os.environ["TEST_API_KEY"]

    def test_expand_multiple_vars(self):
        os.environ["VAR1"] = "val1"
        os.environ["VAR2"] = "val2"
        result = _expand_env_vars({"a": "${VAR1}", "b": "${VAR2}"})
        assert result["a"] == "val1"
        assert result["b"] == "val2"
        del os.environ["VAR1"]
        del os.environ["VAR2"]

    def test_expand_missing_var(self):
        result = _expand_env_vars({"token": "${NONEXISTENT_VAR}"})
        assert result["token"] == ""

    def test_expand_nested(self):
        result = _expand_env_vars({"nested": [{"key": "${MISSING}"}]})
        assert result["nested"][0]["key"] == ""


class TestLoadConfig:
    def test_load_minimal_config(self):
        config_yaml = """
version: "1.0"
endpoints:
  - url: "https://example.com/v1"
    token: "test-token"
test_cases:
  model: "claude-opus-4-6"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_yaml)
            f.flush()
            path = f.name

        try:
            cfg = load_config(path)
            assert cfg.version == "1.0"
            assert len(cfg.endpoints) == 1
            assert cfg.endpoints[0].url == "https://example.com/v1"
            assert cfg.endpoints[0].token == "test-token"
            assert cfg.test_cases.model == "claude-opus-4-6"
            assert cfg.settings.timeout == 120  # default
        finally:
            Path(path).unlink()

    def test_load_with_env_var(self):
        os.environ["MY_SECRET_TOKEN"] = "env-secret-token"
        config_yaml = """
version: "1.0"
endpoints:
  - url: "https://example.com/v1"
    token: "${MY_SECRET_TOKEN}"
test_cases:
  model: "test-model"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(config_yaml)
            f.flush()
            path = f.name

        try:
            cfg = load_config(path)
            assert cfg.endpoints[0].token == "env-secret-token"
        finally:
            Path(path).unlink()
            del os.environ["MY_SECRET_TOKEN"]

    def test_load_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.yaml")
