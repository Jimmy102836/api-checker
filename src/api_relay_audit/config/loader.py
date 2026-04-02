"""YAML configuration file loader with environment variable expansion."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import yaml

from api_relay_audit.config.schema import AppConfig

logger = logging.getLogger(__name__)

ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _expand_env_vars(value: str | dict | list | None) -> str | dict | list | None:
    """Recursively expand ${ENV_VAR} references in config values."""
    if value is None:
        return None

    if isinstance(value, str):
        matches = ENV_VAR_PATTERN.findall(value)
        for var_name in matches:
            env_val = os.environ.get(var_name, "")
            value = value.replace(f"${{{var_name}}}", env_val)
        return value

    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]

    return value


def load_config(path: str | Path) -> AppConfig:
    """Load and validate a config.yaml file.

    Args:
        path: Path to the config.yaml file.

    Returns:
        Validated AppConfig instance.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        ValidationError: If config fails pydantic validation.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    logger.info(f"Loading config from {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    # Expand environment variables
    expanded = _expand_env_vars(raw)

    # Validate with pydantic
    config = AppConfig(**expanded)
    logger.info(f"Config loaded: {len(config.endpoints)} endpoint(s)")

    return config


def load_config_or_default(path: str | Path | None) -> AppConfig:
    """Load config from path, or return a minimal default config."""
    if path and Path(path).exists():
        return load_config(path)

    logger.warning("No config file found, using default configuration")
    return AppConfig()
