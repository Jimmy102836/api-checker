#!/usr/bin/env python3
"""Main CLI entry point for API Relay Audit.

Usage:
    python scripts/audit.py --config config.yaml
    python scripts/audit.py -c config.yaml --endpoint "Primary Relay"
    python scripts/audit.py -c config.yaml --detectors token_injection --verbose
    python scripts/audit.py -c config.yaml --format openai --token sk-test-123
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import click

# Ensure src/ is on path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from api_relay_audit.config.loader import load_config, load_config_or_default
from api_relay_audit.engine.auditor import Auditor
from api_relay_audit.reports.json_exporter import JSONExporter
from api_relay_audit.reports.markdown_exporter import MarkdownExporter
from api_relay_audit.utils.formatting import print_audit_summary


def _setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure logging based on verbosity level."""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _generate_output_path(output_dir: Path, name: str, suffix: str, ext: str) -> Path:
    """Generate a timestamped output path."""
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    filename = f"{safe_name}_{timestamp}{suffix}.{ext}"
    return output_dir / filename


def _apply_cli_overrides(config: AppConfig, token: str | None, endpoint: str | None,
                          model: str | None, format: str | None, timeout: int | None,
                          output_dir: str | None) -> AppConfig:
    """Apply CLI parameter overrides to the loaded config."""
    if token:
        # Override token for all endpoints
        for ep in config.endpoints:
            ep.token = token

    if endpoint:
        # Override specific endpoint URL/name
        for ep in config.endpoints:
            if ep.name == endpoint or str(ep.url) == endpoint:
                if token:
                    ep.token = token
                break

    if model:
        config.settings.model = model

    if format and format in ("openai", "anthropic", "auto"):
        config.settings.default_format = format

    if timeout:
        config.settings.timeout = timeout

    if output_dir:
        config.settings.output_dir = output_dir

    return config


@click.group()
@click.version_option(version="1.0.0", prog_name="api-relay-audit")
def cli():
    """API Relay Audit — Security auditing tool for AI API relay/proxy services.

    Detects prompt dumping, hidden injection, instruction override,
    context truncation, and data exfiltration in API relay services.
    """
    pass


@cli.command("audit")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("config.yaml"),
    help="Path to config.yaml file",
)
@click.option(
    "--endpoint", "-e",
    help="Endpoint name or URL to audit (default: all enabled endpoints)",
)
@click.option(
    "--token", "-t",
    help="Override API token (also via $TOKEN env var)",
)
@click.option(
    "--model", "-m",
    help="Override model name (default: from config)",
)
@click.option(
    "--output-dir", "-o",
    type=click.Path(file_okay=False, path_type=Path),
    help="Output directory for reports",
)
@click.option(
    "--format",
    type=click.Choice(["auto", "openai", "anthropic"]),
    default=None,
    help="Force API format detection",
)
@click.option(
    "--detectors",
    multiple=True,
    help="Run only these detectors (by ID)",
)
@click.option(
    "--skip-detectors",
    multiple=True,
    help="Skip these detectors (by ID)",
)
@click.option(
    "--timeout",
    type=int,
    help="Request timeout in seconds (default: from config)",
)
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode (errors only)")
@click.option(
    "--json-only", "json_only", is_flag=True, help="Output JSON only, no Markdown"
)
@click.option(
    "--report-format",
    "report_formats",
    multiple=True,
    type=click.Choice(["json", "markdown", "html"]),
    help="Report formats to generate",
)
def audit(
    config: Path,
    endpoint: str | None,
    token: str | None,
    model: str | None,
    output_dir: Path | None,
    format: str | None,
    detectors: tuple[str, ...],
    skip_detectors: tuple[str, ...],
    timeout: int | None,
    verbose: bool,
    quiet: bool,
    json_only: bool,
    report_formats: tuple[str, ...],
):
    """Run a security audit against configured API endpoints."""
    _setup_logging(verbose, quiet)
    logger = logging.getLogger(__name__)

    # Load config
    try:
        cfg = load_config(config)
    except FileNotFoundError:
        logger.error(f"Config file not found: {config}")
        click.echo(f"Error: Config file not found: {config}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        click.echo(f"Error: Failed to load config: {e}", err=True)
        sys.exit(1)

    # Apply CLI overrides
    cfg = _apply_cli_overrides(cfg, token, endpoint, model, format, timeout, str(output_dir) if output_dir else None)

    # Determine report formats
    if report_formats:
        fmt_list = list(report_formats)
    elif json_only:
        fmt_list = ["json"]
    else:
        fmt_list = list(cfg.reports.formats) if cfg.reports.formats else ["json", "markdown"]

    # Output directory
    out_dir = Path(cfg.settings.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    click.echo(f"Starting audit (formats: {', '.join(fmt_list)})...")
    if verbose:
        click.echo(f"  Config: {config}")
        click.echo(f"  Output: {out_dir}")
        click.echo(f"  Endpoints: {len([e for e in cfg.endpoints if e.enabled])}")

    # Run auditor
    auditor = Auditor(cfg, out_dir)

    try:
        results = auditor.run(endpoint_name=endpoint)
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        click.echo(f"Error: Audit failed: {e}", err=True)
        sys.exit(1)

    if not results:
        click.echo("No results. Check your configuration and endpoint settings.", err=True)
        sys.exit(1)

    # Print summary
    if not quiet:
        print_audit_summary(results)

    # Export reports
    json_exporter = JSONExporter()
    md_exporter = MarkdownExporter()

    output_files: list[Path] = []
    for result in results:
        ep_name = result.target_name or result.target_url.split("//")[1].split("/")[0]

        if "json" in fmt_list:
            json_path = _generate_output_path(out_dir, ep_name, "", "json")
            json_exporter.export(result, json_path, pretty=cfg.reports.json_settings.pretty)
            output_files.append(json_path)

        if "markdown" in fmt_list:
            md_path = _generate_output_path(out_dir, ep_name, "", "md")
            md_exporter.export(result, md_path)
            output_files.append(md_path)

    # Report output paths
    click.echo("\nReport(s) written:")
    for f in output_files:
        click.echo(f"  {f}")

    # Exit code based on risk
    max_risk = max(r.overall_risk.value for r in results)
    if max_risk in ("high", "critical"):
        sys.exit(2)
    elif max_risk == "medium":
        sys.exit(1)


@cli.command("config-test")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("config.yaml"),
    help="Path to config.yaml file",
)
def config_test(config: Path):
    """Validate a config.yaml file and print parsed values."""
    _setup_logging(False, False)

    try:
        cfg = load_config(config)
    except FileNotFoundError:
        click.echo(f"Error: Config file not found: {config}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: Invalid config: {e}", err=True)
        sys.exit(1)

    click.echo("Config validation: OK")
    click.echo(f"\nEndpoints ({len(cfg.endpoints)}):")
    for ep in cfg.endpoints:
        status = "enabled" if ep.enabled else "disabled"
        click.echo(f"  [{status}] {ep.name or ep.url} ({ep.format})")
        click.echo(f"    URL: {ep.url}")
        click.echo(f"    Token: {'*' * 8}{ep.token[-4:] if len(ep.token) > 4 else '***'}")

    click.echo(f"\nSettings:")
    click.echo(f"  timeout: {cfg.settings.timeout}s")
    click.echo(f"  max_retries: {cfg.settings.max_retries}")
    click.echo(f"  default_format: {cfg.settings.default_format}")
    click.echo(f"  output_dir: {cfg.settings.output_dir}")
    click.echo(f"  model: {cfg.settings.model}")
    click.echo(f"  verbose: {cfg.settings.verbose}")
    click.echo(f"  sleep_between_calls: {cfg.settings.sleep_between_calls}s")

    click.echo(f"\nDetectors: (all enabled)")
    click.echo(f"  token_injection, hidden_injection, instruction_override,")
    click.echo(f"  context_truncation, data_exfiltration")


if __name__ == "__main__":
    cli()
