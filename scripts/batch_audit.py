#!/usr/bin/env python3
"""Batch audit CLI — runs audits against all enabled endpoints in config.yaml.

Usage:
    python scripts/batch_audit.py --config config.yaml
    python scripts/batch_audit.py -c config.yaml --format json
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from api_relay_audit.config.loader import load_config
from api_relay_audit.engine.auditor import Auditor
from api_relay_audit.reports.json_exporter import JSONExporter
from api_relay_audit.reports.markdown_exporter import MarkdownExporter
from api_relay_audit.utils.formatting import print_audit_summary


def _setup_logging(verbose: bool, quiet: bool) -> None:
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


@click.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("config.yaml"),
    help="Path to config.yaml",
)
@click.option("-v", "--verbose", is_flag=True)
@click.option("-q", "--quiet", is_flag=True)
@click.option(
    "--format",
    "report_formats",
    multiple=True,
    type=click.Choice(["json", "markdown", "html"]),
    help="Report formats to generate",
)
def batch_audit(
    config: Path,
    verbose: bool,
    quiet: bool,
    report_formats: tuple[str, ...],
):
    """Audit all enabled endpoints in the config file."""
    _setup_logging(verbose, quiet)
    logger = logging.getLogger(__name__)

    try:
        cfg = load_config(config)
    except FileNotFoundError:
        click.echo(f"Error: Config not found: {config}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error loading config: {e}", err=True)
        sys.exit(1)

    enabled = [e for e in cfg.endpoints if e.enabled]
    if not enabled:
        click.echo("No enabled endpoints found in config.")
        sys.exit(0)

    click.echo(f"Batch audit: {len(enabled)} endpoint(s)\n")

    out_dir = Path(cfg.settings.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    auditor = Auditor(cfg, out_dir)
    json_exporter = JSONExporter()
    md_exporter = MarkdownExporter()

    fmt_list = list(report_formats) if report_formats else list(cfg.reports.formats)

    all_results = []
    for ep in enabled:
        ep_name = ep.name or str(ep.url).split("//")[1].split("/")[0]
        click.echo(f"\n--- Auditing: {ep_name} ---")

        try:
            results = auditor.run(endpoint_name=ep.name)
            all_results.extend(results)
        except Exception as e:
            logger.error(f"Failed to audit {ep_name}: {e}")
            click.echo(f"  ERROR: {e}", err=True)
            continue

    if all_results:
        if not quiet:
            print_audit_summary(all_results)

        # Export reports for all results
        from datetime import datetime
        for result in all_results:
            ep_name = result.target_name or result.target_url.split("//")[1].split("/")[0]
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in ep_name)

            for fmt in fmt_list:
                if fmt == "json":
                    path = out_dir / f"{safe_name}_{ts}_batch.json"
                    json_exporter.export(result, path, pretty=cfg.reports.json.pretty)
                    click.echo(f"  JSON: {path}")
                elif fmt == "markdown":
                    path = out_dir / f"{safe_name}_{ts}_batch.md"
                    md_exporter.export(result, path)
                    click.echo(f"  Markdown: {path}")
    else:
        click.echo("\nNo results generated.")

    click.echo("\nBatch audit complete.")


if __name__ == "__main__":
    batch_audit()
