from __future__ import annotations

from pathlib import Path

import typer

from .pipeline import IOCPipeline

app = typer.Typer(help="SOC automation CLI for IOC enrichment and incident response.")


@app.command()
def run_pipeline(
    log_file: str = typer.Option(..., "--log-file", help="Path to the suspicious log file."),
    output_dir: str = typer.Option("reports", "--output-dir", help="Output directory for generated reports."),
) -> None:
    """Run the IOC enrichment pipeline on a log file."""
    pipeline = IOCPipeline(log_file, output_dir)
    results = pipeline.run()
    typer.echo(f"Processed {len(results)} IOC entries.")


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo("soc-automation-tool 0.1.0")


if __name__ == "__main__":
    app()
