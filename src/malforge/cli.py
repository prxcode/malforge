import logging
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from malforge import __version__
from malforge.analyzer import Analyzer

if TYPE_CHECKING:
    from malforge.analyzer import AnalysisResult
from malforge.plugins import load_plugins

console = Console()


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(name)s — %(message)s",
    )


@click.group()
@click.version_option(version=__version__, prog_name="malforge")
def main() -> None:
    """Malforge — Detection Engineering Toolkit.

    Generate YARA rules, Sigma rules, MITRE ATT&CK mappings, IOC reports,
    and HTML reports from suspicious binaries.
    """


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory (default: ./malforge_output)",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["all", "json", "html"]),
    default="all",
    help="Output format (default: all)",
)
@click.option("--no-yara", is_flag=True, help="Skip YARA rule generation")
@click.option("--no-sigma", is_flag=True, help="Skip Sigma rule generation")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
def analyze(
    file: Path,
    output: Path | None,
    output_format: str,
    no_yara: bool,
    no_sigma: bool,
    verbose: bool,
) -> None:
    """Analyze a suspicious binary and generate detection artifacts."""
    setup_logging(verbose)

    if output is None:
        output = Path("malforge_output")

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]Malforge v{__version__}[/bold]  —  Detection Engineering Toolkit",
            border_style="bright_magenta",
        )
    )
    console.print()

    # Validate file
    file = file.resolve()
    console.print(f"  [dim]Target:[/dim]  {file}")
    console.print(f"  [dim]Output:[/dim]  {output.resolve()}")
    console.print()

    # Run analysis
    analyzer = Analyzer()

    with console.status("[bold magenta]Analyzing...[/bold magenta]", spinner="dots"):
        result = analyzer.analyze(file)

    # Suppress outputs based on flags
    if no_yara:
        result.yara_rule = None
        result.yara_validation = None
    if no_sigma:
        result.sigma_rule = None

    # Write outputs
    outputs = analyzer.write_outputs(result, output)

    # Remove unwanted format files
    if output_format == "json" and "report_html" in outputs:
        outputs["report_html"].unlink(missing_ok=True)
        del outputs["report_html"]
    elif output_format == "html" and "report_json" in outputs:
        outputs["report_json"].unlink(missing_ok=True)
        del outputs["report_json"]

    # Print summary
    console.print()
    _print_summary(result)
    _print_outputs(outputs)
    console.print()


@main.group()
def plugins() -> None:
    """Manage malforge plugins."""


@plugins.command(name="list")
def plugins_list() -> None:
    """List all loaded plugins."""
    loaded = load_plugins()
    if not loaded:
        console.print("  [dim]No plugins installed.[/dim]")
        console.print()
        console.print(
            "  Install plugins via pip, then register them in pyproject.toml:"
        )
        console.print('  [dim][project.entry-points."malforge.plugins"][/dim]')
        console.print('  [dim]my_plugin = "my_package:MyPlugin"[/dim]')
        return

    table = Table(title="Loaded Plugins")
    table.add_column("Name", style="bold")
    table.add_column("Version")
    for p in loaded:
        table.add_row(p.name, p.version)
    console.print(table)


def _print_summary(result: "AnalysisResult") -> None:  # type: ignore[name-defined]
    """Print a colorful summary table."""
    report = result.report

    # Classification color
    classification = report.get("classification", "UNKNOWN")
    if classification == "MALICIOUS":
        cls_style = "bold red"
    elif classification == "SUSPICIOUS":
        cls_style = "bold yellow"
    else:
        cls_style = "bold green"

    # Summary table
    table = Table(
        title="Analysis Summary", border_style="bright_magenta", show_lines=True
    )
    table.add_column("Metric", style="dim", width=20)
    table.add_column("Value")

    table.add_row("File", report["file_metadata"]["filename"])
    table.add_row("SHA-256", report["file_metadata"]["sha256"][:32] + "...")
    table.add_row("Size", f"{report['file_metadata']['file_size']:,} bytes")
    table.add_row("Risk Score", f"[bold]{report['risk_score']:.0f}[/bold] / 100")
    table.add_row("Classification", f"[{cls_style}]{classification}[/{cls_style}]")
    table.add_row("Heuristic Score", f"{report['heuristic_score']:.1f} / 10.0")
    table.add_row("Heuristic Flags", str(len(report.get("heuristic_flags", []))))
    table.add_row("IOCs Found", str(len(report.get("iocs", []))))
    table.add_row("ATT&CK Techniques", str(len(report.get("attack_mapping", []))))
    table.add_row(
        "YARA Rule",
        "[green]Generated [PASS][/green]" if result.yara_rule else "[dim]Skipped[/dim]",
    )
    table.add_row(
        "Sigma Rule",
        (
            "[green]Generated [PASS][/green]"
            if result.sigma_rule
            else "[dim]Skipped[/dim]"
        ),
    )

    console.print(table)

    # ATT&CK techniques mini-table
    if result.attack_mappings:
        console.print()
        mitre_table = Table(title="MITRE ATT&CK Mappings", border_style="blue")
        mitre_table.add_column("Technique", style="bold cyan")
        mitre_table.add_column("Name")
        mitre_table.add_column("Tactic", style="dim")
        for m in result.attack_mappings:
            mitre_table.add_row(m.technique_id, m.technique_name, m.tactic)
        console.print(mitre_table)


def _print_outputs(outputs: dict[str, Path]) -> None:
    """Print the output file paths."""
    console.print()
    table = Table(title="Output Files", border_style="green")
    table.add_column("Type", style="bold")
    table.add_column("Path")

    labels = {
        "report_html": "HTML Report",
        "report_json": "JSON Report",
        "iocs": "IOCs",
        "mitre": "MITRE Mapping",
        "yara": "YARA Rule",
        "sigma": "Sigma Rule",
    }

    for key, path in outputs.items():
        label = labels.get(key, key)
        table.add_row(label, str(path))

    console.print(table)


if __name__ == "__main__":
    main()
