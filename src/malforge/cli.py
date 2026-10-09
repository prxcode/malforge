import logging
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from malforge import __version__
from malforge.analyzer import Analyzer
from malforge.plugins import PLUGIN_GROUP, load_plugins
from malforge.result import AnalysisResult

console = Console()

CLASSIFICATION_STYLES = {
    "MALICIOUS": "bold red",
    "SUSPICIOUS": "bold yellow",
    "BENIGN": "bold green",
}

OUTPUT_LABELS = {
    "report_html": "HTML report",
    "report_json": "JSON report",
    "iocs": "IOCs",
    "mitre": "ATT&CK mapping",
    "yara": "YARA rule",
    "sigma": "Sigma rules",
}


@click.group()
@click.version_option(__version__, prog_name="malforge")
def main() -> None:
    """Malforge: turn a suspicious binary into YARA, Sigma, ATT&CK and IOC reports."""


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-o",
    "--output",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("malforge_output"),
    show_default=True,
    help="Directory to write results to.",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["all", "json", "html"]),
    default="all",
    show_default=True,
    help="Report format(s) to write. IOC, ATT&CK and rule files are always written.",
)
@click.option("--no-yara", is_flag=True, help="Skip YARA rule generation.")
@click.option("--no-sigma", is_flag=True, help="Skip Sigma rule generation.")
@click.option("-v", "--verbose", is_flag=True, help="Show debug logging.")
def analyze(
    file: Path,
    output: Path,
    report_format: str,
    no_yara: bool,
    no_sigma: bool,
    verbose: bool,
) -> None:
    """Analyze FILE and generate detection artifacts."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False)],
    )

    console.print(f"[bold]Malforge[/bold] v{__version__}")
    console.print(f"[dim]Target:[/dim] {file.resolve()}")
    console.print(f"[dim]Output:[/dim] {output.resolve()}\n")

    analyzer = Analyzer(yara=not no_yara, sigma=not no_sigma)
    with console.status("Analyzing...", spinner="line"):
        result = analyzer.analyze(file)

    formats = ["json", "html"] if report_format == "all" else [report_format]
    outputs = analyzer.write_outputs(result, output, formats)

    _print_summary(result, yara_enabled=not no_yara, sigma_enabled=not no_sigma)
    _print_outputs(outputs)


@main.group()
def plugins() -> None:
    """Manage Malforge plugins."""


@plugins.command(name="list")
def plugins_list() -> None:
    """List installed plugins."""
    loaded = load_plugins()
    if not loaded:
        console.print("No plugins installed.")
        console.print(
            f"[dim]Plugins are discovered from the '{PLUGIN_GROUP}' entry point group.[/dim]"
        )
        return

    table = Table(title="Installed plugins")
    table.add_column("Name", style="bold")
    table.add_column("Version")
    for plugin in loaded:
        table.add_row(plugin.name, plugin.version)
    console.print(table)


def _rule_status(rule: str | None, enabled: bool, detail: str = "") -> str:
    if not enabled:
        return "[dim]skipped[/dim]"
    if not rule:
        return "[dim]not generated (no usable indicators)[/dim]"
    return f"[green]generated[/green]{detail}"


def _print_summary(result: AnalysisResult, *, yara_enabled: bool, sigma_enabled: bool) -> None:
    report = result.report
    metadata = report["file_metadata"]
    classification = report["classification"]
    style = CLASSIFICATION_STYLES.get(classification, "bold")

    yara_detail = ""
    if result.yara_validation:
        if not result.yara_validation.is_valid:
            yara_detail = ", [red]does not compile[/red]"
        elif result.yara_validation.true_positive:
            yara_detail = ", compiles, matches sample"
        else:
            yara_detail = ", compiles, [yellow]does not match sample[/yellow]"

    table = Table(title="Analysis summary", show_header=False, show_lines=True)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("File", metadata["filename"])
    table.add_row("SHA-256", metadata["sha256"])
    table.add_row("Size", f"{metadata['file_size']:,} bytes")
    table.add_row("Risk score", f"[bold]{report['risk_score']:.0f}[/bold] / 100")
    table.add_row("Classification", f"[{style}]{classification}[/{style}]")
    table.add_row("Heuristic score", f"{report['heuristic_score']:.1f} / 10.0")
    table.add_row("Heuristic flags", str(len(report["heuristic_flags"])))
    table.add_row("IOCs", str(len(report["iocs"])))
    table.add_row("ATT&CK techniques", str(len(report["attack_mapping"])))
    table.add_row("YARA rule", _rule_status(result.yara_rule, yara_enabled, yara_detail))
    table.add_row("Sigma rules", _rule_status(result.sigma_rule, sigma_enabled))
    console.print(table)

    if result.attack_mappings:
        mitre = Table(title="MITRE ATT&CK")
        mitre.add_column("Technique", style="bold cyan")
        mitre.add_column("Name")
        mitre.add_column("Tactic", style="dim")
        for m in result.attack_mappings:
            mitre.add_row(m.technique_id, m.technique_name, m.tactic)
        console.print(mitre)


def _print_outputs(outputs: dict[str, Path]) -> None:
    table = Table(title="Output files")
    table.add_column("Type", style="bold")
    table.add_column("Path", overflow="fold")
    for kind, path in outputs.items():
        table.add_row(OUTPUT_LABELS.get(kind, kind), str(path))
    console.print(table)
