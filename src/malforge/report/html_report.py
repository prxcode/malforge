from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from malforge import __version__


class HtmlReportRenderer:
    """Renders the analysis report as a single self-contained HTML page."""

    def __init__(self) -> None:
        self.env = Environment(
            loader=PackageLoader("malforge", "report/templates"),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render(self, report: dict[str, Any]) -> str:
        return self.env.get_template("report.html").render(report=report, version=__version__)

    def render_to_file(self, report: dict[str, Any], output_path: Path) -> None:
        output_path.write_text(self.render(report), encoding="utf-8")
