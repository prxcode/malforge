# Malforge — HTML Report Renderer
# Renders analysis results into a standalone HTML file using Jinja2.

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"


class HtmlReportRenderer:
    """Renders a standalone HTML report from analysis data."""

    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )

    def render(self, report_data: dict[str, Any]) -> str:
        """Render the full HTML report as a string."""
        template = self.env.get_template("report.html")

        # Pre-format YARA and Sigma rules for display
        context = {
            "report": report_data,
            "report_json": json.dumps(report_data, indent=2, default=str),
        }

        return template.render(**context)

    def render_to_file(self, report_data: dict[str, Any], output_path: Path) -> None:
        """Render the HTML report and write it to a file."""
        html = self.render(report_data)
        output_path.write_text(html, encoding="utf-8")
