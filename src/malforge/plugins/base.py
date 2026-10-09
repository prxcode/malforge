from typing import Any


class MalforgePlugin:
    """Base class for Malforge plugins.

    Subclass it, override :meth:`on_analysis_complete`, and register the class
    under the ``malforge.plugins`` entry point group of your package.
    """

    name: str = "unnamed_plugin"
    version: str = "0.0.0"

    def on_analysis_complete(self, report: dict[str, Any]) -> dict[str, Any]:
        """Receive the finished report and return it, optionally modified."""
        return report
