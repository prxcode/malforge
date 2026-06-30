from typing import Any


class MalforgePlugin:
    """Base class for malforge plugins.

    To create a plugin:
    1. Create a class that extends MalforgePlugin
    2. Implement on_analysis_complete()
    3. Register via pyproject.toml entry point:

       [project.entry-points."malforge.plugins"]
       my_plugin = "my_package:MyPlugin"
    """

    name: str = "unnamed_plugin"
    version: str = "0.0.0"

    def on_analysis_complete(self, result: dict[str, Any]) -> dict[str, Any]:
        """Hook called after analysis is complete.

        Receives the full analysis result dict.
        Return the (optionally modified) result.
        """
        return result
