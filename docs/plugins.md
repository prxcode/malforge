# Writing a plugin

A plugin is a class that receives the finished report and returns it, usually with extra
data added. Plugins run after every built-in stage, in the order they are discovered.

## 1. Write the class

```python
# my_malforge_plugin/__init__.py
from typing import Any

from malforge.plugins import MalforgePlugin


class HashLookup(MalforgePlugin):
    name = "hash-lookup"
    version = "0.1.0"

    def on_analysis_complete(self, report: dict[str, Any]) -> dict[str, Any]:
        sha256 = report["file_metadata"]["sha256"]
        report["hash_lookup"] = {"sha256": sha256, "known_bad": False}
        return report
```

The report has the same structure as `report.json`. Anything you add ends up in
`report.json`. The HTML report only renders the built-in sections.

## 2. Register the entry point

In your plugin package's `pyproject.toml`:

```toml
[project.entry-points."malforge.plugins"]
hash-lookup = "my_malforge_plugin:HashLookup"
```

## 3. Install and check

```bash
pip install -e .
malforge plugins list
```

## Behaviour

- Classes that do not subclass `MalforgePlugin` are skipped with a warning.
- If a plugin raises an exception during loading or in `on_analysis_complete`, the error
  is logged with its traceback and the analysis carries on without it.
- Plugins should not need network access to work. If yours does, make that clear in its
  documentation and fail gracefully when offline.
