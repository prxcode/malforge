# Contributing to Malforge

Thanks for your interest in contributing to Malforge!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/prxcode/malforge.git
cd malforge

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/
```

## Writing a Plugin

Malforge supports plugins via Python entry points.

### 1. Create Your Plugin Class

```python
from malforge.plugins.base import MalforgePlugin

class MyPlugin(MalforgePlugin):
    name = "my_plugin"
    version = "1.0.0"

    def on_analysis_complete(self, result: dict) -> dict:
        # Add custom data to the report
        result["my_custom_field"] = "custom value"
        return result
```

### 2. Register via pyproject.toml

```toml
[project.entry-points."malforge.plugins"]
my_plugin = "my_package:MyPlugin"
```

### 3. Install and Use

```bash
pip install my-malforge-plugin
malforge plugins list   # Should show your plugin
malforge analyze sample.exe   # Plugin runs automatically
```

## Project Structure

```
src/malforge/
├── cli.py              # Click CLI entry point
├── analyzer.py         # Pipeline orchestrator
├── analysis/           # PE parsing, strings, heuristics
├── detection/          # YARA/Sigma generation + validation
├── ioc/                # IOC extraction
├── mitre/              # ATT&CK mapping
├── report/             # JSON + HTML report generation
└── plugins/            # Plugin base class + loader
```

## Guidelines

- Keep code simple and easy to debug
- Follow the existing style (ruff handles formatting)
- Add tests for new features
- Don't add new dependencies without opening an issue first
- Avoid silent fallbacks — fail visibly if something is wrong

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run tests (`pytest tests/ -v`)
5. Lint (`ruff check src/ tests/`)
6. Push and open a Pull Request
