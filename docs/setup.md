# Malforge Setup

Malforge is a lightweight Python package designed to run on Windows, Linux, and macOS.

## System Requirements

- Python 3.11, 3.12, or 3.13
- A C compiler (for `yara-python` if a pre-compiled wheel is not available for your platform)

## Installation from PyPI

```bash
pip install malforge
```

## Installation from Source

```bash
git clone https://github.com/prxcode/malforge.git
cd malforge
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
```

## Development Setup

To contribute to Malforge, install the optional `dev` dependencies which include `pytest`, `ruff`, and `mypy`.

```bash
pip install -e ".[dev]"
```
