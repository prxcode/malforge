# Testing Malforge

Malforge uses `pytest` for testing. The test suite includes unit tests for individual components and end-to-end integration tests for the CLI and the analyzer pipeline.

## Running Tests

From the project root:

```bash
# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=src/malforge

# Run specific test file
pytest tests/test_cli.py -v
```

## Test Fixtures

Malforge tests do not rely on actual malware samples. Instead, we use `tests/conftest.py` to dynamically generate a valid, benign Windows PE (Portable Executable) file in memory that contains specific traits we want to test (e.g., suspicious strings, fake IPs, specific API imports). This ensures the test suite is safe to run on any machine or CI environment.

## CLI Testing

The CLI is tested using Click's `CliRunner`, which allows us to invoke CLI commands in isolation and capture their stdout and exit codes. 

To test the CLI manually:
```bash
# Install your local checkout
pip install -e .

# Run the command
malforge analyze sample.exe --verbose
```
