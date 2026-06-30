# Malforge API

The Malforge pipeline is exposed as a Python library, allowing you to integrate it into your own scripts and tools.

## Example Usage

```python
from pathlib import Path
from malforge.analyzer import Analyzer

file_path = Path("sample.exe")
analyzer = Analyzer()

# Run the 10-stage pipeline
result = analyzer.analyze(file_path)

# Access typed data
print(f"Risk Score: {result.report['risk_score']}")
print(f"File Hashes: {result.file_metadata['sha256']}")
print(f"Number of IOCs extracted: {len(result.iocs)}")
print(f"Number of ATT&CK techniques: {len(result.attack_mappings)}")

# Write standard outputs to a directory
output_dir = Path("./results")
analyzer.write_outputs(result, output_dir)
```

## Core Classes

- `malforge.analyzer.Analyzer`: The main orchestrator class.
- `malforge.ioc.extractor.IOCExtractor`: Extracts `malforge.ioc.extractor.IOC` objects from text.
- `malforge.detection.yara_generator.YaraGenerator`: Generates YARA rules.
- `malforge.detection.sigma_generator.SigmaGenerator`: Generates Sigma rules.
- `malforge.plugins.base.MalforgePlugin`: Base class for creating custom plugins.
