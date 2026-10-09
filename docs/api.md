# Python API

## Running an analysis

```python
from pathlib import Path

from malforge.analyzer import Analyzer

analyzer = Analyzer()
result = analyzer.analyze(Path("sample.exe"))

print(result.report["classification"], result.report["risk_score"])
print(result.file_metadata["sha256"])
for ioc in result.iocs:
    print(ioc.indicator_type, ioc.value, ioc.confidence)

paths = analyzer.write_outputs(result, Path("results"), formats=["json"])
```

`Analyzer` accepts keyword arguments:

| Argument  | Default            | Effect                                          |
| --------- | ------------------ | ----------------------------------------------- |
| `yara`    | `True`             | Generate and validate a YARA rule               |
| `sigma`   | `True`             | Generate Sigma rules                            |
| `plugins` | installed plugins  | List of `MalforgePlugin` instances; `[]` for none |

`write_outputs()` returns a dict that maps each output kind (`report_json`,
`report_html`, `iocs`, `mitre`, `yara`, `sigma`) to the path it was written to.

## AnalysisResult

Defined in `malforge.result`.

| Field              | Type                         |
| ------------------ | ---------------------------- |
| `file_metadata`    | `dict` with filename, size, md5, sha1, sha256, entropy |
| `pe_data`          | `dict` or `None` for non-PE files |
| `strings`          | `ExtractedStrings` with `all` and `suspicious` lists |
| `heuristic_flags`  | `list[HeuristicFlag]`        |
| `heuristic_score`  | `float`, 0-10                |
| `suspicious_apis`  | `list[str]`                  |
| `iocs`             | `list[IOC]`                  |
| `attack_mappings`  | `list[AttackMapping]`        |
| `yara_rule`        | `str` or `None`              |
| `yara_validation`  | `ValidationResult` or `None` |
| `sigma_rule`       | `str` or `None`              |
| `report`           | `dict`, the JSON report      |

## Using components on their own

Each stage can be used directly:

```python
from malforge.ioc.extractor import IOCExtractor
from malforge.detection.yara_generator import YaraGenerator
from malforge.detection.sigma_generator import SigmaGenerator

iocs = IOCExtractor().extract_from_strings(["beacon to http://c2.example.ru/gate"])
yara_rule = YaraGenerator().generate("<sha256>", suspicious_apis=[], iocs=iocs)
sigma_rules = SigmaGenerator().generate("<sha256>", iocs)
```

| Class                                              | Purpose                          |
| -------------------------------------------------- | -------------------------------- |
| `malforge.analysis.pe_analyzer.PEAnalyzer`         | Parse a PE file                  |
| `malforge.analysis.string_extractor.StringExtractor` | Extract strings                |
| `malforge.analysis.heuristics.HeuristicsEngine`    | Score parsed PE data             |
| `malforge.ioc.extractor.IOCExtractor`              | Extract IOCs from strings        |
| `malforge.mitre.mapper.MitreMapper`                | Map findings to ATT&CK           |
| `malforge.detection.yara_generator.YaraGenerator`  | Build a YARA rule                |
| `malforge.detection.sigma_generator.SigmaGenerator` | Build Sigma rules               |
| `malforge.detection.validator.DetectionValidator`  | Compile and test a YARA rule     |
