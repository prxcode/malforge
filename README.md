# Malforge

[![PyPI](https://img.shields.io/pypi/v/malforge?color=7c5cff)](https://pypi.org/project/malforge/)
[![Python](https://img.shields.io/pypi/pyversions/malforge)](https://pypi.org/project/malforge/)
[![CI](https://img.shields.io/github/actions/workflow/status/prxcode/malforge/ci.yml?branch=main&label=CI)](https://github.com/prxcode/malforge/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/prxcode/malforge)](https://github.com/prxcode/malforge/blob/main/LICENSE)

Malforge is a static analysis tool for detection engineers. Point it at a suspicious
Windows binary and it writes:

- a **YARA rule**, compiled and tested against the sample before it is saved
- **Sigma rules** for process, registry, DNS and network telemetry
- a **MITRE ATT&CK** mapping with the evidence behind each technique
- an **IOC list** (URLs, domains, IPs, registry keys, paths, hashes) with confidence scores
- a **JSON report** and a self-contained **HTML report**

It never executes the sample and needs no network access, sandbox or API keys.

## Installation

```bash
pip install malforge
```

Requires Python 3.11 or newer. `yara-python` ships prebuilt wheels for most platforms;
elsewhere pip builds it from source, which needs a C compiler.

## Usage

```bash
malforge analyze sample.exe                   # writes to ./malforge_output
malforge analyze sample.exe -o results/
malforge analyze sample.exe --format json     # skip the HTML report
malforge analyze sample.exe --no-sigma        # skip Sigma rule generation
malforge analyze sample.exe --no-yara -v      # skip YARA, show debug logging
malforge plugins list
```

Output layout:

```
malforge_output/
├── report.html
├── report.json
├── iocs.json
├── mitre_mapping.json
└── rules/
    ├── yara_rule.yar
    └── sigma_rule.yml
```

A rule file is only written when the sample has indicators specific enough to build it from.

### Example output

From the harmless test binary built by [`tests/pe_builder.py`](https://github.com/prxcode/malforge/blob/main/tests/pe_builder.py):

```yara
rule Malforge_1962dd02 {
    meta:
        author = "Malforge"
        description = "Auto-generated from static analysis"
        date = "2026-10-09"
        hash = "1962dd02da5557370227e71053a2ed19f9a72df0539c679375db6d3dd17cc91e"
        tlp = "CLEAR"

    strings:
        $ioc_ip0 = "203.0.113.50" ascii wide
        $ioc_url1 = "http://malicious-test-domain.com/payload.exe" ascii wide
        $ioc_dom2 = "malicious-test-domain.com" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and any of ($ioc_*)
}
```

`sigma_rule.yml` holds one rule per log source, separated by `---`:

```yaml
title: Malforge 1962dd02 - Suspicious Registry Key
id: bd4c96ed-b3c7-5491-bda5-eba24c60dc6f
status: experimental
description: Auto-generated from static analysis of sample 1962dd02da55...
author: Malforge
date: 2026-10-09
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - 'Software\Microsoft\Windows\CurrentVersion\Run'
    condition: selection
falsepositives:
    - Unknown
level: medium
```

## Python API

```python
from pathlib import Path

from malforge.analyzer import Analyzer

analyzer = Analyzer()
result = analyzer.analyze(Path("sample.exe"))

print(result.report["classification"], result.report["risk_score"])
for mapping in result.attack_mappings:
    print(mapping.technique_id, mapping.technique_name)

analyzer.write_outputs(result, Path("results"))
```

See [docs/api.md](https://github.com/prxcode/malforge/blob/main/docs/api.md) for the full API.

## Plugins

Plugins receive the finished report and can add to it. Subclass `MalforgePlugin` and
register it as an entry point:

```python
from malforge.plugins import MalforgePlugin


class HashLookup(MalforgePlugin):
    name = "hash-lookup"
    version = "0.1.0"

    def on_analysis_complete(self, report):
        report["hash_lookup"] = {"known_bad": False}
        return report
```

```toml
[project.entry-points."malforge.plugins"]
hash-lookup = "my_package:HashLookup"
```

See [docs/plugins.md](https://github.com/prxcode/malforge/blob/main/docs/plugins.md).

## How it works

Malforge hashes the file, extracts strings, parses the PE structure with `pefile`, scores
it against import and section heuristics, pulls IOCs out of the strings, maps the
findings to ATT&CK, and generates and validates detection rules. The details, including
how the risk score is calculated, are in
[docs/architecture.md](https://github.com/prxcode/malforge/blob/main/docs/architecture.md).

## Limitations

- Static analysis only. Packed or encrypted samples hide most of their strings and
  imports, so expect thin results for them (the high-entropy and UPX heuristics flag this).
- The risk score is a triage aid, not a verdict. Legitimate system binaries that import
  injection or hooking APIs will score as suspicious.
- Generated rules are starting points marked `experimental`. Review them before deploying.

For dynamic analysis, pair Malforge with a sandbox such as
[CAPEv2](https://github.com/kevoreilly/CAPEv2).

## Contributing

Bug reports, new heuristics and ATT&CK mappings are welcome. See
[CONTRIBUTING.md](https://github.com/prxcode/malforge/blob/main/CONTRIBUTING.md) to get started.

## License

[MIT](https://github.com/prxcode/malforge/blob/main/LICENSE)
