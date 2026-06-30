<p align="center">
  <h1 align="center">Malforge</h1>
  <p align="center">
    <strong>Detection Engineering Toolkit</strong><br>
    Generate YARA · Sigma · MITRE ATT&CK · IOC Reports · HTML Reports<br>from a suspicious binary. One command.
  </p>
  <p align="center">
    <a href="https://pypi.org/project/malforge"><img src="https://img.shields.io/pypi/v/malforge?color=7c5cff&style=flat-square" alt="PyPI"></a>
    <a href="https://github.com/prxcode/malforge/actions"><img src="https://img.shields.io/github/actions/workflow/status/prxcode/malforge/ci.yml?style=flat-square&label=CI" alt="CI"></a>
    <img src="https://img.shields.io/pypi/pyversions/malforge?style=flat-square&color=3b82f6" alt="Python">
    <a href="LICENSE"><img src="https://img.shields.io/github/license/prxcode/malforge?style=flat-square" alt="License"></a>
  </p>
</p>

---

## What It Does

**Malforge** takes a suspicious binary and produces five actionable outputs:

```
sample.exe → malforge analyze → YARA Rule
                                 Sigma Rule
                                 MITRE ATT&CK Mapping
                                 IOC Report (JSON)
                                 HTML Threat Report
```

It runs a **10-stage analysis pipeline** entirely offline — no cloud, no sandbox, no Docker required:

1. **File hashing** — MD5, SHA1, SHA256, entropy
2. **PE parsing** — Headers, sections, imports, exports, timestamps
3. **String extraction** — ASCII/Unicode strings, categorized (URLs, IPs, registry, paths)
4. **Heuristic analysis** — Process injection, keylogging, crypto, anti-debug, packing detection
5. **IOC extraction** — Network indicators, file hashes, registry keys with confidence scoring
6. **MITRE ATT&CK mapping** — ~13 techniques mapped from heuristics and IOCs
7. **YARA rule generation** — From suspicious APIs + network IOCs, auto-validated
8. **Sigma rule generation** — From file paths, registry, DNS, and network IOCs
9. **HTML report** — Standalone, dark-themed, professional threat report
10. **Plugin hooks** — Extend with your own analysis steps

## Install

```bash
pip install malforge
```

Requires **Python 3.11+** and `yara-python` (compiled automatically by pip on most systems).

## Quick Start

```bash
# Analyze a suspicious binary
malforge analyze sample.exe

# Custom output directory
malforge analyze sample.exe -o ./results

# JSON report only (skip HTML)
malforge analyze sample.exe --format json

# Skip Sigma rule generation
malforge analyze sample.exe --no-sigma

# Show version
malforge --version
```

## Output

```
malforge_output/
├── report.html          # Standalone HTML threat report
├── report.json          # Full analysis data
├── iocs.json            # Extracted IOCs with confidence scores
├── mitre_mapping.json   # ATT&CK technique mappings
└── rules/
    ├── yara_rule.yar    # Auto-generated YARA rule
    └── sigma_rule.yml   # Auto-generated Sigma rule
```

### Sample YARA Rule Output

```yara
rule Malforge_a1b2c3d4 {
    meta:
        author = "Malforge"
        description = "Auto-generated detection rule from static analysis."
        date = "2026-06-30"
        hash = "a1b2c3d4..."
        tlp = "WHITE"

    strings:
        $s0 = "VirtualAllocEx" ascii wide nocase
        $s1 = "WriteProcessMemory" ascii wide nocase
        $s2 = "CreateRemoteThread" ascii wide nocase
        $ioc_url0 = "http://evil.com/payload.exe" ascii wide
        $ioc_ip1 = "203.0.113.50" ascii wide

    condition:
        uint16(0) == 0x5a4d
        and all of ($s*)
        and any of ($ioc_*)
}
```

### Sample Sigma Rule Output

```yaml
title: Suspicious Activity — Malforge a1b2c3d4
id: 8f14e45f-ceea-367f-a27f-c790a516b3b9
status: experimental
description: Auto-generated Sigma rule for sample a1b2c3d4...
author: Malforge
date: 2026/06/30
logsource:
    category: process_creation
    product: windows
detection:
    selection_files:
        Image|endswith:
            - '\cmd.exe'
    selection_registry:
        TargetObject|contains:
            - 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
    selection_dns:
        QueryName|endswith:
            - 'malicious-domain.com'
    condition: selection_files or selection_registry or selection_dns
falsepositives:
    - Unknown
level: medium
```

## How It Works

```
 ┌─────────────────────────────────────────────────────┐
 │                malforge analyze                     │
 │                                                     │
 │  sample.exe ──▶ Read bytes + compute hashes         │
 │       │                                             │
 │       ├──▶ PE Analyzer (pefile)                     │
 │       │     └── headers, sections, imports, exports │
 │       │                                             │
 │       ├──▶ String Extractor                          │
 │       │     └── URLs, IPs, registry, suspicious      │
 │       │                                              │
 │       ├──▶ Heuristic Engine                          │
 │       │     └── injection, keylog, crypto, packing   │
 │       │                                              │
 │       ├──▶ IOC Extractor                             │
 │       │     └── typed IOCs with confidence scores    │
 │       │                                              │
 │       ├──▶ MITRE ATT&CK Mapper                      │
 │       │     └── technique IDs + tactics + evidence   │
 │       │                                              │
 │       ├──▶ YARA Generator ──▶ Validator              │
 │       │                                              │
 │       ├──▶ Sigma Generator                           │
 │       │                                              │
 │       └──▶ Report Generator                          │
 │             ├── report.json                          │
 │             ├── report.html                          │
 │             ├── iocs.json                            │
 │             ├── mitre_mapping.json                   │
 │             └── rules/ (yara + sigma)                │
 └─────────────────────────────────────────────────────┘
```

## Plugin System

Extend Malforge with custom analysis steps:

```python
# my_plugin.py
from malforge.plugins.base import MalforgePlugin

class VirusTotalPlugin(MalforgePlugin):
    name = "virustotal"
    version = "1.0.0"

    def on_analysis_complete(self, result: dict) -> dict:
        # Add VirusTotal lookup results
        result["virustotal"] = {"detected": True, "positives": 42}
        return result
```

Register in your plugin's `pyproject.toml`:
```toml
[project.entry-points."malforge.plugins"]
virustotal = "my_plugin:VirusTotalPlugin"
```

```bash
pip install my-malforge-plugin
malforge plugins list       # Shows: virustotal v1.0.0
malforge analyze sample.exe # Plugin runs automatically
```

## Project Structure

```
malforge/
├── src/malforge/
│   ├── cli.py              # Click CLI entry point
│   ├── analyzer.py         # 10-stage pipeline orchestrator
│   ├── analysis/           # PE parsing, string extraction, heuristics
│   ├── detection/          # YARA + Sigma generation, YARA validation
│   ├── ioc/                # IOC extraction with confidence scoring
│   ├── mitre/              # ATT&CK technique mapping
│   ├── report/             # JSON + HTML report generation
│   └── plugins/            # Plugin base class + entry point loader
├── tests/                  # pytest test suite
├── pyproject.toml          # Package config (pip install malforge)
├── CONTRIBUTING.md         # Plugin dev guide + contribution workflow
└── LICENSE                 # MIT
```

## Development

```bash
git clone https://github.com/prxcode/malforge.git
cd malforge
python -m venv .venv && .venv\Scripts\activate
pip install -e ".[dev]"
pytest tests/ -v
```

## What This Is NOT

Malforge is a **static analysis + detection engineering** tool. It does not:

- Execute malware (no sandbox/dynamic analysis)
- Perform full reverse engineering
- Replace commercial EDR or threat intelligence platforms
- Claim memory forensics capabilities

It does one workflow well: **binary → detection artifacts**. If you need dynamic analysis, pair it with [CAPEv2](https://github.com/kevoreilly/CAPEv2) or [ANY.RUN](https://any.run).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, plugin development, and PR guidelines.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Priyanshu** — [@prxcode](https://github.com/prxcode)
