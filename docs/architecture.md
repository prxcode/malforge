# Malforge Architecture

Malforge is a purely offline, static analysis tool designed for speed and reliability. It consists of a 10-stage pipeline that takes a suspicious binary and produces actionable detection engineering artifacts.

## Pipeline Architecture

1. **Initialization & Hashing**: Reads the file bytes, computes hashes (MD5, SHA-1, SHA-256), and calculates file entropy.
2. **String Extraction**: Extracts both ASCII and Unicode strings. Uses regex to categorize strings into URLs, IP addresses, registry keys, and file paths.
3. **PE Analysis**: Uses `pefile` to parse headers, sections, imports, exports, and timestamps.
4. **Heuristics Engine**: Evaluates PE features (e.g., high entropy sections, suspicious API imports like `VirtualAllocEx`) and produces a risk score and heuristic flags.
5. **IOC Extraction**: Refines the raw extracted strings into high-confidence Indicators of Compromise (IOCs) with defined types (e.g., `IndicatorType.IPV4`).
6. **MITRE ATT&CK Mapping**: Maps heuristic flags and IOC types to specific MITRE ATT&CK techniques with supporting evidence.
7. **YARA Generation**: Auto-generates a YARA rule incorporating suspicious APIs and high-confidence network IOCs.
8. **YARA Validation**: Compiles the generated YARA rule in-memory using `yara-python` and matches it against the file to ensure validity.
9. **Sigma Generation**: Generates a Sigma rule focused on process creation, registry modifications, and DNS queries derived from the IOCs.
10. **Report Generation**: Aggregates all data into a JSON structure and renders a standalone HTML threat report using Jinja2.

## Plugin System

Malforge uses Python `entry_points` (`importlib.metadata`) to allow third-party packages to inject additional analysis steps without modifying the core codebase. Plugins implement `malforge.plugins.base.MalforgePlugin` and register themselves under the `malforge.plugins` group.
