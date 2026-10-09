# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-09

### Added

- Heuristic for download-and-execute API combinations.
- ATT&CK mappings for rundll32, regsvr32, mshta, certutil, bitsadmin, bcdedit and wevtutil.
- `yara_compiles` and `yara_matches_sample` in the report, and a match status in the CLI summary.
- `url` field on every ATT&CK mapping.
- `Analyzer(yara=..., sigma=..., plugins=...)` and `write_outputs(..., formats=...)`.
- `py.typed` marker, so type checkers use Malforge's annotations.

### Changed

- Sigma output is now one rule per log source (`process_creation`, `registry_set`,
  `dns_query`, `network_connection`). The old single rule mixed fields from all four
  under `process_creation` and was not valid Sigma.
- Risk score is now 60% heuristics, 30% ATT&CK techniques and 10% network IOCs. The
  sample's own hashes no longer count towards it. `SUSPICIOUS` starts at 25 and
  `MALICIOUS` at 60.
- Anti-debugging is mapped to T1622 Debugger Evasion instead of T1497.001.
- Repeated section findings are reported as one flag instead of one per section.
- YARA rules use `$api*` for imported APIs and TLP `CLEAR`. No rule is written if the
  sample has no specific indicators, instead of a rule that matched every PE file.
- `--no-yara`, `--no-sigma` and `--format` now skip the work instead of deleting output
  afterwards, and skipped rules no longer appear in `report.json` or the HTML report.

### Removed

- `file_path` from file metadata, so reports no longer leak the analyst's local paths.
- `strings.urls`, `strings.ips`, `strings.registry` and `strings.paths` from the report.
  These duplicated the IOC list.
- Unused `IndicatorType` members (`IPV6`, `MUTEX`, `SERVICE_NAME`, `SCHEDULED_TASK`,
  `USER_AGENT`, `PIPE_NAME`).

### Fixed

- YARA validation crashed on yara-python 4.3 and newer, so match details were always empty.
- File names such as `payload.exe` and `cmd.exe` were reported as domains and ended up
  in YARA and Sigma rules.
- Version strings and OIDs such as `6.0.0.0` were reported as IP addresses.
- `IsDebuggerPresent`, which almost every MSVC binary imports, triggered the
  anti-debugging heuristic.
- `notmicrosoft.com` was treated as benign because it ends with `microsoft.com`.
- T1105 was reported for any file path, and T1547.001 for any registry key.
- `malforge analyze` crashed with `UnicodeEncodeError` on Windows consoles using a legacy
  code page when its output was redirected.

## [1.0.0] - 2026-07-02

First release.

[Unreleased]: https://github.com/prxcode/malforge/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/prxcode/malforge/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/prxcode/malforge/releases/tag/v1.0.0
