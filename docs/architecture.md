# Architecture

Malforge is a single offline pipeline. `Analyzer.analyze()` in `src/malforge/analyzer.py`
runs each stage in order and collects the results in an `AnalysisResult`
(`src/malforge/result.py`).

```
file bytes
  ├─ file_info          hashes, Shannon entropy
  ├─ StringExtractor    ASCII + UTF-16LE strings, suspicious keyword hits
  ├─ PEAnalyzer         headers, sections, imports, exports  (skipped if not a PE)
  ├─ HeuristicsEngine   flags + heuristic score 0-10          (PE only)
  ├─ IOCExtractor       typed IOCs from the strings, plus the file's own hashes
  ├─ MitreMapper        ATT&CK techniques from flags, strings and IOCs
  ├─ YaraGenerator  ──▶ DetectionValidator (compile + match against the sample)
  ├─ SigmaGenerator     one rule per log source
  ├─ ReportGenerator    report dict, risk score, classification
  └─ plugins            each receives the report dict and returns it
```

`Analyzer.write_outputs()` then writes the report as JSON and HTML, plus the IOC list,
the ATT&CK mapping and the rule files.

## Stages

**Strings.** Runs of at least 5 printable characters, in both ASCII and UTF-16LE.
Strings that contain an entry of `SUSPICIOUS_KEYWORDS` (LOLBins, shadow copy deletion,
injection API names) are kept separately for ATT&CK mapping.

**Heuristics.** Each `ApiRule` lists groups of APIs. A rule fires when the PE imports at
least one API from every group, so the process injection rule needs an allocation, a
write and a thread-creation API. Section checks flag high entropy (above 7.2), UPX section
names and non-standard section names. Weights add up to a score capped at 10.

**IOCs.** Regex patterns per indicator type, followed by filters for the false positives
that are common in binaries:

- Domains must end in a real TLD and be single-case. This rejects `kernel32.dll`,
  `notepad.cpp` and `System.Runtime.InteropServices`.
- IPs inside longer dotted sequences (OIDs), network addresses such as `6.0.0.0`, and
  private, loopback, link-local and multicast ranges are dropped.
- Certificate authority and Microsoft domains are dropped.

**ATT&CK mapping.** Static tables in `mitre/mapper.py` map heuristic names and string
keywords to techniques. URLs map to T1071.001 and `CurrentVersion\Run` keys to T1547.001.
Each technique appears once, with the first piece of evidence that triggered it.

**YARA.** Strings come from the APIs that triggered heuristics and from up to 10 network
IOCs. The condition requires the MZ header plus all (or 3 of) the API strings and any
(or 2 of) the IOC strings. The rule is compiled with `yara-python` and run against the
sample, and the result is recorded in the report.

**Sigma.** File paths ending in `.exe` produce a `process_creation` rule, registry keys a
`registry_set` rule, domains a `dns_query` rule, and IPs a `network_connection` rule. Rule
IDs are UUIDv5 values derived from the sample hash and log source, so re-running on the
same sample gives the same IDs.

## Risk score

`report/generator.py` combines three components into a score from 0 to 100:

| Component           | Contribution                      | Maximum |
| ------------------- | --------------------------------- | ------- |
| Heuristic score     | heuristic score × 6               | 60      |
| ATT&CK techniques   | 6 per technique                   | 30      |
| Network IOCs        | 5 per URL, domain or IP           | 10      |

A score of 60 or more is `MALICIOUS`, 25 or more is `SUSPICIOUS`, and anything lower is
`BENIGN`. The file's own hashes are recorded as IOCs but are not counted.

## Plugins

Plugins are discovered through the `malforge.plugins` entry point group and run last.
See [plugins.md](plugins.md).
