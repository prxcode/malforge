# Contributing to Malforge

Thanks for helping out. This guide covers setting up a dev environment, where things
live, and what a pull request needs.

## Setup

```bash
git clone https://github.com/prxcode/malforge.git
cd malforge
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Checks

CI runs these on every pull request. Run them before pushing:

```bash
ruff check .
ruff format --check .
mypy
pytest --cov
```

## Project layout

```
src/malforge/
├── cli.py                  Click commands and terminal output
├── analyzer.py             Runs the pipeline and writes output files
├── result.py               AnalysisResult, the pipeline's output
├── analysis/
│   ├── file_info.py        Hashes and entropy
│   ├── string_extractor.py ASCII/UTF-16 strings and suspicious keywords
│   ├── pe_analyzer.py      PE parsing via pefile
│   └── heuristics.py       Import and section heuristics, heuristic score
├── ioc/extractor.py        IOC patterns and false-positive filters
├── mitre/mapper.py         Heuristic, string and IOC to ATT&CK mappings
├── detection/
│   ├── yara_generator.py
│   ├── sigma_generator.py
│   └── validator.py        Compiles and test-matches YARA rules
├── report/
│   ├── generator.py        Report dict and risk score
│   ├── html_report.py
│   └── templates/report.html
└── plugins/                Plugin base class and entry point loader
tests/
├── pe_builder.py           Builds the harmless PE used by the tests
└── test_*.py               One file per module
```

`docs/architecture.md` describes the pipeline end to end.

## Common changes

**Add an API heuristic.** Add an `ApiRule` to `API_RULES` in `analysis/heuristics.py`.
List API names without the `A`/`W` suffix; both variants are matched automatically. If
the behaviour maps to an ATT&CK technique, add the rule name to `HEURISTIC_TECHNIQUES`
in `mitre/mapper.py`.

**Add a suspicious string.** Add the keyword to `SUSPICIOUS_KEYWORDS` in
`analysis/string_extractor.py` and, if it has a technique, to `STRING_TECHNIQUES` in
`mitre/mapper.py`. A test enforces that every mapped keyword is also extracted.

**Reduce IOC false positives.** Filters live in `ioc/extractor.py` (`BENIGN_DOMAINS`,
`KNOWN_TLDS`, `is_non_routable_ip`). Add a test that shows the false positive first.

**Change the report.** The report dict from `report/generator.py` is what plugins
receive and what `report.json` contains, so treat changes to its keys as breaking and
note them in `CHANGELOG.md`.

## Tests and samples

Tests must not depend on real malware. Use `tests/pe_builder.py`, or plain dicts and
strings for unit tests. To try the CLI by hand:

```bash
python tests/pe_builder.py sample.exe
malforge analyze sample.exe
```

Never commit binaries or live samples. `.gitignore` excludes `*.exe` and `*.dll` as a
safety net. When reporting a false positive or negative, share the SHA-256 of a public
sample instead of the file.

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Keep each pull request focused on one change and include tests.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages,
   for example `feat(heuristics): detect process hollowing` or
   `fix(ioc): ignore version strings`.
4. Add a line to the "Unreleased" section of `CHANGELOG.md` for user-facing changes.
5. Open an issue before adding a new runtime dependency.

## Releasing

Maintainers only:

1. Bump `__version__` in `src/malforge/__init__.py`.
2. Move the "Unreleased" changelog entries under the new version.
3. Commit, then tag and push: `git tag v1.2.0 && git push origin v1.2.0`.

The publish workflow checks that the tag matches the version, runs the tests, and uploads
to PyPI using trusted publishing.
