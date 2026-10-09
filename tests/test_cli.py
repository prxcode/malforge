from pathlib import Path

from click.testing import CliRunner

from malforge import __version__
from malforge.cli import main


def test_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_analyze_help_lists_options() -> None:
    result = CliRunner().invoke(main, ["analyze", "--help"])
    assert result.exit_code == 0
    for option in ("--output", "--format", "--no-yara", "--no-sigma"):
        assert option in result.output


def test_missing_file_fails() -> None:
    result = CliRunner().invoke(main, ["analyze", "does_not_exist.exe"])
    assert result.exit_code != 0


def test_analyze_writes_all_outputs(pe_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["analyze", str(pe_file), "-o", str(out)])

    assert result.exit_code == 0, result.output
    for name in ("report.json", "report.html", "iocs.json", "mitre_mapping.json"):
        assert (out / name).exists()
    assert (out / "rules" / "yara_rule.yar").exists()
    assert (out / "rules" / "sigma_rule.yml").exists()


def test_format_and_skip_flags(pe_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = CliRunner().invoke(
        main,
        ["analyze", str(pe_file), "-o", str(out), "--format", "json", "--no-yara", "--no-sigma"],
    )

    assert result.exit_code == 0, result.output
    assert (out / "report.json").exists()
    assert not (out / "report.html").exists()
    assert not (out / "rules").exists()


def test_plugins_list() -> None:
    result = CliRunner().invoke(main, ["plugins", "list"])
    assert result.exit_code == 0
