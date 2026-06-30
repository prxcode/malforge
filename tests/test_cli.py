

from pathlib import Path

from click.testing import CliRunner

from malforge.cli import main


class TestCLI:
    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "malforge" in result.output.lower()

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Detection Engineering Toolkit" in result.output

    def test_analyze_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output
        assert "--format" in result.output

    def test_analyze_missing_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["analyze", "nonexistent_file.exe"])
        assert result.exit_code != 0

    def test_analyze_synthetic_pe(self, synthetic_pe_file: Path, tmp_path: Path) -> None:
        runner = CliRunner()
        output_dir = tmp_path / "cli_output"

        result = runner.invoke(
            main,
            ["analyze", str(synthetic_pe_file), "-o", str(output_dir)],
        )
        assert result.exit_code == 0

        # Check outputs were created
        assert (output_dir / "report.json").exists()
        assert (output_dir / "report.html").exists()
        assert (output_dir / "iocs.json").exists()
        assert (output_dir / "mitre_mapping.json").exists()

    def test_analyze_json_only(self, synthetic_pe_file: Path, tmp_path: Path) -> None:
        runner = CliRunner()
        output_dir = tmp_path / "json_only"

        result = runner.invoke(
            main,
            ["analyze", str(synthetic_pe_file), "-o", str(output_dir), "--format", "json"],
        )
        assert result.exit_code == 0
        assert (output_dir / "report.json").exists()
        assert not (output_dir / "report.html").exists()

    def test_plugins_list(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["plugins", "list"])
        assert result.exit_code == 0
