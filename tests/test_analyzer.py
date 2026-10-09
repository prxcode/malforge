import json
from pathlib import Path

from malforge.analyzer import Analyzer
from malforge.ioc.extractor import IndicatorType
from malforge.plugins import MalforgePlugin


def test_pipeline_on_pe(analyzer: Analyzer, pe_file: Path) -> None:
    result = analyzer.analyze(pe_file)

    assert result.file_metadata["filename"] == "test_sample.exe"
    assert len(result.file_metadata["sha256"]) == 64
    assert result.pe_data is not None
    assert result.strings.all

    values = {ioc.value for ioc in result.iocs}
    assert "http://malicious-test-domain.com/payload.exe" in values
    assert "203.0.113.50" in values
    assert "payload.exe" not in values

    technique_ids = {m.technique_id for m in result.attack_mappings}
    assert {"T1059.003", "T1071.001", "T1547.001"} <= technique_ids

    assert result.yara_rule is not None
    assert result.yara_validation is not None
    assert result.yara_validation.is_valid
    assert result.yara_validation.true_positive
    assert result.sigma_rule is not None
    assert result.report["classification"] == "SUSPICIOUS"


def test_hash_iocs_do_not_raise_risk(analyzer: Analyzer, tmp_path: Path) -> None:
    sample = tmp_path / "blank.bin"
    sample.write_bytes(b"\x00" * 64)

    result = analyzer.analyze(sample)

    assert {ioc.indicator_type for ioc in result.iocs} == {
        IndicatorType.FILE_HASH_MD5,
        IndicatorType.FILE_HASH_SHA1,
        IndicatorType.FILE_HASH_SHA256,
    }
    assert result.report["risk_score"] == 0
    assert result.report["classification"] == "BENIGN"


def test_non_pe_file(analyzer: Analyzer, tmp_path: Path) -> None:
    sample = tmp_path / "readme.txt"
    sample.write_text("Not a PE file. Fetch http://evil.example.net/stage2 next.")

    result = analyzer.analyze(sample)

    assert result.pe_data is None
    assert result.heuristic_flags == []
    assert any(ioc.indicator_type == IndicatorType.URL for ioc in result.iocs)


def test_disabled_rules_are_absent_from_report(pe_file: Path) -> None:
    result = Analyzer(yara=False, sigma=False, plugins=[]).analyze(pe_file)

    assert result.yara_rule is None
    assert result.sigma_rule is None
    assert result.report["detection_rules"]["yara"] is None
    assert result.report["detection_rules"]["sigma"] is None


def test_write_outputs(analyzer: Analyzer, pe_file: Path, tmp_path: Path) -> None:
    result = analyzer.analyze(pe_file)
    outputs = analyzer.write_outputs(result, tmp_path / "out")

    assert set(outputs) == {"report_html", "report_json", "iocs", "mitre", "yara", "sigma"}
    assert all(path.exists() for path in outputs.values())
    assert json.loads(outputs["report_json"].read_text())["classification"] == "SUSPICIOUS"
    assert outputs["yara"].read_text().startswith("rule Malforge_")

    html = outputs["report_html"].read_text(encoding="utf-8")
    assert "Malforge Report" in html
    assert "test_sample.exe" in html


def test_write_outputs_json_only(analyzer: Analyzer, pe_file: Path, tmp_path: Path) -> None:
    result = analyzer.analyze(pe_file)
    outputs = analyzer.write_outputs(result, tmp_path / "out", formats=["json"])

    assert "report_html" not in outputs
    assert not (tmp_path / "out" / "report.html").exists()


class TaggingPlugin(MalforgePlugin):
    name = "tagger"

    def on_analysis_complete(self, report: dict[str, object]) -> dict[str, object]:
        report["tag"] = "seen"
        return report


class BrokenPlugin(MalforgePlugin):
    name = "broken"

    def on_analysis_complete(self, report: dict[str, object]) -> dict[str, object]:
        raise RuntimeError("boom")


def test_plugins_run_and_failures_are_isolated(pe_file: Path) -> None:
    result = Analyzer(plugins=[BrokenPlugin(), TaggingPlugin()]).analyze(pe_file)

    assert result.report["tag"] == "seen"
