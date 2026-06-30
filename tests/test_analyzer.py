

from pathlib import Path

from malforge.analyzer import Analyzer


class TestAnalyzer:
    def test_full_pipeline(self, synthetic_pe_file: Path) -> None:
        analyzer = Analyzer()
        result = analyzer.analyze(synthetic_pe_file)

        # File metadata populated
        assert result.file_metadata["filename"] == "test_sample.exe"
        assert result.file_metadata["sha256"] != ""
        assert result.file_metadata["file_size"] > 0

        # Strings extracted
        assert len(result.strings_data.get("all", [])) > 0

        # PE data present (our synthetic PE is valid)
        assert result.pe_data is not None
        assert "sections" in result.pe_data

        # IOCs extracted (our synthetic PE has URLs, IPs, registry keys)
        assert len(result.iocs) > 0

        # YARA rule generated
        assert result.yara_rule is not None
        assert "rule Malforge_" in result.yara_rule

        # Report generated
        assert result.report["classification"] in ("MALICIOUS", "SUSPICIOUS", "BENIGN")
        assert result.report["risk_score"] >= 0

    def test_write_outputs(self, synthetic_pe_file: Path, tmp_path: Path) -> None:
        analyzer = Analyzer()
        result = analyzer.analyze(synthetic_pe_file)

        output_dir = tmp_path / "output"
        outputs = analyzer.write_outputs(result, output_dir)

        # All expected files created
        assert outputs["report_json"].exists()
        assert outputs["report_html"].exists()
        assert outputs["iocs"].exists()
        assert outputs["mitre"].exists()

        # YARA rule file
        if result.yara_rule:
            assert outputs["yara"].exists()
            assert outputs["yara"].read_text().startswith("rule ")

        # HTML report is non-empty and contains key elements
        html = outputs["report_html"].read_text()
        assert "Malforge Report" in html
        assert result.file_metadata["filename"] in html

    def test_non_pe_file(self, tmp_path: Path) -> None:
        # Create a non-PE file
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("This is not a PE file. Visit http://example.com for more.")

        analyzer = Analyzer()
        result = analyzer.analyze(txt_file)

        # Should still complete without error
        assert result.pe_data is None
        assert result.file_metadata["filename"] == "readme.txt"
        # Strings and IOCs should still be extracted
        assert len(result.strings_data.get("all", [])) > 0
