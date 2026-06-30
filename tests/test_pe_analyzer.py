

from malforge.analysis.pe_analyzer import PEAnalyzer


class TestPEAnalyzer:
    def test_valid_pe(self, synthetic_pe_data: bytes) -> None:
        analyzer = PEAnalyzer(synthetic_pe_data)
        assert analyzer.is_valid is True

        result = analyzer.analyze()
        assert "error" not in result
        assert "headers" in result
        assert "sections" in result
        assert "imports" in result
        assert "exports" in result
        assert "entry_point" in result
        assert "timestamp" in result

    def test_sections_extracted(self, synthetic_pe_data: bytes) -> None:
        analyzer = PEAnalyzer(synthetic_pe_data)
        result = analyzer.analyze()
        sections = result["sections"]

        assert len(sections) >= 1
        for sec in sections:
            assert "name" in sec
            assert "entropy" in sec
            assert "raw_size" in sec

    def test_invalid_pe(self) -> None:
        analyzer = PEAnalyzer(b"this is not a PE file")
        assert analyzer.is_valid is False

        result = analyzer.analyze()
        assert result == {"error": "Invalid PE file"}

    def test_timestamp_format(self, synthetic_pe_data: bytes) -> None:
        analyzer = PEAnalyzer(synthetic_pe_data)
        result = analyzer.analyze()
        # Should be an ISO format timestamp or "Invalid" / "Unknown"
        ts = result["timestamp"]
        assert isinstance(ts, str)
        assert ts != ""
