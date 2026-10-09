from malforge.analysis.pe_analyzer import PEAnalyzer


def test_parses_synthetic_pe(pe_bytes: bytes) -> None:
    analyzer = PEAnalyzer(pe_bytes)
    assert analyzer.is_valid

    pe = analyzer.analyze()
    assert pe is not None
    assert [s["name"] for s in pe["sections"]] == [".text", ".data"]
    assert pe["entry_point"] == "0x1000"
    assert pe["image_base"] == "0x400000"
    assert pe["timestamp"] == "2020-04-09T12:55:22+00:00"
    assert pe["imports"] == []
    assert pe["exports"] == []


def test_sections_have_entropy(pe_bytes: bytes) -> None:
    pe = PEAnalyzer(pe_bytes).analyze()
    assert pe is not None
    for section in pe["sections"]:
        assert 0.0 <= section["entropy"] <= 8.0


def test_rejects_non_pe_data() -> None:
    analyzer = PEAnalyzer(b"definitely not a PE file")
    assert not analyzer.is_valid
    assert analyzer.analyze() is None
