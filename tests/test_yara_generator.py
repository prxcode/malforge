

from malforge.detection.yara_generator import YaraGenerator
from malforge.ioc.extractor import IOC, IndicatorType


class TestYaraGenerator:
    def test_basic_generation(self) -> None:
        gen = YaraGenerator()
        analysis_data = {"suspicious_apis": ["VirtualAllocEx", "CreateRemoteThread"]}
        rule = gen.generate("a" * 64, analysis_data)

        assert "rule Malforge_" in rule
        assert "meta:" in rule
        assert "strings:" in rule
        assert "condition:" in rule
        assert "uint16(0) == 0x5a4d" in rule

    def test_with_iocs(self) -> None:
        gen = YaraGenerator()
        analysis_data = {"suspicious_apis": []}
        iocs = [
            IOC(
                indicator_type=IndicatorType.URL,
                value="http://evil.com/payload",
                confidence=0.8,
                source="static_strings",
                context="test",
            ),
            IOC(
                indicator_type=IndicatorType.IPV4,
                value="10.20.30.40",
                confidence=0.8,
                source="static_strings",
                context="test",
            ),
        ]
        rule = gen.generate("b" * 64, analysis_data, iocs)

        assert "$ioc_url0" in rule
        assert "$ioc_ip1" in rule
        assert "http://evil.com/payload" in rule

    def test_empty_analysis(self) -> None:
        gen = YaraGenerator()
        analysis_data = {"suspicious_apis": []}
        rule = gen.generate("c" * 64, analysis_data)

        # Should still produce a valid rule with MZ check
        assert "rule Malforge_" in rule
        assert "uint16(0) == 0x5a4d" in rule

    def test_meta_fields(self) -> None:
        gen = YaraGenerator()
        rule = gen.generate("d" * 64, {"suspicious_apis": []})

        assert "author" in rule
        assert "Malforge" in rule
        assert "hash" in rule
        assert "tlp" in rule
