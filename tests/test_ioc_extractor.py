

from malforge.ioc.extractor import IndicatorType, IOCExtractor


class TestIOCExtractor:
    def setup_method(self) -> None:
        self.extractor = IOCExtractor()

    def test_extract_urls(self) -> None:
        strings = ["visit http://evil.com/payload.exe for details"]
        iocs = self.extractor.extract_from_strings(strings)

        url_iocs = [i for i in iocs if i.indicator_type == IndicatorType.URL]
        assert len(url_iocs) >= 1
        assert any("evil.com" in i.value for i in url_iocs)

    def test_extract_ips(self) -> None:
        strings = ["connecting to 203.0.113.50 on port 443"]
        iocs = self.extractor.extract_from_strings(strings)

        ip_iocs = [i for i in iocs if i.indicator_type == IndicatorType.IPV4]
        assert len(ip_iocs) >= 1
        assert ip_iocs[0].value == "203.0.113.50"

    def test_filter_internal_ips(self) -> None:
        strings = ["localhost is 127.0.0.1 and LAN is 192.168.1.1"]
        iocs = self.extractor.extract_from_strings(strings)

        ip_iocs = [i for i in iocs if i.indicator_type == IndicatorType.IPV4]
        # Both should be filtered out
        assert len(ip_iocs) == 0

    def test_filter_benign_domains(self) -> None:
        strings = ["downloaded from microsoft.com"]
        iocs = self.extractor.extract_from_strings(strings)

        domain_iocs = [i for i in iocs if i.indicator_type == IndicatorType.DOMAIN]
        # microsoft.com should be filtered
        benign = [i for i in domain_iocs if "microsoft.com" in i.value]
        assert len(benign) == 0

    def test_extract_registry_keys(self) -> None:
        strings = [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"]
        iocs = self.extractor.extract_from_strings(strings)

        reg_iocs = [i for i in iocs if i.indicator_type == IndicatorType.REGISTRY_KEY]
        assert len(reg_iocs) >= 1

    def test_deduplication(self) -> None:
        strings = [
            "http://evil.com/malware",
            "another ref to http://evil.com/malware here",
        ]
        iocs = self.extractor.extract_from_strings(strings)

        url_iocs = [i for i in iocs if i.indicator_type == IndicatorType.URL]
        values = [i.value for i in url_iocs]
        # Should be deduplicated
        assert len(values) == len(set(values))

    def test_confidence_scores(self) -> None:
        strings = ["check 203.0.113.50 and http://evil.com/test"]
        iocs = self.extractor.extract_from_strings(strings)

        for ioc in iocs:
            assert 0.0 <= ioc.confidence <= 1.0
