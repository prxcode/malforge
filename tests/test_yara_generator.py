import yara

from malforge.detection.validator import DetectionValidator
from malforge.detection.yara_generator import YaraGenerator
from malforge.ioc.extractor import IOC, IndicatorType

SHA256 = "ab" * 32


def ioc(ind_type: IndicatorType, value: str) -> IOC:
    return IOC(ind_type, value, 0.8, "test", "")


def test_rule_from_apis() -> None:
    rule = YaraGenerator().generate(SHA256, ["VirtualAllocEx", "CreateRemoteThread"])

    assert rule is not None
    assert rule.startswith("rule Malforge_abababab {")
    assert '$api0 = "VirtualAllocEx" ascii wide nocase' in rule
    assert "and all of ($api*)" in rule
    yara.compile(source=rule)


def test_rule_from_network_iocs_only() -> None:
    iocs = [
        ioc(IndicatorType.URL, "http://evil.com/payload"),
        ioc(IndicatorType.IPV4, "203.0.113.5"),
        ioc(IndicatorType.REGISTRY_KEY, r"HKCU\Software\Run"),
    ]

    rule = YaraGenerator().generate(SHA256, [], iocs)

    assert rule is not None
    assert '$ioc_url0 = "http://evil.com/payload"' in rule
    assert '$ioc_ip1 = "203.0.113.5"' in rule
    assert "Software" not in rule
    yara.compile(source=rule)


def test_escapes_quotes_and_backslashes() -> None:
    rule = YaraGenerator().generate(SHA256, ['Weird"Api\\Name'])

    assert rule is not None
    yara.compile(source=rule)


def test_no_rule_without_indicators() -> None:
    assert YaraGenerator().generate(SHA256, [], []) is None


def test_validator_reports_match(pe_bytes: bytes) -> None:
    rule = YaraGenerator().generate(SHA256, [], [ioc(IndicatorType.IPV4, "203.0.113.50")])
    assert rule is not None

    result = DetectionValidator().validate_yara(rule, pe_bytes)

    assert result.is_valid
    assert result.true_positive
    assert result.error is None
    assert result.matches[0]["strings"][0]["identifier"] == "$ioc_ip0"


def test_validator_reports_syntax_errors() -> None:
    result = DetectionValidator().validate_yara("rule broken {", b"")

    assert not result.is_valid
    assert result.error is not None
