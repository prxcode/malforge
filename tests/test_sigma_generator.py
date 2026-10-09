from malforge.detection.sigma_generator import SigmaGenerator
from malforge.ioc.extractor import IOC, IndicatorType

SHA256 = "cd" * 32


def ioc(ind_type: IndicatorType, value: str) -> IOC:
    return IOC(ind_type, value, 0.8, "test", "")


def test_one_rule_per_log_source() -> None:
    iocs = [
        ioc(IndicatorType.FILE_PATH, r"C:\Windows\System32\cmd.exe"),
        ioc(IndicatorType.REGISTRY_KEY, r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"),
        ioc(IndicatorType.DOMAIN, "evil.com"),
        ioc(IndicatorType.IPV4, "203.0.113.5"),
    ]

    rules = SigmaGenerator().generate(SHA256, iocs)

    assert rules is not None
    documents = rules.split("---\n")
    assert len(documents) == 4
    categories = [line.split(": ")[1] for line in rules.splitlines() if "category:" in line]
    assert categories == ["process_creation", "registry_set", "dns_query", "network_connection"]
    assert "            - '\\cmd.exe'" in rules
    assert "            - 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'" in rules
    assert rules.count("condition: selection") == 4


def test_rule_ids_are_stable_and_unique() -> None:
    iocs = [ioc(IndicatorType.DOMAIN, "evil.com"), ioc(IndicatorType.IPV4, "203.0.113.5")]

    first = SigmaGenerator().generate(SHA256, iocs)
    second = SigmaGenerator().generate(SHA256, iocs)

    assert first == second
    assert first is not None
    ids = [line for line in first.splitlines() if line.startswith("id: ")]
    assert len(set(ids)) == 2


def test_quotes_are_escaped() -> None:
    rules = SigmaGenerator().generate(
        SHA256, [ioc(IndicatorType.REGISTRY_KEY, r"HKCU\Software\it's")]
    )

    assert rules is not None
    assert "'Software\\it''s'" in rules


def test_non_executable_paths_are_skipped() -> None:
    assert (
        SigmaGenerator().generate(SHA256, [ioc(IndicatorType.FILE_PATH, r"C:\temp\notes.txt")])
        is None
    )
