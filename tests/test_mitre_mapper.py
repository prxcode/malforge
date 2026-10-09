from malforge.analysis.heuristics import HeuristicFlag
from malforge.ioc.extractor import IOC, IndicatorType
from malforge.mitre.mapper import MitreMapper

RUN_KEY = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"


def ioc(ind_type: IndicatorType, value: str) -> IOC:
    return IOC(ind_type, value, 0.8, "test", "")


def test_maps_heuristics_strings_and_iocs() -> None:
    mappings = MitreMapper().map(
        [HeuristicFlag("Anti-Debugging APIs", "", "medium", 2.0)],
        ["powershell -enc AAAA"],
        [ioc(IndicatorType.URL, "http://evil.com/x"), ioc(IndicatorType.REGISTRY_KEY, RUN_KEY)],
    )

    assert [m.technique_id for m in mappings] == ["T1622", "T1059.001", "T1071.001", "T1547.001"]


def test_deduplicates_by_technique() -> None:
    flags = [
        HeuristicFlag("UPX Packed", "", "medium", 2.0),
        HeuristicFlag("High Entropy Section", "", "high", 3.0),
    ]

    mappings = MitreMapper().map(flags, [], [])

    assert len(mappings) == 1
    assert mappings[0].evidence == "Heuristic: UPX Packed"


def test_ordinary_registry_keys_are_not_persistence() -> None:
    mappings = MitreMapper().map([], [], [ioc(IndicatorType.REGISTRY_KEY, r"HKCU\Software\Vendor")])
    assert mappings == []


def test_technique_url() -> None:
    (mapping,) = MitreMapper().map([], ["schtasks /create"], [])
    assert mapping.url == "https://attack.mitre.org/techniques/T1053/005/"
