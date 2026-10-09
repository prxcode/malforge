import pytest

from malforge.ioc.extractor import IOC, IndicatorType, IOCExtractor


def extract(*strings: str) -> list[IOC]:
    return IOCExtractor().extract_from_strings(list(strings))


def values_of(iocs: list[IOC], ind_type: IndicatorType) -> list[str]:
    return [ioc.value for ioc in iocs if ioc.indicator_type == ind_type]


def test_extracts_url_and_its_domain() -> None:
    iocs = extract("fetching http://evil.com/payload.exe now")

    assert values_of(iocs, IndicatorType.URL) == ["http://evil.com/payload.exe"]
    assert values_of(iocs, IndicatorType.DOMAIN) == ["evil.com"]


@pytest.mark.parametrize(
    "name", ["payload.exe", "kernel32.dll", "config.json", "run.ps1", "notepad.cpp", "setup.py"]
)
def test_file_names_are_not_domains(name: str) -> None:
    assert values_of(extract(name), IndicatorType.DOMAIN) == []


@pytest.mark.parametrize(
    "name", ["System.Runtime.InteropServices", "Microsoft.Windows.Shell.notepad", "s.autosave"]
)
def test_code_identifiers_are_not_domains(name: str) -> None:
    assert values_of(extract(name), IndicatorType.DOMAIN) == []


@pytest.mark.parametrize("domain", ["c2.evil.ru", "update-check.xyz", "EVIL.COM"])
def test_real_domains_are_kept(domain: str) -> None:
    assert values_of(extract(domain), IndicatorType.DOMAIN) == [domain]


def test_version_strings_and_oids_are_not_ips() -> None:
    iocs = extract("version 6.0.0.0", "10.0.19041.0", "1.3.6.1.4.1.311.10.3.1")
    assert values_of(iocs, IndicatorType.IPV4) == []


def test_urls_need_a_real_host() -> None:
    assert values_of(extract("http://www", "http://i"), IndicatorType.URL) == []


def test_extracts_public_ip() -> None:
    assert values_of(extract("connect 203.0.113.50:443"), IndicatorType.IPV4) == ["203.0.113.50"]


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.20.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "169.254.1.1",
        "255.255.255.255",
    ],
)
def test_non_routable_ips_are_ignored(ip: str) -> None:
    assert values_of(extract(ip), IndicatorType.IPV4) == []


def test_benign_domains_are_ignored_but_lookalikes_are_not() -> None:
    iocs = extract("https://www.microsoft.com/pki", "notmicrosoft.com")

    assert values_of(iocs, IndicatorType.URL) == []
    assert values_of(iocs, IndicatorType.DOMAIN) == ["notmicrosoft.com"]


def test_registry_run_key_has_high_confidence() -> None:
    iocs = extract(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")

    (key,) = [i for i in iocs if i.indicator_type == IndicatorType.REGISTRY_KEY]
    assert key.confidence == 0.85


def test_file_paths() -> None:
    iocs = extract(r"C:\Users\Public\evil.exe", r"\\fileserver\share\drop.bin")

    assert values_of(iocs, IndicatorType.FILE_PATH) == [
        r"C:\Users\Public\evil.exe",
        r"\\fileserver\share\drop.bin",
    ]


def test_deduplicates_across_strings() -> None:
    iocs = extract("http://evil.com/a", "again: http://evil.com/a")

    assert values_of(iocs, IndicatorType.URL) == ["http://evil.com/a"]


def test_hashes_of_each_length() -> None:
    iocs = extract("a" * 32, "b" * 40, "c" * 64)

    assert values_of(iocs, IndicatorType.FILE_HASH_MD5) == ["a" * 32]
    assert values_of(iocs, IndicatorType.FILE_HASH_SHA1) == ["b" * 40]
    assert values_of(iocs, IndicatorType.FILE_HASH_SHA256) == ["c" * 64]
