from malforge.analysis.string_extractor import SUSPICIOUS_KEYWORDS, StringExtractor
from malforge.mitre.mapper import STRING_TECHNIQUES


def test_extracts_ascii_and_utf16() -> None:
    data = b"\x00\x01hello world\x00\xff" + "wide string".encode("utf-16le") + b"\x00\x00"

    strings = StringExtractor(data).extract()

    assert "hello world" in strings.all
    assert "wide string" in strings.all


def test_respects_min_length() -> None:
    strings = StringExtractor(b"abc\x00abcdef\x00", min_length=5).extract()
    assert strings.all == ["abcdef"]


def test_flags_suspicious_strings() -> None:
    data = b"cmd.exe /c vssadmin delete shadows\x00just a normal string\x00"

    strings = StringExtractor(data).extract()

    assert strings.suspicious == ["cmd.exe /c vssadmin delete shadows"]


def test_every_mapped_keyword_is_extracted() -> None:
    assert set(STRING_TECHNIQUES) <= set(SUSPICIOUS_KEYWORDS)
