import re
from dataclasses import dataclass, field

SUSPICIOUS_KEYWORDS = (
    "cmd.exe",
    "powershell",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
    "bitsadmin",
    "schtasks",
    "wmic",
    "winmgmts",
    "vssadmin",
    "shadowcopy",
    "bcdedit",
    "wevtutil",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "setwindowshook",
)


@dataclass
class ExtractedStrings:
    all: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)


class StringExtractor:
    """Extracts printable ASCII and UTF-16LE strings from binary data."""

    def __init__(self, file_data: bytes, min_length: int = 5) -> None:
        self.file_data = file_data
        self._ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        self._utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)

    def extract(self) -> ExtractedStrings:
        found = {s.decode("ascii") for s in self._ascii_re.findall(self.file_data)}
        found.update(s.decode("utf-16le") for s in self._utf16_re.findall(self.file_data))

        all_strings = sorted(found)
        suspicious = [s for s in all_strings if self._is_suspicious(s)]
        return ExtractedStrings(all=all_strings, suspicious=suspicious)

    @staticmethod
    def _is_suspicious(s: str) -> bool:
        lowered = s.lower()
        return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)
