

import enum
import re
from dataclasses import dataclass


class IndicatorType(str, enum.Enum):
    """Types of indicators of compromise."""

    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    MUTEX = "mutex"
    SERVICE_NAME = "service_name"
    SCHEDULED_TASK = "scheduled_task"
    USER_AGENT = "user_agent"
    PIPE_NAME = "pipe_name"


@dataclass
class IOC:
    """A single extracted indicator of compromise."""

    indicator_type: IndicatorType
    value: str
    confidence: float
    source: str
    context: str


class IOCExtractor:
    """Extracts typed IOCs from raw text or analysis artifacts."""

    def __init__(self) -> None:
        # Precise regexes to avoid false positives
        self.regexes = {
            IndicatorType.IPV4: re.compile(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            ),
            IndicatorType.URL: re.compile(
                r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[-\w._~!$&'()*+,;=:@%]*)*(?:\?[-\w.!~*'();/?:@&=+$,%]*)?(?:#[-\w.!~*'();/?:@&=+$,%]*)?"
            ),
            IndicatorType.DOMAIN: re.compile(
                r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b"
            ),
            IndicatorType.EMAIL: re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ),
            IndicatorType.REGISTRY_KEY: re.compile(
                r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\\\w\-]+"
            ),
            IndicatorType.FILE_PATH: re.compile(r"(?:[a-zA-Z]:\\|\b\\\\)[\\\w\-. ]+"),
            IndicatorType.FILE_HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
            IndicatorType.FILE_HASH_SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
            IndicatorType.FILE_HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
        }

        # Common false positives
        self.ignore_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
        self.ignore_domains = {"microsoft.com", "windows.com", "schema.org", "w3.org"}

    def extract_from_strings(self, strings: list[str]) -> list[IOC]:
        """Extract IOCs from a list of raw strings."""
        extracted = []
        seen: set[str] = set()

        for s in strings:
            for ind_type, regex in self.regexes.items():
                for match in regex.findall(s):
                    # Filter false positives
                    if ind_type == IndicatorType.IPV4 and self._is_internal_ip(match):
                        continue
                    if ind_type == IndicatorType.DOMAIN and self._is_benign_domain(match):
                        continue

                    # Deduplicate
                    unique_key = f"{ind_type.value}:{match}"
                    if unique_key in seen:
                        continue
                    seen.add(unique_key)

                    # Compute confidence
                    confidence = self._compute_confidence(ind_type, match)

                    extracted.append(
                        IOC(
                            indicator_type=ind_type,
                            value=match,
                            confidence=confidence,
                            source="static_strings",
                            context=s[:100],  # store partial context
                        )
                    )

        return extracted

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is local/private/multicast."""
        if ip in self.ignore_ips:
            return True
        if ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) == 4:
                try:
                    if 16 <= int(parts[1]) <= 31:
                        return True
                except ValueError:
                    pass
        return False

    def _is_benign_domain(self, domain: str) -> bool:
        """Check if domain is commonly found in benign software."""
        domain = domain.lower()
        return any(domain.endswith(bd) for bd in self.ignore_domains)

    def _compute_confidence(self, ind_type: IndicatorType, value: str) -> float:
        """Assign confidence scores to extracted indicators."""
        if ind_type in (IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IPV4):
            return 0.8
        if ind_type == IndicatorType.FILE_HASH_SHA256:
            return 0.9
        if ind_type == IndicatorType.REGISTRY_KEY:
            # Common run keys get higher confidence
            if "currentversion\\run" in value.lower():
                return 0.85
            return 0.6
        return 0.5
