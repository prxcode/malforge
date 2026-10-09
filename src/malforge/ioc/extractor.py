import enum
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class IndicatorType(enum.StrEnum):
    """Types of indicators of compromise."""

    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"


NETWORK_TYPES = frozenset({IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IPV4})


@dataclass
class IOC:
    """A single extracted indicator of compromise."""

    indicator_type: IndicatorType
    value: str
    confidence: float
    source: str
    context: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.indicator_type.value,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
        }


PATTERNS: dict[IndicatorType, re.Pattern[str]] = {
    IndicatorType.URL: re.compile(
        r"https?://[\w.-]+(?::\d+)?(?:/[\w.~!$&'()*+,;=:@%/-]*)?(?:\?[^\s\"'<>]*)?"
    ),
    IndicatorType.IPV4: re.compile(
        r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)"
    ),
    IndicatorType.DOMAIN: re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
    ),
    IndicatorType.EMAIL: re.compile(r"\b[\w.%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b"),
    IndicatorType.REGISTRY_KEY: re.compile(
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)"
        r"\\[\w\\ .-]+",
        re.IGNORECASE,
    ),
    IndicatorType.FILE_PATH: re.compile(r"(?:\b[a-zA-Z]:\\|\\\\[\w.-]+\\)[\w\\ .$-]+"),
    IndicatorType.FILE_HASH_MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
    IndicatorType.FILE_HASH_SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
    IndicatorType.FILE_HASH_SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
}

# Binaries are full of dotted names ("kernel32.dll", "notepad.cpp", "Microsoft.Windows.Shell")
# that match the domain pattern, so a candidate is only kept if its TLD is a two-letter
# country code or one of these generic TLDs.
GENERIC_TLDS = frozenset(
    {
        "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "app", "dev",
        "xyz", "top", "online", "site", "club", "shop", "store", "live", "life", "world",
        "space", "website", "tech", "cloud", "host", "fun", "icu", "vip", "work", "link",
        "click", "pro", "name", "mobi", "asia", "win", "bid", "loan", "date", "download",
        "stream", "racing", "review", "science", "party", "trade", "network", "services",
        "support", "email", "digital", "zone", "today", "news", "onion", "bit",
    }
)  # fmt: skip

COUNTRY_TLDS = frozenset(
    """
    ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo
    br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm
    do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs
    gt gu gw gy hk hm hn hr ht hu id ie il im in iq ir is it je jm jo jp ke kg kh ki km kn
    kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc me mg mh mk ml mm mn mp mq mr ms
    mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pn pr
    pt pw qa re ro ru rw sa sb sc sd se sg si sk sl sm sn sr ss st su sv sx sy sz tc td tf
    tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye
    yt za zm zw
    """.split()
)
# Left out of COUNTRY_TLDS because they are far more often file extensions in a binary:
# md, mo, pm, ps, py, rs, sh, so.

KNOWN_TLDS = GENERIC_TLDS | COUNTRY_TLDS

BENIGN_DOMAINS = frozenset(
    {
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "msftncsi.com",
        "schemas.microsoft.com",
        "w3.org",
        "xmlsoap.org",
        "schema.org",
        "digicert.com",
        "verisign.com",
        "globalsign.com",
        "globalsign.net",
        "sectigo.com",
        "usertrust.com",
        "comodoca.com",
        "symcb.com",
        "symcd.com",
        "thawte.com",
        "entrust.net",
    }
)

NON_ROUTABLE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in ("0.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)


def is_non_routable_ip(value: str) -> bool:
    addr = ipaddress.ip_address(value)
    if value.endswith(".0"):
        # Network addresses are almost always version strings such as "6.0.0.0".
        return True
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or any(addr in net for net in NON_ROUTABLE_NETWORKS)
    )


def is_benign_domain(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in BENIGN_DOMAINS)


def looks_like_domain(candidate: str) -> bool:
    # Mixed case ("desiredSize.cx", "System.Runtime.InteropServices") means a code
    # identifier or random bytes, not a hostname.
    if not (candidate.islower() or candidate.isupper()):
        return False
    return candidate.rsplit(".", 1)[-1].lower() in KNOWN_TLDS


class IOCExtractor:
    """Extracts typed IOCs from raw strings."""

    def extract_from_strings(self, strings: list[str]) -> list[IOC]:
        extracted: list[IOC] = []
        seen: set[tuple[IndicatorType, str]] = set()

        for s in strings:
            for ind_type, pattern in PATTERNS.items():
                for match in pattern.findall(s):
                    value = self._normalize(ind_type, match)
                    if not value or not self._keep(ind_type, value):
                        continue
                    key = (ind_type, value.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    extracted.append(
                        IOC(
                            indicator_type=ind_type,
                            value=value,
                            confidence=self._confidence(ind_type, value),
                            source="static_strings",
                            context=s[:100],
                        )
                    )

        return extracted

    @staticmethod
    def _normalize(ind_type: IndicatorType, value: str) -> str:
        if ind_type in (IndicatorType.FILE_PATH, IndicatorType.REGISTRY_KEY):
            return value.rstrip(" .\\")
        if ind_type == IndicatorType.URL:
            return value.rstrip(".,;:)'\"")
        return value

    @staticmethod
    def _keep(ind_type: IndicatorType, value: str) -> bool:
        if ind_type == IndicatorType.IPV4:
            return not is_non_routable_ip(value)
        if ind_type == IndicatorType.DOMAIN:
            return looks_like_domain(value) and not is_benign_domain(value)
        if ind_type == IndicatorType.URL:
            host = urlsplit(value).hostname or ""
            return "." in host and not is_benign_domain(host)
        if ind_type == IndicatorType.FILE_PATH:
            return len(value) > 5
        return True

    @staticmethod
    def _confidence(ind_type: IndicatorType, value: str) -> float:
        if ind_type == IndicatorType.REGISTRY_KEY:
            return 0.85 if "currentversion\\run" in value.lower() else 0.6
        if ind_type == IndicatorType.FILE_HASH_SHA256:
            return 0.9
        if ind_type in NETWORK_TYPES:
            return 0.8
        return 0.5
