import re
from typing import List, Dict

class IOCExtractor:
    def __init__(self):
        # Regex patterns for various IOCs
        self.patterns = {
            "ipv4": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "url": re.compile(r'(?i)https?://[^\s<>"]+|www\.[^\s<>"]+'),
            "domain": re.compile(r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'),
            "email": re.compile(r'(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "md5": re.compile(r'(?i)\b[a-f0-9]{32}\b'),
            "sha1": re.compile(r'(?i)\b[a-f0-9]{40}\b'),
            "sha256": re.compile(r'(?i)\b[a-f0-9]{64}\b'),
            "registry": re.compile(r'(?i)(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s]+'),
            "file_path": re.compile(r'(?i)(?:[A-Z]:\\[^\s]+|%[A-Za-z0-9_]+%\\[^\s]+)'),
        }

    def extract_from_strings(self, strings: List[str]) -> List[Dict[str, str]]:
        """Extract IOCs from a list of strings."""
        results = []
        seen = set()
        
        for s in strings:
            for ioc_type, pattern in self.patterns.items():
                matches = pattern.findall(s)
                for match in matches:
                    if match not in seen:
                        seen.add(match)
                        results.append({
                            "indicator_type": ioc_type,
                            "value": match,
                            "confidence": self._calculate_confidence(ioc_type, match)
                        })
                        
        return results
        
    def _calculate_confidence(self, ioc_type: str, value: str) -> str:
        """Simple confidence scoring based on IOC type."""
        # Simple heuristic for student project
        high_confidence = ["md5", "sha1", "sha256", "registry", "url"]
        if ioc_type in high_confidence:
            return "high"
        elif ioc_type == "ipv4":
            # Ignore local IPs
            if value.startswith("10.") or value.startswith("192.168.") or value.startswith("127."):
                return "low"
            return "medium"
        return "medium"

ioc_extractor = IOCExtractor()
