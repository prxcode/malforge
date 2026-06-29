# MAP — String Extractor
# Extracts ASCII and Unicode strings from binaries and categorizes them.

import re
from typing import Dict, List, Set


class StringExtractor:
    """Extracts strings and attempts to classify them as IPs, Domains, URLs, etc."""

    def __init__(self, file_data: bytes, min_length: int = 5):
        self.file_data = file_data
        self.min_length = min_length
        
        # Pre-compile regexes
        self.ascii_re = re.compile(b"[\x20-\x7E]{" + str(min_length).encode() + b",}")
        self.unicode_re = re.compile(b"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + b",}")
        
        self.url_re = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
        self.ip_re = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        self.registry_re = re.compile(r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\\a-zA-Z0-9_\-]+")
        self.file_path_re = re.compile(r"(?:[a-zA-Z]:\\|\b\\\\)[\\\w\-. ]+")

    def extract(self) -> Dict[str, List[str]]:
        """Extract strings and categorize them."""
        # 1. Raw extraction
        ascii_strings = [s.decode('ascii') for s in self.ascii_re.findall(self.file_data)]
        unicode_strings = [s.decode('utf-16le') for s in self.unicode_re.findall(self.file_data)]
        
        all_strings = set(ascii_strings + unicode_strings)
        
        # 2. Categorization
        categorized = {
            "all": list(all_strings),
            "urls": [],
            "ips": [],
            "registry": [],
            "paths": [],
            "suspicious": []
        }
        
        # Filter sets to avoid duplicates
        urls: Set[str] = set()
        ips: Set[str] = set()
        registry: Set[str] = set()
        paths: Set[str] = set()
        
        suspicious_keywords = [
            "cmd.exe", "powershell", "virtualalloc", "writeprocessmemory",
            "createremotethread", "setwindowshook", "loadlibrary", "getprocaddress",
            "vssadmin", "shadowcopy", "wevtutil", "schtasks", "wmi"
        ]

        for s in all_strings:
            # URLs
            for match in self.url_re.findall(s):
                urls.add(match)
                
            # IPs
            for match in self.ip_re.findall(s):
                ips.add(match)
                
            # Registry
            for match in self.registry_re.findall(s):
                registry.add(match)
                
            # Paths
            for match in self.file_path_re.findall(s):
                if len(match) > 5: # Filter out very short noise
                    paths.add(match)
                    
            # Suspicious
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in suspicious_keywords):
                categorized["suspicious"].append(s)

        categorized["urls"] = list(urls)
        categorized["ips"] = list(ips)
        categorized["registry"] = list(registry)
        categorized["paths"] = list(paths)
        
        return categorized
