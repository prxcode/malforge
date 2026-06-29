import re
from typing import List, Dict

def extract_strings(content: bytes, min_length: int = 5) -> Dict[str, List[str]]:
    """Extract ASCII and Unicode strings, and categorize them."""
    
    # ASCII strings
    ascii_pattern = re.compile(b'[\x20-\x7e]{' + str(min_length).encode() + b',}')
    ascii_strings = [s.decode('ascii') for s in ascii_pattern.findall(content)]
    
    # Unicode strings (utf-16-le)
    unicode_pattern = re.compile(b'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}')
    unicode_raw = unicode_pattern.findall(content)
    unicode_strings = [s.decode('utf-16-le') for s in unicode_raw]
    
    all_strings = ascii_strings + unicode_strings
    
    # Categorization using regex
    urls = []
    ips = []
    registry = []
    
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    reg_pattern = re.compile(r'(?i)(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s]+')
    
    for s in all_strings:
        if url_pattern.search(s):
            urls.append(s)
        if ip_pattern.search(s):
            ips.append(s)
        if reg_pattern.search(s):
            registry.append(s)
            
    return {
        "all_count": len(all_strings),
        "urls": list(set(urls)),
        "ips": list(set(ips)),
        "registry": list(set(registry))
    }
