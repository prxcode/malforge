from typing import Dict, Any, List

def run_heuristics(pe_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Analyze PE data for suspicious heuristic flags."""
    flags = []
    
    # 1. Check for high entropy sections (likely packed)
    for section in pe_data.get("sections", []):
        if section.get("entropy", 0) > 7.0:
            flags.append({
                "severity": "high",
                "name": "Packed Section",
                "description": f"Section {section['name']} has high entropy ({section['entropy']:.2f})."
            })
            
    # 2. Check for unusual section names
    standard_sections = [".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".bss", ".crt", ".tls", ".reloc"]
    for section in pe_data.get("sections", []):
        name = section.get("name", "").lower()
        if name and name not in standard_sections:
            flags.append({
                "severity": "medium",
                "name": "Unusual Section Name",
                "description": f"Found non-standard section: {name}"
            })
            
    # 3. Check for suspicious imports
    suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent", "RegSetValueExA"]
    found_apis = []
    
    for dll, funcs in pe_data.get("imports", {}).items():
        for func in funcs:
            if func in suspicious_apis:
                found_apis.append(func)
                
    if found_apis:
        flags.append({
            "severity": "high",
            "name": "Suspicious Imports",
            "description": f"Found potentially malicious APIs: {', '.join(found_apis)}"
        })
        
    return flags
