import pefile
from typing import Dict, Any, List

def analyze_pe(file_path: str) -> Dict[str, Any]:
    """Parse PE structure using pefile."""
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {"error": str(e)}

    # Sections
    sections = []
    for section in pe.sections:
        sections.append({
            "name": section.Name.decode("utf-8", errors="ignore").strip('\x00'),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": hex(section.Misc_VirtualSize),
            "raw_size": section.SizeOfRawData,
            "entropy": section.get_entropy()
        })

    # Imports
    imports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore")
            imports[dll_name] = []
            for imp in entry.imports:
                if imp.name:
                    imports[dll_name].append(imp.name.decode("utf-8", errors="ignore"))

    # Exports
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="ignore"))

    # Header info
    headers = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "time_date_stamp": pe.FILE_HEADER.TimeDateStamp,
        "characteristics": hex(pe.FILE_HEADER.Characteristics)
    }

    return {
        "headers": headers,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "compiler": "Unknown" # Placeholder for advanced compiler detection
    }
