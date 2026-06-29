# MAP — Heuristics Engine
# Identifies suspicious traits in PE structure and strings.

from typing import Any, Dict, List, Tuple


class HeuristicsEngine:
    """Applies heuristic rules to PE and string analysis results."""

    def __init__(self, pe_data: Dict[str, Any], strings_data: Dict[str, Any]):
        self.pe_data = pe_data
        self.strings_data = strings_data
        self.flags = []
        self.score = 0.0

    def analyze(self) -> Tuple[List[Dict[str, Any]], float]:
        """Run all heuristics and return flags and total score (0.0 to 10.0)."""
        self._check_entropy()
        self._check_section_names()
        self._check_suspicious_imports()
        
        # Cap score at 10.0
        self.score = min(self.score, 10.0)
        
        return self.flags, round(self.score, 1)

    def _add_flag(self, name: str, description: str, severity: str, weight: float):
        self.flags.append({
            "name": name,
            "description": description,
            "severity": severity
        })
        self.score += weight

    def _check_entropy(self):
        """Check for high entropy sections (packer indication)."""
        sections = self.pe_data.get("sections", [])
        for sec in sections:
            if sec.get("entropy", 0) > 7.2:
                self._add_flag(
                    "High Entropy Section",
                    f"Section {sec.get('name')} has entropy {sec.get('entropy')} (>7.2). May be packed.",
                    "high",
                    3.0
                )

    def _check_section_names(self):
        """Check for unusual section names."""
        standard_sections = {".text", ".data", ".rsrc", ".rdata", ".reloc", ".pdata", ".bss", ".edata", ".idata", ".xdata", ".tls"}
        sections = self.pe_data.get("sections", [])
        for sec in sections:
            name = sec.get("name", "").lower()
            if name and name not in standard_sections:
                # UPX specific
                if name.startswith("upx"):
                    self._add_flag("UPX Packed", "UPX section names detected.", "medium", 2.0)
                else:
                    self._add_flag("Unusual Section Name", f"Section {name} is not standard.", "low", 1.0)

    def _check_suspicious_imports(self):
        """Check for API combinations associated with malicious behavior."""
        imports = self.pe_data.get("imports", [])
        
        all_funcs = set()
        for imp in imports:
            all_funcs.update([f.lower() for f in imp.get("functions", [])])
            
        # Process Injection
        if "virtualallocex" in all_funcs and "writeprocessmemory" in all_funcs and "createremotethread" in all_funcs:
            self._add_flag(
                "Process Injection APIs",
                "Contains VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread.",
                "high",
                4.0
            )
            
        # Keylogging
        if "setwindowshookex" in all_funcs or "setwindowshookexa" in all_funcs or "setwindowshookexw" in all_funcs:
            if "getasynckeystate" in all_funcs or "getkeystate" in all_funcs:
                self._add_flag("Keylogging APIs", "Contains window hook and keystate APIs.", "high", 3.5)
                
        # Cryptography / Ransomware
        if "cryptacquirecontexta" in all_funcs and "cryptencrypt" in all_funcs:
            self._add_flag("Cryptography APIs", "Contains crypto APIs often used in ransomware.", "medium", 2.0)
            
        # Anti-Debugging
        if "isdebuggerpresent" in all_funcs or "checkremotedebuggerpresent" in all_funcs:
            self._add_flag("Anti-Debugging APIs", "Contains APIs used to detect debuggers.", "medium", 2.0)
