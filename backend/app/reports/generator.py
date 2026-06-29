from typing import Dict, Any, List

class ReportGenerator:
    def generate_executive_summary(self, sample_name: str, ioc_count: int, rule_count: int) -> str:
        """Auto-generate an executive summary."""
        return (
            f"The sample '{sample_name}' was analyzed by MAP. "
            f"During the analysis, {ioc_count} potential indicators of compromise were extracted. "
            f"Additionally, {rule_count} detection rules (YARA/Sigma) were successfully generated "
            f"to help identify this threat in the environment."
        )

    def generate_attack_mapping(self, heuristics: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Map heuristics to MITRE ATT&CK."""
        mapping = []
        for flag in heuristics:
            name = flag.get("name", "")
            if "Packed" in name:
                mapping.append({"id": "T1027.002", "tactic": "Defense Evasion", "technique": "Software Packing"})
            if "Suspicious Imports" in name:
                mapping.append({"id": "T1055", "tactic": "Defense Evasion", "technique": "Process Injection"})
                
        if not mapping:
            mapping.append({"id": "Unknown", "tactic": "Unknown", "technique": "No clear ATT&CK mapping found"})
            
        return mapping

    def generate_recommendations(self) -> List[str]:
        return [
            "Isolate infected hosts from the network immediately.",
            "Deploy the generated YARA rules to your EDR solution.",
            "Block the extracted IOCs (IPs, Domains) on the perimeter firewall.",
            "Reset credentials for any users logged into the affected machines."
        ]

report_generator = ReportGenerator()
