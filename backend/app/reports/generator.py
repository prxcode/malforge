# MAP — Threat Report Generator
# Aggregates data across all domains to generate a comprehensive threat intelligence report.

from typing import Any


class ThreatReportGenerator:
    """Generates structured threat intelligence reports."""

    def generate(
        self,
        sample_meta: dict[str, Any],
        static_analysis: dict[str, Any] | None,
        memory_analysis: dict[str, Any] | None,
        iocs: list[dict[str, Any]],
        rules: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Aggregate analysis data into a structured threat report."""

        # 1. File Metadata
        file_metadata = {
            "filename": sample_meta.get("filename"),
            "sha256": sample_meta.get("sha256"),
            "md5": sample_meta.get("md5"),
            "size": sample_meta.get("file_size"),
            "type": sample_meta.get("file_type")
        }

        # 2. Malware Characteristics & ATT&CK Mapping
        characteristics = {"capabilities": [], "heuristics": []}
        attack_mapping = []

        if static_analysis:
            characteristics["entropy"] = static_analysis.get("entropy_score")
            characteristics["compiler"] = static_analysis.get("compiler")

            for flag in static_analysis.get("heuristic_flags", []):
                characteristics["heuristics"].append(flag["name"])

                # Simple ATT&CK mapping based on heuristics
                if "Injection" in flag["name"]:
                    attack_mapping.append({"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"})
                elif "Keylog" in flag["name"]:
                    attack_mapping.append({"id": "T1056.001", "name": "Keylogging", "tactic": "Collection"})
                elif "Packed" in flag["name"] or "Entropy" in flag["name"]:
                    attack_mapping.append({"id": "T1027.002", "name": "Software Packing", "tactic": "Defense Evasion"})

        # 3. IOC Summary
        ioc_counts = {}
        for ioc in iocs:
            itype = ioc["indicator_type"]
            ioc_counts[itype] = ioc_counts.get(itype, 0) + 1

        # 4. Executive Summary
        severity = "High" if (static_analysis and static_analysis.get("heuristic_score", 0) > 7.0) else "Medium"
        summary = f"Analysis of {file_metadata['filename']} (SHA256: {file_metadata['sha256'][:8]}...) indicates a {severity.lower()} threat level."
        if attack_mapping:
            tactics = list(set([m["tactic"] for m in attack_mapping]))
            summary += f" The sample exhibits behaviors associated with {', '.join(tactics)}."

        # 5. Build full report structure
        report = {
            "executive_summary": summary,
            "confidence_level": severity.lower(),
            "file_metadata": file_metadata,
            "malware_characteristics": characteristics,
            "attack_mapping": attack_mapping,
            "observed_indicators": [
                {"type": ioc["indicator_type"], "value": ioc["value"], "confidence": ioc["confidence"]}
                for ioc in iocs[:50] # Cap at top 50 for report summary
            ],
            "ioc_summary": ioc_counts,
            "detection_opportunities": [
                {"description": "Monitor for process injection APIs", "log_source": "API Monitoring"},
                {"description": "Monitor network connections to extracted IPs/Domains", "log_source": "Firewall/DNS"}
            ],
            "recommendations": [
                {"action": "Block IOCs", "description": "Block all extracted IPs and Domains at the perimeter."}
            ],
            "rule_references": [
                {"rule_name": rule["rule_name"], "type": rule["rule_type"]}
                for rule in rules
            ]
        }

        return report
