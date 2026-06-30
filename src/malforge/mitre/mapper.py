from dataclasses import dataclass
from typing import Any

from malforge.ioc.extractor import IOC, IndicatorType


@dataclass
class AttackMapping:
    """A single MITRE ATT&CK technique mapping."""

    technique_id: str
    technique_name: str
    tactic: str
    evidence: str  # what triggered this mapping


# Mapping rules: heuristic flag name -> ATT&CK technique
HEURISTIC_MAPPINGS: dict[str, dict[str, str]] = {
    "Process Injection APIs": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion",
    },
    "Keylogging APIs": {
        "id": "T1056.001",
        "name": "Keylogging",
        "tactic": "Collection",
    },
    "UPX Packed": {
        "id": "T1027.002",
        "name": "Software Packing",
        "tactic": "Defense Evasion",
    },
    "High Entropy Section": {
        "id": "T1027.002",
        "name": "Software Packing",
        "tactic": "Defense Evasion",
    },
    "Anti-Debugging APIs": {
        "id": "T1497.001",
        "name": "System Checks (Anti-Debug)",
        "tactic": "Defense Evasion",
    },
    "Cryptography APIs": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
    },
}

# Mapping rules: suspicious string keyword -> ATT&CK technique
STRING_MAPPINGS: dict[str, dict[str, str]] = {
    "cmd.exe": {
        "id": "T1059.003",
        "name": "Windows Command Shell",
        "tactic": "Execution",
    },
    "powershell": {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
    },
    "schtasks": {
        "id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": "Execution",
    },
    "wmi": {
        "id": "T1047",
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
    },
    "vssadmin": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
    },
    "shadowcopy": {
        "id": "T1490",
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
    },
    "loadlibrary": {
        "id": "T1129",
        "name": "Shared Modules",
        "tactic": "Execution",
    },
    "getprocaddress": {
        "id": "T1129",
        "name": "Shared Modules",
        "tactic": "Execution",
    },
}


class MitreMapper:
    """Maps analysis results to MITRE ATT&CK techniques."""

    def map(
        self,
        heuristic_flags: list[dict[str, Any]],
        suspicious_strings: list[str],
        iocs: list[IOC],
    ) -> list[AttackMapping]:
        """
        Produce ATT&CK mappings from heuristic flags, suspicious strings, and IOCs.
        Deduplicates by technique ID.
        """
        seen_ids: set[str] = set()
        mappings: list[AttackMapping] = []

        # 1. Map from heuristic flags
        for flag in heuristic_flags:
            flag_name = flag.get("name", "")
            if flag_name in HEURISTIC_MAPPINGS:
                entry = HEURISTIC_MAPPINGS[flag_name]
                if entry["id"] not in seen_ids:
                    seen_ids.add(entry["id"])
                    mappings.append(
                        AttackMapping(
                            technique_id=entry["id"],
                            technique_name=entry["name"],
                            tactic=entry["tactic"],
                            evidence=f"Heuristic: {flag_name}",
                        )
                    )

        # 2. Map from suspicious strings
        for s in suspicious_strings:
            s_lower = s.lower()
            for keyword, entry in STRING_MAPPINGS.items():
                if keyword in s_lower and entry["id"] not in seen_ids:
                    seen_ids.add(entry["id"])
                    mappings.append(
                        AttackMapping(
                            technique_id=entry["id"],
                            technique_name=entry["name"],
                            tactic=entry["tactic"],
                            evidence=f'String: "{s[:60]}"',
                        )
                    )

        # 3. Map from IOC types
        has_network_iocs = any(
            ioc.indicator_type
            in (IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IPV4)
            for ioc in iocs
        )
        if has_network_iocs and "T1071.001" not in seen_ids:
            seen_ids.add("T1071.001")
            mappings.append(
                AttackMapping(
                    technique_id="T1071.001",
                    technique_name="Web Protocols",
                    tactic="Command and Control",
                    evidence="Network IOCs (URLs/Domains/IPs) extracted",
                )
            )

        has_file_path_iocs = any(
            ioc.indicator_type == IndicatorType.FILE_PATH for ioc in iocs
        )
        if has_file_path_iocs and "T1105" not in seen_ids:
            seen_ids.add("T1105")
            mappings.append(
                AttackMapping(
                    technique_id="T1105",
                    technique_name="Ingress Tool Transfer",
                    tactic="Command and Control",
                    evidence="File path IOCs extracted",
                )
            )

        has_registry_iocs = any(
            ioc.indicator_type == IndicatorType.REGISTRY_KEY for ioc in iocs
        )
        if has_registry_iocs and "T1547.001" not in seen_ids:
            seen_ids.add("T1547.001")
            mappings.append(
                AttackMapping(
                    technique_id="T1547.001",
                    technique_name="Registry Run Keys / Startup Folder",
                    tactic="Persistence",
                    evidence="Registry key IOCs extracted",
                )
            )

        return mappings
