from dataclasses import asdict, dataclass
from typing import Any

from malforge.analysis.heuristics import HeuristicFlag
from malforge.ioc.extractor import IOC, IndicatorType


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


@dataclass
class AttackMapping:
    """A single MITRE ATT&CK technique mapping."""

    technique_id: str
    technique_name: str
    tactic: str
    evidence: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "url": self.url}


SOFTWARE_PACKING = Technique("T1027.002", "Software Packing", "Defense Evasion")
INHIBIT_RECOVERY = Technique("T1490", "Inhibit System Recovery", "Impact")
WMI = Technique("T1047", "Windows Management Instrumentation", "Execution")

HEURISTIC_TECHNIQUES: dict[str, Technique] = {
    "Process Injection APIs": Technique("T1055", "Process Injection", "Defense Evasion"),
    "Keylogging APIs": Technique("T1056.001", "Keylogging", "Collection"),
    "UPX Packed": SOFTWARE_PACKING,
    "High Entropy Section": SOFTWARE_PACKING,
    "Anti-Debugging APIs": Technique("T1622", "Debugger Evasion", "Defense Evasion"),
    "Cryptography APIs": Technique("T1486", "Data Encrypted for Impact", "Impact"),
    "Download and Execute APIs": Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
}

# Keys must be entries of malforge.analysis.string_extractor.SUSPICIOUS_KEYWORDS.
STRING_TECHNIQUES: dict[str, Technique] = {
    "cmd.exe": Technique("T1059.003", "Windows Command Shell", "Execution"),
    "powershell": Technique("T1059.001", "PowerShell", "Execution"),
    "rundll32": Technique("T1218.011", "Rundll32", "Defense Evasion"),
    "regsvr32": Technique("T1218.010", "Regsvr32", "Defense Evasion"),
    "mshta": Technique("T1218.005", "Mshta", "Defense Evasion"),
    "certutil": Technique("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "bitsadmin": Technique("T1197", "BITS Jobs", "Defense Evasion"),
    "schtasks": Technique("T1053.005", "Scheduled Task", "Execution"),
    "wmic": WMI,
    "winmgmts": WMI,
    "vssadmin": INHIBIT_RECOVERY,
    "shadowcopy": INHIBIT_RECOVERY,
    "bcdedit": INHIBIT_RECOVERY,
    "wevtutil": Technique("T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
}

WEB_PROTOCOLS = Technique("T1071.001", "Web Protocols", "Command and Control")
RUN_KEYS = Technique("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")


class MitreMapper:
    """Maps heuristic flags, suspicious strings and IOCs to ATT&CK techniques."""

    def map(
        self,
        heuristic_flags: list[HeuristicFlag],
        suspicious_strings: list[str],
        iocs: list[IOC],
    ) -> list[AttackMapping]:
        """Return one mapping per technique, keeping the first piece of evidence seen."""
        mappings: dict[str, AttackMapping] = {}

        def add(technique: Technique, evidence: str) -> None:
            if technique.id not in mappings:
                mappings[technique.id] = AttackMapping(
                    technique.id, technique.name, technique.tactic, evidence
                )

        for flag in heuristic_flags:
            if flag.name in HEURISTIC_TECHNIQUES:
                add(HEURISTIC_TECHNIQUES[flag.name], f"Heuristic: {flag.name}")

        for s in suspicious_strings:
            lowered = s.lower()
            for keyword, technique in STRING_TECHNIQUES.items():
                if keyword in lowered:
                    add(technique, f'String: "{s[:60]}"')

        for ioc in iocs:
            if ioc.indicator_type == IndicatorType.URL:
                add(WEB_PROTOCOLS, f"URL: {ioc.value[:60]}")
            elif ioc.indicator_type == IndicatorType.REGISTRY_KEY and (
                "currentversion\\run" in ioc.value.lower()
            ):
                add(RUN_KEYS, f"Registry key: {ioc.value[:60]}")

        return list(mappings.values())
