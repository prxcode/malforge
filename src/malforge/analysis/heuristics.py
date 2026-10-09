from dataclasses import asdict, dataclass, field
from typing import Any

MAX_SCORE = 10.0
HIGH_ENTROPY_THRESHOLD = 7.2

STANDARD_SECTIONS = frozenset(
    {
        ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".bss", ".edata",
        ".idata", ".xdata", ".tls", ".crt", ".didat", ".gfids", ".00cfg", ".gehcont",
        ".retplne", ".voltbl", ".mrdata", ".orpc", ".fptable", "_rdata", "fothk",
    }
)  # fmt: skip


@dataclass(frozen=True)
class ApiRule:
    """Fires when the PE imports at least one API from every group in `requires`."""

    name: str
    description: str
    severity: str
    weight: float
    requires: tuple[frozenset[str], ...]


def _group(*apis: str) -> frozenset[str]:
    return frozenset(api.lower() for api in apis)


API_RULES = (
    ApiRule(
        name="Process Injection APIs",
        description="Allocates and writes memory in a remote process and starts a thread there.",
        severity="high",
        weight=4.0,
        requires=(
            _group("VirtualAllocEx", "NtAllocateVirtualMemory"),
            _group("WriteProcessMemory", "NtWriteVirtualMemory"),
            _group("CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC"),
        ),
    ),
    ApiRule(
        name="Keylogging APIs",
        description="Installs a window hook and polls keyboard state.",
        severity="high",
        weight=3.5,
        requires=(
            _group("SetWindowsHookEx"),
            _group("GetAsyncKeyState", "GetKeyState", "GetKeyboardState"),
        ),
    ),
    ApiRule(
        name="Cryptography APIs",
        description="Acquires a crypto provider and encrypts data, a common ransomware pattern.",
        severity="medium",
        weight=2.0,
        requires=(
            _group("CryptAcquireContext", "BCryptOpenAlgorithmProvider"),
            _group("CryptEncrypt", "BCryptEncrypt"),
        ),
    ),
    ApiRule(
        name="Anti-Debugging APIs",
        description="Checks whether a debugger is attached to the process.",
        severity="medium",
        weight=2.0,
        # IsDebuggerPresent is left out on purpose: the MSVC runtime imports it in
        # almost every binary, so on its own it says nothing about the sample.
        requires=(_group("CheckRemoteDebuggerPresent", "NtSetInformationThread"),),
    ),
    ApiRule(
        name="Download and Execute APIs",
        description="Downloads a file from a URL and can launch processes.",
        severity="medium",
        weight=2.0,
        requires=(
            _group("URLDownloadToFile", "InternetOpenUrl"),
            _group("WinExec", "ShellExecute", "ShellExecuteEx", "CreateProcess"),
        ),
    ),
)

_KNOWN_APIS: frozenset[str] = frozenset().union(*(g for rule in API_RULES for g in rule.requires))


@dataclass(frozen=True)
class HeuristicFlag:
    name: str
    description: str
    severity: str
    weight: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HeuristicResult:
    flags: list[HeuristicFlag] = field(default_factory=list)
    score: float = 0.0
    suspicious_apis: list[str] = field(default_factory=list)


def normalize_api(name: str) -> str:
    """Lower-case an API name and drop the ANSI/Unicode suffix, e.g. CreateProcessW -> createprocess."""
    lowered = name.lower()
    if len(lowered) > 1 and lowered[-1] in "aw" and lowered[-2].isalpha():
        stripped = lowered[:-1]
        if stripped in _KNOWN_APIS:
            return stripped
    return lowered


class HeuristicsEngine:
    """Scores a parsed PE file against static heuristics."""

    def __init__(self, pe_data: dict[str, Any]) -> None:
        self.pe_data = pe_data

    def analyze(self) -> HeuristicResult:
        result = HeuristicResult()
        result.flags.extend(self._entropy_flags())
        result.flags.extend(self._section_name_flags())

        imported = self._imported_functions()
        matched_apis: set[str] = set()
        for rule in API_RULES:
            hits = [
                {fn for fn in imported if normalize_api(fn) in group} for group in rule.requires
            ]
            if all(hits):
                result.flags.append(
                    HeuristicFlag(rule.name, rule.description, rule.severity, rule.weight)
                )
                matched_apis.update(*hits)

        result.suspicious_apis = sorted(matched_apis)
        result.score = round(min(sum(f.weight for f in result.flags), MAX_SCORE), 1)
        return result

    def _imported_functions(self) -> set[str]:
        return {fn for imp in self.pe_data.get("imports", []) for fn in imp.get("functions", [])}

    def _entropy_flags(self) -> list[HeuristicFlag]:
        packed = [
            f"{sec['name']} ({sec['entropy']})"
            for sec in self.pe_data.get("sections", [])
            if sec.get("entropy", 0) > HIGH_ENTROPY_THRESHOLD
        ]
        if not packed:
            return []
        return [
            HeuristicFlag(
                "High Entropy Section",
                f"Entropy above {HIGH_ENTROPY_THRESHOLD} suggests packed or encrypted data: "
                + ", ".join(packed),
                "high",
                3.0,
            )
        ]

    def _section_name_flags(self) -> list[HeuristicFlag]:
        names = [sec.get("name", "") for sec in self.pe_data.get("sections", [])]
        unusual = [n for n in names if n and n.lower() not in STANDARD_SECTIONS]
        upx = [n for n in unusual if n.lower().startswith("upx")]
        other = [n for n in unusual if n not in upx]

        flags = []
        if upx:
            flags.append(
                HeuristicFlag("UPX Packed", f"UPX sections: {', '.join(upx)}", "medium", 2.0)
            )
        if other:
            flags.append(
                HeuristicFlag(
                    "Unusual Section Name", f"Non-standard sections: {', '.join(other)}", "low", 1.0
                )
            )
        return flags
