from typing import Any

from malforge.analysis.heuristics import HeuristicsEngine, normalize_api


def pe(*functions: str, sections: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "sections": sections or [{"name": ".text", "entropy": 6.0}],
        "imports": [{"dll": "kernel32.dll", "functions": list(functions)}],
    }


def flag_names(pe_data: dict[str, Any]) -> list[str]:
    return [f.name for f in HeuristicsEngine(pe_data).analyze().flags]


def test_clean_pe_has_no_flags() -> None:
    result = HeuristicsEngine(pe("GetModuleHandleW", "VirtualAlloc")).analyze()

    assert result.flags == []
    assert result.score == 0.0
    assert result.suspicious_apis == []


def test_process_injection_requires_the_full_chain() -> None:
    assert flag_names(pe("VirtualAllocEx", "WriteProcessMemory")) == []
    assert flag_names(pe("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")) == [
        "Process Injection APIs"
    ]


def test_ansi_and_unicode_variants_match() -> None:
    result = HeuristicsEngine(pe("SetWindowsHookExW", "GetAsyncKeyState")).analyze()

    assert [f.name for f in result.flags] == ["Keylogging APIs"]
    assert result.suspicious_apis == ["GetAsyncKeyState", "SetWindowsHookExW"]


def test_normalize_api_only_strips_known_suffixes() -> None:
    assert normalize_api("CreateProcessW") == "createprocess"
    assert normalize_api("CryptAcquireContextA") == "cryptacquirecontext"
    assert normalize_api("GetSystemMetricsA") == "getsystemmetricsa"


def test_section_heuristics() -> None:
    sections = [
        {"name": "UPX0", "entropy": 0.0},
        {"name": "UPX1", "entropy": 7.9},
        {"name": ".evil", "entropy": 4.0},
    ]

    assert flag_names(pe(sections=sections)) == [
        "High Entropy Section",
        "UPX Packed",
        "Unusual Section Name",
    ]


def test_section_flags_do_not_stack_per_section() -> None:
    sections = [{"name": f".x{i}", "entropy": 7.9} for i in range(5)]

    result = HeuristicsEngine(pe(sections=sections)).analyze()

    assert [f.name for f in result.flags] == ["High Entropy Section", "Unusual Section Name"]
    assert result.score == 4.0


def test_score_is_capped() -> None:
    apis = (
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "SetWindowsHookExA",
        "GetAsyncKeyState",
        "CheckRemoteDebuggerPresent",
    )
    sections = [{"name": "UPX0", "entropy": 7.9}]

    assert HeuristicsEngine(pe(*apis, sections=sections)).analyze().score == 10.0
