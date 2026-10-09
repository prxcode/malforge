import logging
from datetime import UTC, datetime
from typing import Any

import pefile

logger = logging.getLogger(__name__)


class PEAnalyzer:
    """Extracts headers, sections, imports and exports from a PE file."""

    def __init__(self, file_data: bytes) -> None:
        self.pe: pefile.PE | None
        try:
            self.pe = pefile.PE(data=file_data)
        except pefile.PEFormatError as e:
            logger.debug("Not a PE file: %s", e)
            self.pe = None

    @property
    def is_valid(self) -> bool:
        return self.pe is not None

    def analyze(self) -> dict[str, Any] | None:
        """Return the parsed PE structure, or None if the data is not a PE file."""
        if self.pe is None:
            return None

        optional = getattr(self.pe, "OPTIONAL_HEADER", None)
        return {
            "headers": _headers(self.pe),
            "sections": _sections(self.pe),
            "imports": _imports(self.pe),
            "exports": _exports(self.pe),
            "entry_point": hex(optional.AddressOfEntryPoint) if optional else None,
            "image_base": hex(optional.ImageBase) if optional else None,
            "timestamp": _timestamp(self.pe),
        }


def _decode(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("utf-8", errors="replace")


def _headers(pe: pefile.PE) -> dict[str, str]:
    headers: dict[str, str] = {}
    if hasattr(pe, "FILE_HEADER"):
        headers["machine"] = hex(pe.FILE_HEADER.Machine)
        headers["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
    if hasattr(pe, "OPTIONAL_HEADER"):
        headers["magic"] = hex(pe.OPTIONAL_HEADER.Magic)
        headers["subsystem"] = hex(pe.OPTIONAL_HEADER.Subsystem)
        headers["dll_characteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
    return headers


def _sections(pe: pefile.PE) -> list[dict[str, Any]]:
    return [
        {
            "name": _decode(section.Name),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": round(section.get_entropy(), 4),
            "characteristics": hex(section.Characteristics),
        }
        for section in pe.sections
    ]


def _imports(pe: pefile.PE) -> list[dict[str, Any]]:
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll_name = _decode(entry.dll)
        if not dll_name:
            continue
        functions = [
            _decode(imp.name) if imp.name else f"Ordinal{imp.ordinal}"
            for imp in entry.imports
            if imp.name or imp.ordinal
        ]
        imports.append({"dll": dll_name, "functions": functions})
    return imports


def _exports(pe: pefile.PE) -> list[str]:
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is None:
        return []
    return [_decode(exp.name) for exp in export_dir.symbols if exp.name]


def _timestamp(pe: pefile.PE) -> str | None:
    if not hasattr(pe, "FILE_HEADER"):
        return None
    try:
        return datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None
