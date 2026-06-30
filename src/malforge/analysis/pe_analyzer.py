

import contextlib
import logging
from datetime import UTC, datetime
from typing import Any

import pefile

logger = logging.getLogger(__name__)


class PEAnalyzer:
    """Extracts features from PE files."""

    def __init__(self, file_data: bytes):
        self.file_data = file_data
        try:
            self.pe = pefile.PE(data=file_data, fast_load=False)
            self.is_valid = True
        except pefile.PEFormatError as e:
            logger.warning("Invalid PE format: %s", e)
            self.pe = None
            self.is_valid = False

    def analyze(self) -> dict[str, Any]:
        """Perform full PE analysis."""
        if not self.is_valid:
            return {"error": "Invalid PE file"}

        return {
            "headers": self._extract_headers(),
            "sections": self._extract_sections(),
            "imports": self._extract_imports(),
            "exports": self._extract_exports(),
            "entry_point": (
                hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                if hasattr(self.pe, "OPTIONAL_HEADER")
                else None
            ),
            "image_base": (
                hex(self.pe.OPTIONAL_HEADER.ImageBase)
                if hasattr(self.pe, "OPTIONAL_HEADER")
                else None
            ),
            "timestamp": self._extract_timestamp(),
        }

    def _extract_headers(self) -> dict[str, Any]:
        """Extract basic PE headers."""
        headers = {}
        if hasattr(self.pe, "FILE_HEADER"):
            headers["machine"] = hex(self.pe.FILE_HEADER.Machine)
            headers["characteristics"] = hex(self.pe.FILE_HEADER.Characteristics)

        if hasattr(self.pe, "OPTIONAL_HEADER"):
            headers["magic"] = hex(self.pe.OPTIONAL_HEADER.Magic)
            headers["subsystem"] = hex(self.pe.OPTIONAL_HEADER.Subsystem)
            headers["dll_characteristics"] = hex(self.pe.OPTIONAL_HEADER.DllCharacteristics)

        return headers

    def _extract_sections(self) -> list[dict[str, Any]]:
        """Extract sections and their properties including entropy."""
        sections = []
        for section in self.pe.sections:
            name = section.Name.hex()
            with contextlib.suppress(Exception):
                name = section.Name.decode("utf-8", errors="replace").strip("\x00")

            sections.append(
                {
                    "name": name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(section.get_entropy(), 4),
                    "characteristics": hex(section.Characteristics),
                }
            )
        return sections

    def _extract_imports(self) -> list[dict[str, Any]]:
        """Extract imported DLLs and their functions."""
        imports = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = ""
                with contextlib.suppress(Exception):
                    dll_name = entry.dll.decode("utf-8", errors="replace")

                if not dll_name:
                    continue

                functions = []
                for imp in entry.imports:
                    if imp.name:
                        with contextlib.suppress(Exception):
                            func_name = imp.name.decode("utf-8", errors="replace")
                            functions.append(func_name)
                    elif imp.ordinal:
                        functions.append(f"Ordinal{imp.ordinal}")

                imports.append({"dll": dll_name, "functions": functions})
        return imports

    def _extract_exports(self) -> list[str]:
        """Extract exported functions."""
        exports = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    with contextlib.suppress(Exception):
                        exports.append(exp.name.decode("utf-8", errors="replace"))
        return exports

    def _extract_timestamp(self) -> str:
        """Extract compilation timestamp."""
        if hasattr(self.pe, "FILE_HEADER"):
            timestamp_val = self.pe.FILE_HEADER.TimeDateStamp
            try:
                dt = datetime.fromtimestamp(timestamp_val, tz=UTC)
                return dt.isoformat()
            except Exception:
                return "Invalid"
        return "Unknown"
